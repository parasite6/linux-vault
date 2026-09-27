//! Pinentry client.
//!
//! The installed helper starts `pinentry-qt` in the caller's user manager.
//! Tests pass a fake script instead.

use std::ffi::OsString;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Notify;
use zeroize::{Zeroize, Zeroizing};

const LINE_CAP: usize = 4096;

/// Stops an in-flight [`Pinentry::ask`].
#[derive(Clone, Debug)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
    /// Shutdown holds the parent. Cancelling it cancels every prompt.
    parent: Option<Arc<CancelToken>>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            parent: None,
        }
    }

    /// A prompt's own token. Cancelling `self` cancels this too.
    /// Cancelling the child does not cancel `self` or any sibling.
    pub fn child(&self) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            parent: Some(Arc::new(self.clone())),
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // Every prompt is waiting on this token, or on a parent that is.
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_cancelled())
    }

    async fn cancelled(&self) {
        if let Some(parent) = &self.parent {
            let parent = Arc::clone(parent);
            tokio::select! {
                () = self.wait_flag() => {}
                () = parent.wait_flag() => {}
            }
        } else {
            self.wait_flag().await;
        }
    }

    async fn wait_flag(&self) {
        loop {
            // Subscribe before the flag check so a cancel in between is not lost.
            let notified = self.notify.notified();
            if self.flag.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Passphrase bytes. Debug output is a placeholder. Dropped bytes are wiped.
/// There is no `Clone` or `Display`.
///
/// The buffer is `mlock`ed. If that fails, the failure is logged and the
/// passphrase is still kept: the helper has to be able to unlock a vault.
pub struct Passphrase {
    bytes: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl Passphrase {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let bytes = Zeroizing::new(bytes.to_vec());
        let locked = lock_memory(&bytes);
        Self { bytes, locked }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        let len = self.bytes.len();
        let ptr = self.bytes.as_ptr();
        self.bytes.zeroize();
        if self.locked && len > 0 {
            unsafe {
                nix::libc::munlock(ptr.cast::<nix::libc::c_void>(), len);
            }
        }
    }
}

fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let rc = unsafe { nix::libc::mlock(bytes.as_ptr().cast::<nix::libc::c_void>(), bytes.len()) };
    if rc == 0 {
        return true;
    }
    let error = std::io::Error::last_os_error();
    eprintln!("linux-vault-helper: mlock failed: {error}");
    false
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase([redacted])")
    }
}

/// Why the helper is asking.
#[derive(Clone, Copy, Debug)]
pub enum Purpose {
    /// Set the passphrase. Pinentry asks twice.
    Create,
    /// Unlock. Pinentry asks once.
    Unlock,
    /// Recovery lock. Pinentry asks twice, because no archive can check it.
    Recovery,
    /// Delete the vault. Pinentry asks once.
    Terminate,
}

impl Purpose {
    fn confirm(self) -> bool {
        matches!(self, Self::Create | Self::Recovery)
    }

    fn description(self, vault: &str) -> String {
        match self {
            Self::Create => format!("Choose a passphrase for {vault}."),
            Self::Unlock => format!("Unlock {vault}."),
            Self::Recovery => format!("Confirm the passphrase for {vault}."),
            Self::Terminate => format!("Terminate {vault}."),
        }
    }
}

/// A pinentry launch command.
pub struct Pinentry {
    argv: Vec<OsString>,
    /// Shown in the not-logged-in error. Not passed to `systemd-run`.
    user: Option<String>,
    /// When set, `systemd-run` and `systemctl` run as this user.
    launch: Option<Launch>,
    unit: Option<String>,
}

#[derive(Clone, Copy)]
struct Launch {
    uid: u32,
    gid: u32,
}

impl Pinentry {
    /// `systemd-run --user --pipe --wait -q --unit=lve-pinentry-<id> pinentry-qt`
    ///
    /// The child drops to `uid`/`gid` first, the same way `7z` does: clear
    /// supplementary groups, then `setgid`, then `setuid`. Its environment is
    /// only `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`. `<id>` is random.
    pub fn systemd_run(user: &str, uid: u32, gid: u32) -> Result<Self, PinentryError> {
        if !plain_account(user) {
            return Err(PinentryError::Failed(
                "user name is not safe to pass to systemd-run".into(),
            ));
        }
        let unit = random_unit()?;
        Ok(Self {
            argv: vec![
                OsString::from("systemd-run"),
                OsString::from("--user"),
                OsString::from("--pipe"),
                OsString::from("--wait"),
                OsString::from("-q"),
                OsString::from(format!("--unit={unit}")),
                OsString::from("pinentry-qt"),
            ],
            user: Some(user.to_string()),
            launch: Some(Launch { uid, gid }),
            unit: Some(unit),
        })
    }

    /// Launch this program. The first item is the executable.
    pub fn argv(argv: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> Self {
        Self {
            argv: argv
                .into_iter()
                .map(|part| part.as_ref().to_os_string())
                .collect(),
            user: None,
            launch: None,
            unit: None,
        }
    }

    pub fn command(&self) -> &[OsString] {
        &self.argv
    }

    /// Ask for the passphrase. `cancel` interrupts the conversation.
    pub async fn ask(
        &self,
        purpose: Purpose,
        vault: &str,
        cancel: &CancelToken,
    ) -> Result<Passphrase, PinentryError> {
        if vault.contains('\0') {
            return Err(PinentryError::Failed("vault name contains NUL".into()));
        }
        if cancel.is_cancelled() {
            return Err(PinentryError::Cancelled);
        }
        if let Some(launch) = &self.launch {
            ensure_logged_in(launch.uid, self.user.as_deref().unwrap_or("user")).await?;
        }
        let mut session = Session::spawn(&self.argv, self.launch, self.unit.clone()).await?;
        let result = session.talk(purpose, vault, cancel).await;
        // A cancel token already killed the child. BYE would wait on a prompt
        // that is never going to answer. A Cancel the user pressed in pinentry
        // still gets BYE.
        if !session.stopped {
            session.bye(cancel).await;
        }
        result
    }
}

/// Failure from pinentry. None of the messages include the passphrase.
#[derive(Debug)]
pub enum PinentryError {
    /// The user pressed Cancel, or the prompt was cancelled.
    Cancelled,
    /// Empty, or the decoded passphrase contains CR, LF, or NUL.
    InvalidPassphrase,
    /// Create or recovery got a passphrase without `S PIN_REPEATED`.
    NotRepeated,
    /// Pinentry's own timer expired.
    Timeout,
    /// The prompt could not be shown.
    NoDisplay,
    /// logind has no session for this user, or `/run/user/<uid>` does not exist.
    NotLoggedIn { user: Option<String> },
    /// Pinentry could not be started, or the conversation broke.
    Failed(String),
}

impl std::fmt::Display for PinentryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled"),
            Self::InvalidPassphrase => {
                f.write_str("passphrase is empty or contains a line break or NUL")
            }
            Self::NotRepeated => f.write_str("pinentry did not confirm the passphrase"),
            Self::Timeout => f.write_str("pinentry timed out"),
            Self::NoDisplay => f.write_str("pinentry has no display"),
            Self::NotLoggedIn { user: Some(user) } => {
                write!(
                    f,
                    "{user} is not logged in, so there is no session for pinentry"
                )
            }
            Self::NotLoggedIn { user: None } => {
                f.write_str("not logged in, so there is no session for pinentry")
            }
            Self::Failed(message) => write!(f, "pinentry failed: {message}"),
        }
    }
}

impl std::error::Error for PinentryError {}

fn random_unit() -> Result<String, PinentryError> {
    let mut bytes = [0u8; 16];
    let mut random = std::fs::File::open("/dev/urandom")
        .map_err(|error| PinentryError::Failed(error.to_string()))?;
    random
        .read_exact(&mut bytes)
        .map_err(|error| PinentryError::Failed(error.to_string()))?;
    let mut id = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0xf) as usize] as char);
    }
    Ok(format!("lve-pinentry-{id}"))
}

fn plain_account(user: &str) -> bool {
    let mut chars = user.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: Option<tokio::task::JoinHandle<Vec<u8>>>,
    launch: Option<Launch>,
    unit: Option<String>,
    stopped: bool,
    line: Zeroizing<[u8; LINE_CAP]>,
    decoded: Zeroizing<[u8; LINE_CAP]>,
}

impl Session {
    async fn spawn(
        argv: &[OsString],
        launch: Option<Launch>,
        unit: Option<String>,
    ) -> Result<Self, PinentryError> {
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| PinentryError::Failed("no pinentry command".into()))?;
        let mut child = None;
        let mut last_error = None;
        for _ in 0..8 {
            let mut command = Command::new(program);
            command
                .args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            if let Some(launch) = launch {
                apply_user_session(&mut command, launch);
            }
            match command.spawn() {
                Ok(spawned) => {
                    child = Some(spawned);
                    break;
                }
                // A script that was just written can still be busy for exec.
                Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    last_error = Some(error);
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(error) => return Err(PinentryError::Failed(error.to_string())),
            }
        }
        let mut child = child.ok_or_else(|| {
            PinentryError::Failed(
                last_error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "pinentry did not start".into()),
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PinentryError::Failed("pinentry stdin was not piped".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PinentryError::Failed("pinentry stdout was not piped".into()))?;
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| PinentryError::Failed("pinentry stderr was not piped".into()))?;
        let stderr = tokio::spawn(async move {
            let mut bytes = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut bytes).await;
            bytes
        });
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr: Some(stderr),
            launch,
            unit,
            stopped: false,
            line: Zeroizing::new([0; LINE_CAP]),
            decoded: Zeroizing::new([0; LINE_CAP]),
        })
    }

    async fn talk(
        &mut self,
        purpose: Purpose,
        vault: &str,
        cancel: &CancelToken,
    ) -> Result<Passphrase, PinentryError> {
        if let Err(error) = self.expect_ok(cancel).await {
            return Err(self.report_startup_failure(error).await);
        }
        self.exchange(
            &format!("SETDESC {}", escape(&purpose.description(vault))),
            cancel,
        )
        .await?;
        self.exchange(&format!("SETPROMPT {}", escape("Passphrase:")), cancel)
            .await?;
        if purpose.confirm() {
            self.exchange(
                &format!("SETREPEAT {}", escape("Repeat passphrase:")),
                cancel,
            )
            .await?;
            self.exchange(
                &format!("SETREPEATERROR {}", escape("Passphrases do not match.")),
                cancel,
            )
            .await?;
        }
        self.getpin(purpose.confirm(), cancel).await
    }

    /// A failure before pinentry speaks is not "not logged in". That was
    /// decided before the process was started. stderr goes to the journal.
    async fn report_startup_failure(&mut self, error: PinentryError) -> PinentryError {
        let closed = matches!(
            &error,
            PinentryError::Failed(message) if message.contains("closed the pipe")
        );
        if !closed {
            return error;
        }
        let stderr = self.stderr_text().await;
        log_pinentry_stderr(&stderr);
        PinentryError::Failed("could not start pinentry".into())
    }

    async fn stderr_text(&mut self) -> String {
        self.child.start_kill().ok();
        let _ = self.child.wait().await;
        let Some(handle) = self.stderr.take() else {
            return String::new();
        };
        let bytes = handle.await.unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    async fn getpin(
        &mut self,
        confirm: bool,
        cancel: &CancelToken,
    ) -> Result<Passphrase, PinentryError> {
        const ATTEMPTS: u32 = 8;
        for _ in 0..ATTEMPTS {
            self.send("GETPIN").await?;
            match self.read_pin(confirm, cancel).await? {
                Reply::Passphrase(passphrase) => return Ok(passphrase),
                Reply::Mismatch => continue,
                Reply::Cancelled => return Err(PinentryError::Cancelled),
                Reply::Timeout => return Err(PinentryError::Timeout),
                Reply::NoDisplay => return Err(PinentryError::NoDisplay),
                Reply::Failed(message) => return Err(PinentryError::Failed(message)),
            }
        }
        Err(PinentryError::Failed(
            "pinentry did not confirm the passphrase".into(),
        ))
    }

    async fn read_pin(
        &mut self,
        confirm: bool,
        cancel: &CancelToken,
    ) -> Result<Reply, PinentryError> {
        self.decoded.zeroize();
        let mut decoded_len = 0;
        let mut repeated = false;
        loop {
            let len = self.read_line(cancel).await?;
            let line = &self.line[..len];
            if line.is_empty() || line.first() == Some(&b'#') {
                continue;
            }
            if is_pin_repeated(line) {
                repeated = true;
                continue;
            }
            if line.starts_with(b"S ") {
                continue;
            }
            if line_is(line, b"OK") {
                if confirm && !repeated {
                    self.decoded.zeroize();
                    return Err(PinentryError::NotRepeated);
                }
                let passphrase = accept(&self.decoded[..decoded_len]);
                self.decoded.zeroize();
                return passphrase.map(Reply::Passphrase);
            }
            if line_is(line, b"ERR") {
                self.decoded.zeroize();
                return Ok(classify_error(line));
            }
            if let Some(encoded) = data_payload(line) {
                let room = &mut self.decoded[decoded_len..];
                decoded_len += decode_into(room, encoded)?;
                continue;
            }
            self.decoded.zeroize();
            return Err(PinentryError::Failed("unexpected pinentry reply".into()));
        }
    }

    async fn exchange(&mut self, command: &str, cancel: &CancelToken) -> Result<(), PinentryError> {
        self.send(command).await?;
        self.expect_ok(cancel).await
    }

    async fn expect_ok(&mut self, cancel: &CancelToken) -> Result<(), PinentryError> {
        loop {
            let len = self.read_line(cancel).await?;
            let line = &self.line[..len];
            if line.is_empty() || line.first() == Some(&b'#') || line.starts_with(b"S ") {
                continue;
            }
            if line_is(line, b"OK") {
                return Ok(());
            }
            if line.starts_with(b"ERR") {
                return Err(PinentryError::Failed("pinentry rejected a command".into()));
            }
            return Err(PinentryError::Failed("expected OK from pinentry".into()));
        }
    }

    async fn bye(&mut self, cancel: &CancelToken) {
        let _ = self.send("BYE").await;
        let _ = self.read_line(cancel).await;
        drop(self.stdin.take());
        let _ = self.child.wait().await;
        if let Some(handle) = self.stderr.take() {
            let _ = handle.await;
        }
    }

    async fn send(&mut self, command: &str) -> Result<(), PinentryError> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| PinentryError::Failed("pinentry stdin is closed".into()))?;
        stdin
            .write_all(command.as_bytes())
            .await
            .map_err(|error| PinentryError::Failed(error.to_string()))?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|error| PinentryError::Failed(error.to_string()))?;
        stdin
            .flush()
            .await
            .map_err(|error| PinentryError::Failed(error.to_string()))
    }

    /// Read one Assuan line into `self.line`. The buffer is fixed; a longer
    /// line is an error and is not copied into the error text.
    async fn read_line(&mut self, cancel: &CancelToken) -> Result<usize, PinentryError> {
        self.line.zeroize();
        let mut len = 0;
        loop {
            if len == LINE_CAP {
                self.line.zeroize();
                return Err(PinentryError::Failed("pinentry line is too long".into()));
            }
            let mut byte = 0u8;
            let read = tokio::select! {
                biased;
                _ = cancel.cancelled() => None,
                result = self.stdout.read(std::slice::from_mut(&mut byte)) => Some(result),
            };
            let Some(read) = read else {
                byte.zeroize();
                return Err(self.cancel_child().await);
            };
            match read {
                Ok(0) => {
                    byte.zeroize();
                    if len == 0 {
                        return Err(PinentryError::Failed("pinentry closed the pipe".into()));
                    }
                    break;
                }
                Ok(_) => {
                    if byte == b'\n' {
                        byte.zeroize();
                        break;
                    }
                    self.line[len] = byte;
                    byte.zeroize();
                    len += 1;
                }
                Err(error) => {
                    byte.zeroize();
                    return Err(PinentryError::Failed(error.to_string()));
                }
            }
        }
        if len > 0 && self.line[len - 1] == b'\r' {
            self.line[len - 1] = 0;
            len -= 1;
        }
        Ok(len)
    }

    async fn cancel_child(&mut self) -> PinentryError {
        self.stopped = true;
        self.stop_unit().await;
        self.child.start_kill().ok();
        let _ = self.child.wait().await;
        if let Some(handle) = self.stderr.take() {
            let _ = handle.await;
        }
        PinentryError::Cancelled
    }

    async fn stop_unit(&self) {
        let (Some(launch), Some(unit)) = (self.launch, self.unit.as_deref()) else {
            return;
        };
        let mut command = Command::new("systemctl");
        command
            .arg("--user")
            .arg("stop")
            .arg(unit)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        apply_user_session(&mut command, launch);
        let _ = command.status().await;
    }
}

enum Reply {
    Passphrase(Passphrase),
    Mismatch,
    Cancelled,
    Timeout,
    NoDisplay,
    Failed(String),
}

fn is_pin_repeated(line: &[u8]) -> bool {
    line == b"S PIN_REPEATED" || line.starts_with(b"S PIN_REPEATED ")
}

fn log_pinentry_stderr(stderr: &str) {
    let text = stderr.trim();
    if text.is_empty() {
        return;
    }
    eprintln!("linux-vault-helper: pinentry: {text}");
}

/// Not logged in when the runtime directory is missing or logind has no
/// session. `stat` of `/run/user/<uid>` needs no `CAP_DAC_OVERRIDE`: the
/// parent is searchable, and only the directory's metadata is read.
async fn ensure_logged_in(uid: u32, user: &str) -> Result<(), PinentryError> {
    if runtime_dir_missing(uid) || !logind_has_session(uid).await? {
        return Err(PinentryError::NotLoggedIn {
            user: Some(user.to_string()),
        });
    }
    Ok(())
}

fn runtime_dir_missing(uid: u32) -> bool {
    matches!(
        std::fs::symlink_metadata(format!("/run/user/{uid}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

async fn logind_has_session(uid: u32) -> Result<bool, PinentryError> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|error| PinentryError::Failed(format!("logind is not available: {error}")))?;
    let proxy = LoginSessionsProxy::new(&connection)
        .await
        .map_err(|error| PinentryError::Failed(format!("logind is not available: {error}")))?;
    let sessions = proxy
        .list_sessions()
        .await
        .map_err(|error| PinentryError::Failed(format!("logind is not available: {error}")))?;
    Ok(sessions.iter().any(|session| session.1 == uid))
}

fn user_session_env(uid: u32) -> [(&'static str, String); 2] {
    [
        ("XDG_RUNTIME_DIR", format!("/run/user/{uid}")),
        (
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{uid}/bus"),
        ),
    ]
}

/// Run this command as `launch`, with only the user-session bus in the environment.
fn apply_user_session(command: &mut Command, launch: Launch) {
    command.env_clear();
    for (key, value) in user_session_env(launch.uid) {
        command.env(key, value);
    }
    let clear_groups = must_clear_groups();
    // SAFETY: the closure runs between fork and exec. It only calls
    // setgroups, setgid, and setuid, which are async-signal-safe. Same order
    // as the 7z child: groups, then gid, then uid.
    unsafe {
        command.pre_exec(move || {
            linux_vault::close_extra_fds()?;
            drop_privileges(launch.uid, launch.gid, clear_groups)
        });
    }
}

pub(crate) fn drop_to(uid: u32, gid: u32) -> std::io::Result<()> {
    drop_privileges(uid, gid, must_clear_groups())
}

fn drop_privileges(uid: u32, gid: u32, clear_groups: bool) -> std::io::Result<()> {
    if clear_groups {
        // SAFETY: size 0 clears the supplementary group list. No list is read.
        let rc = unsafe { nix::libc::setgroups(0, std::ptr::null()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let rc = unsafe { nix::libc::setgid(gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { nix::libc::setuid(uid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn must_clear_groups() -> bool {
    const CAP_SETGID: u64 = 1 << 6;
    const CAP_SETUID: u64 = 1 << 7;
    match effective_caps() {
        Some(caps) => caps & (CAP_SETGID | CAP_SETUID) != 0,
        None => true,
    }
}

fn effective_caps() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = text.lines().find(|line| line.starts_with("CapEff:"))?;
    let hex = line.split_whitespace().nth(1)?;
    u64::from_str_radix(hex, 16).ok()
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait LoginSessions {
    fn list_sessions(&self) -> zbus::Result<Vec<LogindSession>>;
}

type LogindSession = (String, u32, String, String, zbus::zvariant::OwnedObjectPath);

fn line_is(line: &[u8], word: &[u8]) -> bool {
    line == word || (line.starts_with(word) && line.get(word.len()) == Some(&b' '))
}

fn classify_error(line: &[u8]) -> Reply {
    let text = String::from_utf8_lossy(line);
    let lower = text.to_ascii_lowercase();
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|word| word.parse::<u32>().ok());
    if code == Some(83886179) || lower.contains("cancelled") || lower.contains("canceled") {
        return Reply::Cancelled;
    }
    if lower.contains("not match") {
        return Reply::Mismatch;
    }
    if code == Some(83886142) || lower.contains("timeout") {
        return Reply::Timeout;
    }
    if code == Some(83918950)
        || lower.contains("display")
        || lower.contains("isatty")
        || lower.contains("ioctl")
    {
        return Reply::NoDisplay;
    }
    Reply::Failed(format!("pinentry error: {}", text.trim()))
}

fn data_payload(line: &[u8]) -> Option<&[u8]> {
    if line == b"D" {
        Some(b"")
    } else {
        line.strip_prefix(b"D ")
    }
}

fn decode_into(out: &mut [u8], encoded: &[u8]) -> Result<usize, PinentryError> {
    let mut index = 0;
    let mut written = 0;
    while index < encoded.len() {
        if written == out.len() {
            return Err(PinentryError::Failed("pinentry line is too long".into()));
        }
        if encoded[index] != b'%' {
            out[written] = encoded[index];
            written += 1;
            index += 1;
            continue;
        }
        if index + 2 >= encoded.len() {
            return Err(PinentryError::Failed("truncated percent escape".into()));
        }
        let high = hex_value(encoded[index + 1])?;
        let low = hex_value(encoded[index + 2])?;
        out[written] = (high << 4) | low;
        written += 1;
        index += 3;
    }
    Ok(written)
}

fn hex_value(byte: u8) -> Result<u8, PinentryError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PinentryError::Failed("bad percent escape".into())),
    }
}

fn accept(bytes: &[u8]) -> Result<Passphrase, PinentryError> {
    if bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
        Err(PinentryError::InvalidPassphrase)
    } else {
        Ok(Passphrase::from_bytes(bytes))
    }
}

/// Escape `%`, CR, and LF so one Assuan command stays one line.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '%' => escaped.push_str("%25"),
            '\r' => escaped.push_str("%0D"),
            '\n' => escaped.push_str("%0A"),
            other => escaped.push(other),
        }
    }
    escaped
}
