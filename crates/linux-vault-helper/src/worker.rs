//! A worker for one user's home.
//!
//! The helper starts `linux-vault-helper --worker`, drops it to that user's
//! uid and gid, and talks to it over a socketpair. The worker canonicalizes
//! paths, runs 7z, renames, syncs, deletes, and edits bookmarks. When the
//! immutable flag has to change it opens the archive `O_RDONLY|O_NOFOLLOW`
//! and sends the descriptor. The helper checks `fstat` and runs the ioctl.

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use linux_vault::Vaults;
use zeroize::Zeroizing;

use crate::error::HelperError;
use crate::pinentry::{self, Passphrase};

const RESOLVE: u8 = 1;
const PACK: u8 = 2;
const UNPACK: u8 = 3;
const DELETE_ARCHIVE: u8 = 4;
const DELETE_PLAIN: u8 = 5;
const INSPECT: u8 = 6;
const BOOKMARK: u8 = 7;
const FLAG: u8 = 8;
const ACK: u8 = 9;
const OK: u8 = 10;
const ERR: u8 = 11;
const FACTS: u8 = 12;
const SEAL: u8 = 14;
const SCAN: u8 = 15;
const OWNER: u8 = 16;
const MAX_BODY: usize = 1024 * 1024;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

/// Clear the effective, permitted, and inheritable sets.
///
/// The helper keeps `CAP_LINUX_IMMUTABLE` and sets the flag on a descriptor
/// this process sends. A worker that stayed root would otherwise still have
/// that capability and could set the flag itself.
fn drop_capabilities() -> Result<(), String> {
    const VERSION_3: u32 = 0x2008_0522;
    const SYS_CAPGET: i64 = 125;
    const SYS_CAPSET: i64 = 126;
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let rc = unsafe {
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut data: [Data; 2] = std::mem::zeroed();
        if nix::libc::syscall(SYS_CAPGET, &mut header, data.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        data = std::mem::zeroed();
        nix::libc::syscall(SYS_CAPSET, &header, data.as_ptr())
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// Entry point for `--worker`. The socket is fd 3. Dumpable is cleared first.
pub fn run() -> i32 {
    crate::disable_core_dumps().ok();
    // setuid to a normal user already clears capabilities. Clearing them
    // again covers a worker whose uid is 0: it must not be able to change
    // the immutable flag. The helper does that on the descriptor this
    // process sends.
    if let Err(error) = drop_capabilities() {
        let _ = std::io::stderr().write_all(
            format!("linux-vault-helper: worker: dropping capabilities: {error}\n").as_bytes(),
        );
        return 1;
    }
    // The helper's dup2 left fd 3 without close-on-exec so this exec could
    // receive it. Children of the worker, including 7z, must not inherit it.
    let flags = unsafe { nix::libc::fcntl(3, nix::libc::F_GETFD) };
    if flags >= 0 {
        unsafe {
            nix::libc::fcntl(3, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC);
        }
    }
    unsafe {
        nix::libc::signal(
            nix::libc::SIGTERM,
            on_term as *const () as nix::libc::sighandler_t,
        );
    }
    let sock = unsafe { UnixStream::from_raw_fd(3) };
    if let Err(error) = serve(sock) {
        let _ = std::io::stderr()
            .write_all(format!("linux-vault-helper: worker: {error}\n").as_bytes());
        return 1;
    }
    0
}

fn serve(mut sock: UnixStream) -> Result<(), String> {
    let (home, seven_zip) = match read_frame(&mut sock) {
        Ok((OK, body, _)) => {
            let text = String::from_utf8_lossy(&body);
            let mut parts = text.split('\0');
            let home = PathBuf::from(parts.next().unwrap_or(""));
            let seven_zip = parts
                .next()
                .filter(|path| !path.is_empty())
                .map(PathBuf::from);
            (home, seven_zip)
        }
        Ok((ERR, body, _)) => return Err(String::from_utf8_lossy(&body).into_owned()),
        Ok(_) => return Err("worker expected a home path".into()),
        Err(error) => return Err(error.to_string()),
    };
    write_frame(&mut sock, OK, &[], None)
        .map_err(|error| format!("starting worker for {}: {error}", home.display()))?;
    let registry = home.join(format!(".lve-worker-{}", std::process::id()));
    let mut opened = Vaults::open(&registry, &home)
        .map_err(|error| format!("opening worker registry for {}: {error}", home.display()))?;
    if let Some(path) = seven_zip {
        opened.set_seven_zip(path);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let watch = Arc::clone(&stop);
    thread::spawn(move || {
        while !STOP.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(20));
        }
        watch.store(true, Ordering::SeqCst);
    });
    let opened = opened.with_stop_flag(stop);
    let sock = Arc::new(Mutex::new(sock));
    let hook_sock = Arc::clone(&sock);
    let vaults = opened.with_flag_hook(move |archive, set| {
        let mut guard = hook_sock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        send_flag(&mut guard, set, archive).map_err(linux_vault::Error::from)
    });
    loop {
        let (tag, body, _) = {
            let mut guard = sock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match read_frame(&mut guard) {
                Ok(frame) => frame,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => {
                    return Err(format!(
                        "reading worker command for {}: {error}",
                        home.display()
                    ))
                }
            }
        };
        let result = dispatch(&vaults, tag, &body);
        let mut guard = sock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) =
            result.and_then(|reply| write_frame(&mut guard, reply.0, &reply.1, None))
        {
            return Err(format!(
                "writing worker reply for {}: {error}",
                home.display()
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&registry);
    Ok(())
}

fn dispatch(vaults: &Vaults, tag: u8, body: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
    let run = || -> Result<(u8, Vec<u8>), String> {
        match tag {
            RESOLVE => {
                let path = std::str::from_utf8(body)
                    .map_err(|error| format!("resolving for worker command: {error}"))?;
                let resolved = vaults
                    .resolve_folder(Path::new(path))
                    .map_err(|error| format!("resolving for {path}: {error}"))?;
                Ok((OK, path_bytes(&resolved)))
            }
            PACK => {
                let (path, pass) = split_secret(body)?;
                let pass = Passphrase::from_bytes(&pass);
                vaults
                    .pack_folder(Path::new(&path), pass.as_bytes())
                    .map_err(|error| format!("locking for {path}: {error}"))?;
                Ok((OK, Vec::new()))
            }
            UNPACK => {
                let (path, pass) = split_secret(body)?;
                let pass = Passphrase::from_bytes(&pass);
                vaults
                    .unpack_folder(Path::new(&path), pass.as_bytes())
                    .map_err(|error| format!("unlocking for {path}: {error}"))?;
                Ok((OK, Vec::new()))
            }
            DELETE_ARCHIVE => {
                let (path, pass) = split_secret(body)?;
                let pass = Passphrase::from_bytes(&pass);
                vaults
                    .remove_locked_archive(Path::new(&path), pass.as_bytes())
                    .map_err(|error| format!("deleting the archive for {path}: {error}"))?;
                Ok((OK, Vec::new()))
            }
            DELETE_PLAIN => {
                let path = std::str::from_utf8(body)
                    .map_err(|error| format!("deleting the folder for worker command: {error}"))?;
                vaults
                    .remove_plain_folder(Path::new(path))
                    .map_err(|error| format!("deleting the folder for {path}: {error}"))?;
                Ok((OK, Vec::new()))
            }
            INSPECT => {
                let path = std::str::from_utf8(body)
                    .map_err(|error| format!("inspecting for worker command: {error}"))?;
                let facts = vaults
                    .filename_facts(Path::new(path))
                    .map_err(|error| format!("inspecting for {path}: {error}"))?;
                Ok((FACTS, vec![u8::from(facts.folder), u8::from(facts.archive)]))
            }
            BOOKMARK => {
                let path = std::str::from_utf8(body).map_err(|error| {
                    format!("removing the bookmark for worker command: {error}")
                })?;
                crate::bookmarks::remove_along(Path::new(path))
                    .map_err(|error| format!("removing the bookmark for {path}: {error}"))?;
                Ok((OK, Vec::new()))
            }
            SEAL => {
                let path = std::str::from_utf8(body)
                    .map_err(|error| format!("sealing for worker command: {error}"))?;
                vaults
                    .seal_archive(Path::new(path))
                    .map_err(|error| format!("sealing for {path}: {error}"))?;
                Ok((OK, Vec::new()))
            }
            OWNER => {
                let path = std::str::from_utf8(body)
                    .map_err(|error| format!("reading the owner for worker command: {error}"))?;
                let uid = owner_of(Path::new(path))?;
                Ok((OK, uid.to_le_bytes().to_vec()))
            }
            SCAN => {
                let split = body.iter().position(|byte| *byte == 0).ok_or_else(|| {
                    "checking open files for worker command: missing a vault path".to_string()
                })?;
                let name = std::str::from_utf8(&body[..split])
                    .map_err(|error| format!("checking open files for worker command: {error}"))?;
                let path = std::str::from_utf8(&body[split + 1..])
                    .map_err(|error| format!("checking open files for {name}: {error}"))?;
                let uid = unsafe { nix::libc::getuid() };
                match crate::open_files::refuse_if_open(Path::new(path), name, uid) {
                    Ok(()) => Ok((OK, Vec::new())),
                    Err(HelperError::Failed(message)) => {
                        Err(format!("checking open files for {path}: {message}"))
                    }
                    Err(error) => Err(format!("checking open files for {path}: {error}")),
                }
            }
            _ => Err(format!("unknown worker command {tag}")),
        }
    };
    match run() {
        Ok(reply) => Ok(reply),
        Err(error) => Ok((ERR, error.into_bytes())),
    }
}

fn send_flag(sock: &mut UnixStream, set: bool, archive: &Path) -> std::io::Result<()> {
    let fd = open_archive(archive)?;
    write_frame(sock, FLAG, &[u8::from(set)], Some(fd.as_raw_fd()))?;
    let (tag, body, _) = read_frame(sock)?;
    if tag == ERR {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }
    if tag != ACK {
        return Err(std::io::Error::other(
            "helper did not acknowledge the archive descriptor",
        ));
    }
    Ok(())
}

fn open_archive(path: &Path) -> std::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "archive path contains NUL",
        )
    })?;
    let fd = unsafe {
        nix::libc::open(
            name.as_ptr(),
            nix::libc::O_RDONLY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The caller can see this path. A missing folder or archive, or a parent
/// this user cannot search, is a failure. There is no fallback to the parent.
fn owner_of(vault: &Path) -> Result<u32, String> {
    if let Some(uid) = uid_of(vault) {
        return Ok(uid);
    }
    if let Some(name) = vault.file_name().and_then(|name| name.to_str()) {
        let archive = vault.with_file_name(format!("{name}.7z"));
        if let Some(uid) = uid_of(&archive) {
            return Ok(uid);
        }
    }
    Err(format!("cannot see the owner of {}", vault.display()))
}

fn uid_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|meta| meta.uid())
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

fn split_secret(body: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>), String> {
    let split = body
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "worker command is missing a passphrase".to_string())?;
    let path = std::str::from_utf8(&body[..split])
        .map_err(|error| format!("reading the vault path for worker command: {error}"))?
        .to_string();
    Ok((path, Zeroizing::new(body[split + 1..].to_vec())))
}

/// One worker for `uid`/`gid`, allowed to touch `home`.
pub struct HomeWorker {
    child: std::process::Child,
    sock: UnixStream,
    uid: u32,
    vaults: Vaults,
    live: Arc<Mutex<Vec<u32>>>,
}

impl HomeWorker {
    pub fn spawn(
        uid: u32,
        gid: u32,
        home: &Path,
        vaults: Vaults,
        live: Arc<Mutex<Vec<u32>>>,
    ) -> Result<Self, HelperError> {
        let (ours, theirs) = UnixStream::pair().map_err(|error| {
            HelperError::Failed(format!(
                "starting worker for {home}: {error}",
                home = home.display()
            ))
        })?;
        let program = worker_program();
        let raw = theirs.as_raw_fd();
        // SAFETY: dup2 and the privilege drop run between fork and exec.
        // dup2's new descriptor does not keep close-on-exec, so fd 3 survives.
        let mut command = Command::new(program);
        command
            .arg("--worker")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(move || {
                pinentry::drop_to(uid, gid)?;
                if nix::libc::dup2(raw, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|error| {
            HelperError::Failed(format!("starting worker for {}: {error}", home.display()))
        })?;
        remember_worker(&live, child.id());
        drop(theirs);
        let home_body = format!("{}\0{}", home.display(), vaults.seven_zip().display());
        let mut worker = Self {
            child,
            sock: ours,
            uid,
            vaults,
            live,
        };
        worker
            .roundtrip(OK, home_body.as_bytes())
            .map_err(|error| {
                HelperError::Failed(format!(
                    "starting worker for {}: {}",
                    home.display(),
                    failed_text(error)
                ))
            })?;
        Ok(worker)
    }

    /// UID of the folder, or of the archive when the folder is gone.
    /// Fails when this user cannot stat either one.
    pub fn owner_of(&mut self, path: &Path) -> Result<u32, HelperError> {
        let body = self
            .roundtrip(OWNER, &path_bytes(path))
            .map_err(|error| step_error("reading the owner", path, error))?;
        let bytes: [u8; 4] = body.as_slice().try_into().map_err(|_| {
            step_error(
                "reading the owner",
                path,
                HelperError::Failed("worker sent a short owner id".into()),
            )
        })?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn resolve(&mut self, path: &Path) -> Result<PathBuf, HelperError> {
        let body = self
            .roundtrip(RESOLVE, path_bytes(path).as_slice())
            .map_err(|error| step_error("resolving", path, error))?;
        Ok(PathBuf::from(String::from_utf8_lossy(&body).as_ref()))
    }

    pub fn pack(&mut self, path: &Path, passphrase: &[u8]) -> Result<(), HelperError> {
        self.secret(PACK, path, passphrase)
            .map_err(|error| step_error("locking", path, error))
    }

    pub fn unpack(&mut self, path: &Path, passphrase: &[u8]) -> Result<(), HelperError> {
        self.secret(UNPACK, path, passphrase)
            .map_err(|error| step_error("unlocking", path, error))
    }

    pub fn delete_archive(&mut self, path: &Path, passphrase: &[u8]) -> Result<(), HelperError> {
        self.secret(DELETE_ARCHIVE, path, passphrase)
            .map_err(|error| step_error("deleting the archive", path, error))
    }

    pub fn delete_folder(&mut self, path: &Path) -> Result<(), HelperError> {
        self.roundtrip(DELETE_PLAIN, &path_bytes(path))
            .map(|_| ())
            .map_err(|error| step_error("deleting the folder", path, error))
    }

    pub fn inspect(&mut self, path: &Path) -> Result<linux_vault::FilenameFacts, HelperError> {
        self.send(INSPECT, &path_bytes(path))
            .map_err(|error| step_error("inspecting", path, error))?;
        loop {
            let (tag, body, fd) = read_frame(&mut self.sock).map_err(|error| {
                step_error("inspecting", path, HelperError::Failed(error.to_string()))
            })?;
            match tag {
                FLAG => self
                    .ack_flag(body.first().copied().unwrap_or(0) == 1, fd)
                    .map_err(|error| step_error("setting the immutable flag", path, error))?,
                FACTS => {
                    return Ok(linux_vault::FilenameFacts {
                        folder: body.first().copied().unwrap_or(0) == 1,
                        archive: body.get(1).copied().unwrap_or(0) == 1,
                    })
                }
                ERR => {
                    return Err(step_error(
                        "inspecting",
                        path,
                        HelperError::Failed(String::from_utf8_lossy(&body).into_owned()),
                    ))
                }
                _ => {
                    return Err(step_error(
                        "inspecting",
                        path,
                        HelperError::Failed("worker sent an unexpected inspect reply".into()),
                    ))
                }
            }
        }
    }

    pub fn remove_bookmark(&mut self, path: &Path) -> Result<(), HelperError> {
        self.roundtrip(BOOKMARK, &path_bytes(path))
            .map(|_| ())
            .map_err(|error| step_error("removing the bookmark", path, error))
    }

    pub fn scan_open_files(&mut self, name: &str, path: &Path) -> Result<(), HelperError> {
        let mut body = name.as_bytes().to_vec();
        body.push(0);
        body.extend(path_bytes(path));
        self.roundtrip(SCAN, &body)
            .map(|_| ())
            .map_err(|error| step_error("checking open files", path, error))
    }

    pub fn seal(&mut self, path: &Path) -> Result<(), HelperError> {
        self.roundtrip(SEAL, &path_bytes(path))
            .map(|_| ())
            .map_err(|error| step_error("sealing", path, error))
    }

    fn secret(&mut self, tag: u8, path: &Path, passphrase: &[u8]) -> Result<(), HelperError> {
        let mut body = path_bytes(path);
        body.push(0);
        body.extend_from_slice(passphrase);
        self.roundtrip(tag, &body)?;
        Ok(())
    }

    fn roundtrip(&mut self, tag: u8, body: &[u8]) -> Result<Vec<u8>, HelperError> {
        self.send(tag, body)?;
        loop {
            let (reply, payload, fd) = read_frame(&mut self.sock)
                .map_err(|error| HelperError::Failed(format!("reading worker reply: {error}")))?;
            match reply {
                FLAG => self.ack_flag(payload.first().copied().unwrap_or(0) == 1, fd)?,
                OK | FACTS => return Ok(payload),
                ERR => {
                    return Err(HelperError::Failed(
                        String::from_utf8_lossy(&payload).into_owned(),
                    ))
                }
                _ => {
                    return Err(HelperError::Failed(
                        "reading worker reply: worker sent an unexpected reply".into(),
                    ))
                }
            }
        }
    }

    fn send(&mut self, tag: u8, body: &[u8]) -> Result<(), HelperError> {
        write_frame(&mut self.sock, tag, body, None)
            .map_err(|error| HelperError::Failed(format!("writing worker command: {error}")))
    }

    fn ack_flag(&mut self, set: bool, fd: Option<OwnedFd>) -> Result<(), HelperError> {
        let Some(fd) = fd else {
            let _ = write_frame(
                &mut self.sock,
                ERR,
                b"setting the immutable flag for the archive: archive descriptor was missing",
                None,
            );
            return Err(HelperError::Failed(
                "setting the immutable flag for the archive: archive descriptor was missing".into(),
            ));
        };
        let applied = self.vaults.apply_flag_fd(fd.as_raw_fd(), self.uid, set);
        match applied {
            Ok(()) => write_frame(&mut self.sock, ACK, &[], None).map_err(|error| {
                HelperError::Failed(format!(
                    "setting the immutable flag for the archive: {error}"
                ))
            }),
            Err(error) => {
                let text = format!("setting the immutable flag for the archive: {error}");
                let _ = write_frame(&mut self.sock, ERR, text.as_bytes(), None);
                Err(HelperError::Failed(text))
            }
        }
    }
}

impl Drop for HomeWorker {
    fn drop(&mut self) {
        forget_worker(&self.live, self.child.id());
        drop(self.sock.shutdown(std::net::Shutdown::Both));
        let _ = self.child.wait();
    }
}

fn remember_worker(live: &Mutex<Vec<u32>>, pid: u32) {
    live.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(pid);
}

fn forget_worker(live: &Mutex<Vec<u32>>, pid: u32) {
    live.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|existing| *existing != pid);
}

/// SIGTERM each worker of this helper so an extract stops and the immutable flag is restored.
pub fn abort_live_workers(live: &Mutex<Vec<u32>>) {
    let pids = live
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    for pid in pids {
        unsafe {
            nix::libc::kill(pid as i32, nix::libc::SIGTERM);
        }
    }
}

pub fn wait_for_workers(live: &Mutex<Vec<u32>>, timeout: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let empty = live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        if empty {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn failed_text(error: HelperError) -> String {
    match error {
        HelperError::Failed(message) => message,
        other => other.to_string(),
    }
}

fn step_error(step: &str, path: &Path, error: HelperError) -> HelperError {
    let message = failed_text(error);
    let prefix = format!("{step} for ");
    if message.starts_with(&prefix) {
        HelperError::Failed(message)
    } else {
        HelperError::Failed(format!("{step} for {}: {message}", path.display()))
    }
}

fn worker_program() -> PathBuf {
    // Tests copy the helper out of a mode 700 home before dropping
    // CAP_DAC_OVERRIDE. The installed binary is already outside any home.
    if let Some(path) = std::env::var_os("LVE_HELPER_BIN") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_linux_vault_helper") {
        return PathBuf::from(path);
    }
    let current = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("linux-vault-helper"));
    // Integration tests run from target/debug/deps. The helper sits next to that.
    if let Some(deps) = current.parent() {
        if let Some(debug) = deps.parent() {
            let helper = debug.join("linux-vault-helper");
            if helper.is_file() {
                return helper;
            }
        }
    }
    current
}

fn write_frame(
    sock: &mut UnixStream,
    tag: u8,
    body: &[u8],
    fd: Option<RawFd>,
) -> std::io::Result<()> {
    let mut message = Vec::with_capacity(5 + body.len());
    message.push(tag);
    message.extend_from_slice(&(body.len() as u32).to_le_bytes());
    message.extend_from_slice(body);
    send_frame(sock.as_raw_fd(), &message, fd)
}

fn read_frame(sock: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>, Option<OwnedFd>)> {
    let (mut buf, fd) = recv_some(sock.as_raw_fd())?;
    if buf.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "worker socket closed",
        ));
    }
    while buf.len() < 5 {
        let (more, _) = recv_some(sock.as_raw_fd())?;
        if more.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "worker socket closed",
            ));
        }
        buf.extend_from_slice(&more);
    }
    let len = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as usize;
    if len > MAX_BODY {
        return Err(std::io::Error::other("worker message is too large"));
    }
    while buf.len() < 5 + len {
        let (more, _) = recv_some(sock.as_raw_fd())?;
        if more.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "worker socket closed",
            ));
        }
        buf.extend_from_slice(&more);
    }
    Ok((buf[0], buf[5..5 + len].to_vec(), fd))
}

fn send_frame(sock: RawFd, bytes: &[u8], fd: Option<RawFd>) -> std::io::Result<()> {
    let mut iov = nix::libc::iovec {
        iov_base: bytes.as_ptr() as *mut nix::libc::c_void,
        iov_len: bytes.len(),
    };
    let mut cmsg = [0u8; 64];
    let mut msg: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        unsafe {
            let cmsg_len = nix::libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
            msg.msg_control = cmsg.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_len;
            let header = nix::libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = nix::libc::SOL_SOCKET;
            (*header).cmsg_type = nix::libc::SCM_RIGHTS;
            (*header).cmsg_len = nix::libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write(nix::libc::CMSG_DATA(header) as *mut RawFd, fd);
        }
    }
    let sent = unsafe { nix::libc::sendmsg(sock, &msg, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn recv_some(sock: RawFd) -> std::io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut buf = vec![0u8; 8192];
    let mut iov = nix::libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut cmsg = [0u8; 64];
    let mut msg: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len();
    let got = unsafe { nix::libc::recvmsg(sock, &mut msg, 0) };
    if got < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    let mut owned = None;
    unsafe {
        let mut header = nix::libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == nix::libc::SOL_SOCKET
                && (*header).cmsg_type == nix::libc::SCM_RIGHTS
            {
                let fd = std::ptr::read(nix::libc::CMSG_DATA(header) as *const RawFd);
                owned = Some(OwnedFd::from_raw_fd(fd));
                break;
            }
            header = nix::libc::CMSG_NXTHDR(&msg, header);
        }
    }
    Ok((buf, owned))
}
