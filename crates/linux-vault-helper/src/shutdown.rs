//! Shutdown and `SIGTERM` share one path.
//!
//! New calls are refused and an operation waiting for its vault is cancelled.
//! Open pinentry prompts are cancelled, which stops their `lve-pinentry-<id>`
//! units. An unlock that is still extracting is aborted and the immutable flag
//! goes back on the archive. A lock that is already packing is left to finish.
//! Whatever is still unlocked is locked with the held key, or marked as
//! needing recovery when there is no key. The delay inhibitor is released.
//! `SIGTERM` then returns from `main`. `PrepareForShutdown` stays up until
//! systemd sends that signal. That signal runs this sequence again. The
//! second run waits for the first to finish, sees the vaults already locked,
//! and returns without locking them again.

use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures_util::StreamExt;
use linux_vault::State;
use tokio::sync::{Mutex, Notify};
use zbus::Connection;

use crate::error::HelperError;
use crate::open_files;
use crate::passwd_account;
use crate::pinentry::CancelToken;
use crate::HeldPassphrases;

/// Counts calls that have been accepted and are not finished.
///
/// Shutdown sets the flag, then waits until the count is zero. A call checks
/// the flag again after it takes the per-vault lock, so one that was waiting
/// in line returns without starting work.
pub(crate) struct Gate {
    started: AtomicBool,
    inflight: AtomicUsize,
    idle: Notify,
}

pub(crate) struct Flight(Arc<Gate>);

impl Gate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            started: AtomicBool::new(false),
            inflight: AtomicUsize::new(0),
            idle: Notify::new(),
        })
    }

    pub(crate) fn enter(self: &Arc<Self>) -> Result<Flight, HelperError> {
        if self.started.load(Ordering::SeqCst) {
            return Err(shutting_down());
        }
        self.inflight.fetch_add(1, Ordering::SeqCst);
        if self.started.load(Ordering::SeqCst) {
            self.leave();
            return Err(shutting_down());
        }
        Ok(Flight(Arc::clone(self)))
    }

    pub(crate) fn ensure_open(&self) -> Result<(), HelperError> {
        if self.started.load(Ordering::SeqCst) {
            Err(shutting_down())
        } else {
            Ok(())
        }
    }

    /// `false` when shutdown has already started. A second call is a no-op.
    pub(crate) fn begin(&self) -> bool {
        !self.started.swap(true, Ordering::SeqCst)
    }

    fn leave(&self) {
        if self.inflight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.idle.notify_waiters();
        }
    }

    pub(crate) async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.inflight.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        self.0.leave();
    }
}

fn shutting_down() -> HelperError {
    HelperError::Cancelled("helper is shutting down".into())
}

pub(crate) struct Inhibit {
    bus: Mutex<Option<Connection>>,
    fd: Mutex<Option<zbus::zvariant::OwnedFd>>,
}

impl Inhibit {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bus: Mutex::new(None),
            fd: Mutex::new(None),
        })
    }

    async fn has_bus(&self) -> bool {
        self.bus.lock().await.is_some()
    }

    async fn arm(&self) {
        let Some(bus) = self.bus.lock().await.clone() else {
            return;
        };
        let mut slot = self.fd.lock().await;
        if slot.is_some() {
            return;
        }
        match LoginManagerProxy::new(&bus).await {
            Ok(proxy) => {
                match proxy
                    .inhibit("shutdown", "linux-vault", "Locking vaults", "delay")
                    .await
                {
                    Ok(fd) => *slot = Some(fd),
                    Err(error) => {
                        eprintln!("linux-vault-helper: cannot take a shutdown inhibitor: {error}");
                    }
                }
            }
            Err(error) => {
                eprintln!("linux-vault-helper: cannot take a shutdown inhibitor: {error}");
            }
        }
    }

    async fn release(&self) {
        self.fd.lock().await.take();
    }
}

/// Shared with the helper that serves the bus. `main` calls this on
/// `PrepareForShutdown` and on `SIGTERM`.
#[derive(Clone)]
pub struct ShutdownHandle {
    gate: Arc<Gate>,
    cancel: CancelToken,
    vaults: Arc<linux_vault::Vaults>,
    passphrases: HeldPassphrases,
    inhibit: Arc<Inhibit>,
    /// One run of the sequence at a time. `PrepareForShutdown` and `SIGTERM`
    /// can overlap; the later one waits, then looks at the vaults again.
    run: Arc<Mutex<()>>,
    /// How many vaults this process has started locking from shutdown.
    lock_attempts: Arc<AtomicUsize>,
    workers: Arc<StdMutex<Vec<u32>>>,
}

impl ShutdownHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        gate: Arc<Gate>,
        cancel: CancelToken,
        vaults: Arc<linux_vault::Vaults>,
        passphrases: HeldPassphrases,
        inhibit: Arc<Inhibit>,
        run: Arc<Mutex<()>>,
        lock_attempts: Arc<AtomicUsize>,
        workers: Arc<StdMutex<Vec<u32>>>,
    ) -> Self {
        Self {
            gate,
            cancel,
            vaults,
            passphrases,
            inhibit,
            run,
            lock_attempts,
            workers,
        }
    }

    /// Vaults shutdown has started to lock. A second run does not add to this.
    pub fn lock_attempts(&self) -> usize {
        self.lock_attempts.load(Ordering::SeqCst)
    }

    pub(crate) fn inhibit() -> Arc<Inhibit> {
        Inhibit::new()
    }

    /// The system bus. Tests leave this unset, so they never talk to logind
    /// or send a notification.
    pub async fn bind_bus(&self, bus: Connection) {
        *self.inhibit.bus.lock().await = Some(bus);
        self.arm_if_unlocked().await;
    }

    async fn arm_if_unlocked(&self) {
        let vaults = Arc::clone(&self.vaults);
        let Ok(Ok(listed)) = tokio::task::spawn_blocking(move || vaults.list()).await else {
            return;
        };
        if listed.iter().any(|vault| vault.state == State::Unlocked) {
            self.inhibit.arm().await;
        }
    }

    pub(crate) async fn arm_inhibitor(&self) {
        self.inhibit.arm().await;
    }

    /// Lock what is still open, then release the inhibitor.
    ///
    /// Does not exit the process. `main` returns after `SIGTERM`; a
    /// `PrepareForShutdown` signal keeps serving until that signal arrives.
    /// A second call waits for the first. It then locks only vaults that are
    /// still unlocked, so an already locked vault is left alone and no error
    /// is reported.
    pub async fn shut_down(&self) {
        let _run = self.run.lock().await;
        let first = self.gate.begin();
        if first {
            // The notification is the only step that talks to a bus.
            // A failure is ignored. Everything after this uses the filesystem
            // and the process keyring, because the system bus may be stopping.
            self.notify_locking().await;
            self.cancel.cancel();
            crate::worker::abort_live_workers(&self.workers);
            crate::worker::wait_for_workers(&self.workers, std::time::Duration::from_secs(30));
            self.gate.wait_idle().await;
        }
        self.lock_what_is_open().await;
        self.inhibit.release().await;
    }

    /// `PrepareForShutdown(true)` runs [`Self::shut_down`] and keeps watching.
    /// A later `SIGTERM` is what makes the process exit.
    pub async fn watch_prepare_for_shutdown(&self) -> zbus::Result<()> {
        let Some(bus) = self.inhibit.bus.lock().await.clone() else {
            return Ok(());
        };
        let proxy = match LoginManagerProxy::new(&bus).await {
            Ok(proxy) => proxy,
            Err(error) => {
                eprintln!("linux-vault-helper: logind is not available: {error}");
                return Ok(());
            }
        };
        let mut events = proxy.receive_prepare_for_shutdown().await?;
        while let Some(event) = events.next().await {
            let Ok(args) = event.args() else {
                continue;
            };
            if args.start {
                self.shut_down().await;
            }
        }
        Ok(())
    }

    async fn notify_locking(&self) {
        if !self.inhibit.has_bus().await {
            return;
        }
        let Some(user) = self.notification_user().await else {
            return;
        };
        if !plain_user(&user) {
            return;
        }
        let mut command = tokio::process::Command::new("systemd-run");
        command
            .arg(format!("--machine={user}@"))
            .arg("--user")
            .arg("--pipe")
            .arg("--wait")
            .arg("-q")
            .arg("notify-send")
            .arg("linux-vault")
            .arg("Locking vaults before shutdown…")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return;
        };
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        child.start_kill().ok();
    }

    async fn notification_user(&self) -> Option<String> {
        let vaults = Arc::clone(&self.vaults);
        let listed = tokio::task::spawn_blocking(move || vaults.list())
            .await
            .ok()?
            .ok()?;
        for vault in listed {
            if vault.state != State::Unlocked {
                continue;
            }
            let uid = std::fs::symlink_metadata(&vault.path).ok()?.uid();
            if let Ok(account) = passwd_account(uid) {
                return Some(account.user);
            }
        }
        None
    }

    /// Lock unlocked vaults. This makes no D-Bus call.
    async fn lock_what_is_open(&self) {
        let vaults = Arc::clone(&self.vaults);
        let Ok(Ok(listed)) = tokio::task::spawn_blocking(move || vaults.list()).await else {
            eprintln!("linux-vault-helper: cannot list vaults while shutting down");
            return;
        };
        for vault in listed {
            if vault.state != State::Unlocked {
                continue;
            }
            match self.passphrases.read(vault.uid, &vault.name) {
                Ok(passphrase) => self.lock_held(vault, passphrase).await,
                Err(HelperError::Failed(message)) if key_is_missing(&message) => {
                    self.mark_recovery(vault.uid, &vault.name).await;
                }
                Err(error) => {
                    eprintln!("linux-vault-helper: {error}");
                    self.mark_recovery(vault.uid, &vault.name).await;
                }
            }
        }
    }

    async fn lock_held(&self, vault: linux_vault::Vault, passphrase: crate::Passphrase) {
        self.lock_attempts.fetch_add(1, Ordering::SeqCst);
        let name = vault.name.clone();
        let path = vault.path.clone();
        let Some((uid, gid, home)) = crate::ids_for_path(&path) else {
            eprintln!("linux-vault-helper: cannot see the owner of {name}; it needs recovery");
            self.mark_recovery(vault.uid, &name).await;
            return;
        };
        let vaults = self.vaults.share();
        let passphrases = self.passphrases.clone();
        let live = Arc::clone(&self.workers);
        let locked = tokio::task::spawn_blocking(move || {
            let (stored, _previous) = vaults
                .begin_lock(uid, &name)
                .map_err(|error| HelperError::Failed(format!("locking for {name}: {error}")))?;
            let mut worker = match crate::worker::HomeWorker::spawn(
                uid,
                gid,
                &home,
                vaults.share(),
                live.clone(),
            ) {
                Ok(worker) => worker,
                Err(error) => {
                    reconcile_or_log(
                        &vaults,
                        &passphrases,
                        uid,
                        gid,
                        &home,
                        &stored,
                        &name,
                        &live,
                    );
                    return Err(error);
                }
            };
            if let Err(error) = worker.scan_open_files(&name, &stored) {
                eprintln!("linux-vault-helper: {error}. Locking anyway.");
            }
            if uid != 0 {
                if let Err(error) = open_files::refuse_if_open(&stored, &name, 0) {
                    eprintln!("linux-vault-helper: {error}. Locking anyway.");
                }
            }
            let packed = worker.pack(&stored, passphrase.as_bytes());
            if packed.is_err() {
                reconcile_or_log(
                    &vaults,
                    &passphrases,
                    uid,
                    gid,
                    &home,
                    &stored,
                    &name,
                    &live,
                );
                if let Err(ref error) = packed {
                    if error.to_string().contains("immutable") {
                        eprintln!("linux-vault-helper: locking for {name}: {error}");
                    }
                }
                return packed;
            }
            vaults
                .set_state(uid, &name, State::Locked)
                .map_err(|error| {
                    reconcile_or_log(
                        &vaults,
                        &passphrases,
                        uid,
                        gid,
                        &home,
                        &stored,
                        &name,
                        &live,
                    );
                    HelperError::Failed(format!("locking for {name}: {error}"))
                })?;
            packed
        })
        .await;
        match locked {
            Ok(Ok(())) => {
                if let Err(error) = self.passphrases.forget(vault.uid, &vault.name) {
                    eprintln!("linux-vault-helper: {error}");
                }
            }
            Ok(Err(error)) => {
                eprintln!("linux-vault-helper: cannot lock {}: {error}", vault.name);
            }
            Err(error) => {
                eprintln!("linux-vault-helper: cannot lock {}: {error}", vault.name);
            }
        }
    }

    async fn mark_recovery(&self, uid: u32, name: &str) {
        let vaults = Arc::clone(&self.vaults);
        let name = name.to_string();
        let marked =
            tokio::task::spawn_blocking(move || vaults.mark_needs_recovery(uid, &name)).await;
        match marked {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!("linux-vault-helper: cannot mark a vault for recovery: {error}");
            }
            Err(error) => {
                eprintln!("linux-vault-helper: cannot mark a vault for recovery: {error}");
            }
        }
    }
}

fn key_is_missing(message: &str) -> bool {
    message.contains("KeyDoesNotExist") || message.contains("KeyRevoked")
}

#[allow(clippy::too_many_arguments)]
fn reconcile_or_log(
    vaults: &linux_vault::Vaults,
    keys: &crate::HeldPassphrases,
    uid: u32,
    gid: u32,
    home: &std::path::Path,
    path: &std::path::Path,
    name: &str,
    workers: &std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
) {
    if let Err(error) =
        crate::reconcile_from_disk(vaults, keys, uid, gid, home, path, name, workers)
    {
        eprintln!("linux-vault-helper: reconciling {name} for uid {uid}: {error}");
    }
}

fn plain_user(user: &str) -> bool {
    !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait LoginManager {
    fn inhibit(
        &self,
        what: &str,
        who: &str,
        why: &str,
        mode: &str,
    ) -> zbus::Result<zbus::zvariant::OwnedFd>;

    #[zbus(signal)]
    fn prepare_for_shutdown(&self, start: bool) -> zbus::Result<()>;
}
