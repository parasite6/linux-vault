//! D-Bus helper.
//!
//! Every method reads the caller's kernel credentials and checks polkit.
//! `Create` and `Unlock` take the per-vault lock, ask pinentry, and call the core.
//! `Lock` takes that lock, refuses while a vault file is open, and calls the core
//! with the passphrase from the process keyring. If that key is gone, Lock asks
//! for the passphrase twice and uses it only for that lock. `List` returns this
//! caller's vaults. `Remove` drops the registry entry. `Terminate` deletes the
//! vault after a passphrase prompt.

mod bookmarks;
mod caller;
mod error;
mod keyring;
mod locks;
mod open_files;
mod pinentry;
mod polkit;
mod shutdown;
mod upgrade;
pub use upgrade::replaced_binary_probe;
mod worker;

use std::ffi::{CStr, OsString};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use linux_vault::State;
use linux_vault_dbus::VaultStatus;
use zbus::interface;
use zbus::message::Header;
use zbus::Connection;

use caller::caller_from_header;
use error::HelperError;
use keyring::ProcessKeys;
use polkit::authorize;
use shutdown::Gate;

pub use caller::{caller_from_connection, Caller};

/// Leave only the six capabilities in the helper unit's bounding set.
///
/// Tests call this so a check does not run with the rest of root's set.
/// `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` are among the ones removed.
/// The call applies to this thread. A process-wide limit has to happen before
/// other threads are created.
#[doc(hidden)]
pub fn limit_to_unit_capabilities() {
    const KEEP: &[i32] = &[3, 6, 7, 9, 14, 19];
    const VERSION_3: u32 = 0x2008_0522;
    const SYS_CAPGET: i64 = 125;
    const SYS_CAPSET: i64 = 126;
    const PR_CAPBSET_DROP: i32 = 24;
    const PR_CAP_AMBIENT: i32 = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;
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
    unsafe {
        // An ambient bit outside the new inheritable set makes capset fail
        // and leave the old effective set in place.
        nix::libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        // Bounding-set drops need CAP_SETPCAP, which the final set does not keep.
        for cap in 0..64 {
            if !KEEP.contains(&cap) {
                nix::libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
            }
        }
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut data: [Data; 2] = std::mem::zeroed();
        if nix::libc::syscall(SYS_CAPGET, &mut header, data.as_mut_ptr()) == 0 {
            let low = KEEP
                .iter()
                .filter(|cap| **cap < 32)
                .fold(0u32, |mask, cap| mask | (1u32 << cap));
            data[0].effective &= low;
            data[0].permitted &= low;
            data[0].inheritable &= low;
            data[1] = std::mem::zeroed();
            nix::libc::syscall(SYS_CAPSET, &header, data.as_ptr());
        }
    }
}

/// `PR_SET_DUMPABLE 0`. Call this before any other work in the process.
pub fn disable_core_dumps() -> Result<(), String> {
    let rc = unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}
pub use error::HelperError as Error;
pub use keyring::create_process_keyring;
pub use keyring::passphrase_threads;
pub use locks::VaultLocks;
pub use pinentry::{CancelToken, Passphrase, Pinentry, PinentryError, Purpose};
pub use polkit::{bus_name_subject, Authorizer};
pub use shutdown::{stop_log, ShutdownHandle};

/// `--worker`. Dumpable is cleared by the caller before this runs.
pub fn worker_main() -> i32 {
    worker::run()
}

/// How to start pinentry.
pub enum Prompt {
    /// `pinentry-qt` in the caller's user manager.
    UserManager,
    /// A program and its arguments. Tests pass a fake pinentry here.
    Program(Vec<OsString>),
}

/// The account a vault operation runs for.
#[derive(Clone)]
pub struct Account {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

pub enum Accounts {
    /// Look the caller up in the password database.
    Passwd,
    /// Tests supply the home directory. The bus caller is still authorized.
    Fixed(Account),
}

/// System service. `authorizer` is [`Authorizer::Polkit`] in the installed binary.
pub struct Helper {
    authorizer: Authorizer,
    vaults: Arc<linux_vault::Vaults>,
    locks: VaultLocks,
    /// Passphrases for unlocked vaults, in the process keyring.
    /// Nothing on the bus can read this.
    passphrases: HeldPassphrases,
    prompt: Prompt,
    accounts: Accounts,
    gate: Arc<Gate>,
    /// Cancelling this stops every open pinentry.
    cancel: CancelToken,
    shutdown: ShutdownHandle,
    workers: Arc<Mutex<Vec<u32>>>,
    /// Test seam. Runs after the ownership check and before a registry write.
    before_mutation: std::sync::Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
    /// Set at startup when `registry.json` could not be read. Every method
    /// returns this text until the process is restarted.
    registry_fault: Arc<Mutex<Option<String>>>,
}

impl Helper {
    /// Installed service. Registry at `/var/lib/linux-vault`. Reconciles once.
    pub fn system(authorizer: Authorizer) -> Result<Self, HelperError> {
        open_files::warn_if_ptrace_missing();
        let vaults = linux_vault::Vaults::open("/var/lib/linux-vault", "/home")
            .map_err(|error| failed("opening the registry", "/var/lib/linux-vault", error))?;
        Self::from_parts(authorizer, vaults, Prompt::UserManager, Accounts::Passwd)
    }

    /// `vaults` is reconciled before it is used.
    pub fn new(
        authorizer: Authorizer,
        vaults: linux_vault::Vaults,
        prompt: Prompt,
        account: Account,
    ) -> Result<Self, HelperError> {
        Self::from_parts(authorizer, vaults, prompt, Accounts::Fixed(account))
    }

    /// Same as [`Self::system`], but the registry and pinentry are supplied.
    /// The caller's account comes from the password database.
    pub fn for_passwd(
        authorizer: Authorizer,
        vaults: linux_vault::Vaults,
        prompt: Prompt,
    ) -> Result<Self, HelperError> {
        Self::from_parts(authorizer, vaults, prompt, Accounts::Passwd)
    }

    fn from_parts(
        authorizer: Authorizer,
        vaults: linux_vault::Vaults,
        prompt: Prompt,
        accounts: Accounts,
    ) -> Result<Self, HelperError> {
        let vaults = Arc::new(vaults);
        let gate = Gate::new();
        let cancel = CancelToken::new();
        let inhibit = ShutdownHandle::inhibit();
        let passphrases = HeldPassphrases::new()?;
        let workers = Arc::new(Mutex::new(Vec::new()));
        let registry_fault = Arc::new(Mutex::new(None));
        let shutdown = ShutdownHandle::new(
            Arc::clone(&gate),
            cancel.clone(),
            Arc::clone(&vaults),
            passphrases.clone(),
            Arc::clone(&inhibit),
            Arc::new(tokio::sync::Mutex::new(())),
            Arc::new(AtomicUsize::new(0)),
            Arc::clone(&workers),
            Arc::clone(&registry_fault),
        );
        let helper = Self {
            authorizer,
            vaults,
            locks: VaultLocks::new(),
            passphrases,
            prompt,
            accounts,
            gate,
            cancel,
            shutdown,
            workers,
            before_mutation: std::sync::Mutex::new(None),
            registry_fault: Arc::clone(&registry_fault),
        };
        helper.reconcile_with_workers()?;
        Ok(helper)
    }

    /// Run `hook` after the ownership check and before `begin_lock`,
    /// `begin_unlock`, or `unregister`. Tests use this to drop the record
    /// in that gap. The installed service never sets it.
    pub fn set_before_mutation(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .before_mutation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(std::sync::Arc::new(hook));
    }

    fn before_mutation(&self) {
        let hook = self
            .before_mutation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn registry_allows(&self) -> Result<(), HelperError> {
        let message = self
            .registry_fault
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        match message {
            Some(message) => Err(HelperError::RegistryBroken(message)),
            None => Ok(()),
        }
    }

    /// One worker per user. The worker checks filenames; this process writes
    /// the registry and sets the immutable flag on archives that remain.
    fn reconcile_with_workers(&self) -> Result<(), HelperError> {
        let listed = match self.vaults.list() {
            Ok(listed) => listed,
            Err(linux_vault::Error::RegistryDamaged(message)) => {
                eprintln!("<3>linux-vault-helper: {message}");
                *self
                    .registry_fault
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message);
                return Ok(());
            }
            Err(error) => return Err(vault_error("reconciling", "registry", error)),
        };
        warn_about_nested(&listed);
        for vault in listed {
            let account = match self.owner_for(&vault.path) {
                Ok(account) => account,
                Err(error) => {
                    eprintln!("<3>linux-vault-helper: reconciling {}: {error}", vault.name);
                    let _ = self.vaults.mark_needs_recovery(vault.uid, &vault.name);
                    continue;
                }
            };
            if let Err(error) = reconcile_from_disk(
                &self.vaults,
                &self.passphrases,
                vault.uid,
                account.gid,
                &account.home,
                &vault.path,
                &vault.name,
                &self.workers,
            ) {
                eprintln!("<3>linux-vault-helper: reconciling {}: {error}", vault.name);
                let _ = self.vaults.mark_needs_recovery(vault.uid, &vault.name);
            }
        }
        Ok(())
    }

    fn owner_for(&self, path: &Path) -> Result<Account, HelperError> {
        if let Accounts::Fixed(account) = &self.accounts {
            if path == account.home || path.starts_with(&account.home) {
                return Ok(account.clone());
            }
        }
        if let Some(account) = passwd_for_path(path) {
            return Ok(account);
        }
        let meta = std::fs::metadata(path).map_err(|error| {
            HelperError::Failed(format!(
                "cannot see the owner of {}: {error}",
                path.display()
            ))
        })?;
        Ok(Account {
            user: "owner".into(),
            uid: meta.uid(),
            gid: meta.gid(),
            home: path.parent().unwrap_or(path).to_path_buf(),
        })
    }

    /// The handle `main` uses for `PrepareForShutdown` and `SIGTERM`.
    /// It shares the gate, the prompts, the vaults, and the held keys.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    /// Whether this process is holding a passphrase for `name`. The bytes stay here.
    pub fn held_passphrases(&self) -> HeldPassphrases {
        self.passphrases.clone()
    }

    async fn gate(
        &self,
        connection: &Connection,
        header: &Header<'_>,
    ) -> Result<Caller, HelperError> {
        let caller = caller_from_header(connection, header).await?;
        authorize(self.authorizer, connection, &caller).await?;
        Ok(caller)
    }

    fn account_of(&self, caller: &Caller) -> Result<Account, HelperError> {
        match &self.accounts {
            Accounts::Fixed(account) => Ok(account.clone()),
            Accounts::Passwd => passwd_account(caller.uid),
        }
    }

    fn pinentry_for(&self, account: &Account) -> Result<Pinentry, HelperError> {
        match &self.prompt {
            Prompt::Program(argv) => Ok(Pinentry::argv(argv.iter().map(OsString::as_os_str))),
            Prompt::UserManager => Pinentry::systemd_run(&account.user, account.uid, account.gid)
                .map_err(|error| named_pin("starting pinentry", &account.user, error)),
        }
    }

    fn vaults_for(&self, _account: &Account) -> Result<linux_vault::Vaults, HelperError> {
        // Registry only. Do not canonicalize the home: it may be mode 700.
        Ok(self.vaults.share())
    }

    fn keep(&self, uid: u32, name: &str, passphrase: Passphrase) -> Result<(), HelperError> {
        self.passphrases.insert(uid, name, passphrase)
    }

    async fn owned_vault(
        &self,
        account: &Account,
        name: &str,
    ) -> Result<linux_vault::Vault, HelperError> {
        let vaults = self.vaults_for(account)?;
        let uid = account.uid;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        let vault = tokio::task::spawn_blocking(move || vaults.get_for(uid, &name_owned))
            .await
            .map_err(|error| failed("reading the registry", &vault_name, error))?
            .map_err(|error| vault_error("reading the registry", name, error))?;
        self.confirm_owner(account, &vault.path).await?;
        Ok(vault)
    }

    /// The path must sit in this home, and the worker, running as the caller,
    /// must be able to stat the folder or the archive and see this uid.
    /// Anything else, including a stat that fails, is not found.
    async fn confirm_owner(&self, account: &Account, path: &Path) -> Result<(), HelperError> {
        if path != account.home && !path.starts_with(&account.home) {
            return Err(vault_not_found());
        }
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let path = path.to_path_buf();
        let shown = path.display().to_string();
        let vaults = self.vaults.share();
        let live = Arc::clone(&self.workers);
        let owner = tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live)?;
            worker.owner_of(&path)
        })
        .await
        .map_err(|error| failed("reading the owner", &shown, error))?;
        match owner {
            Ok(owner) if owner == uid => Ok(()),
            Ok(_) => Err(vault_not_found()),
            Err(HelperError::Failed(message)) if message.contains("cannot see the owner") => {
                Err(vault_not_found())
            }
            Err(error) => Err(error),
        }
    }

    /// The worker scans the owner's processes. The helper always scans root's,
    /// because the worker has no `CAP_SYS_PTRACE`.
    async fn refuse_if_empty(
        &self,
        account: &Account,
        path: &Path,
        name: &str,
    ) -> Result<(), HelperError> {
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let vaults = self.vaults.share();
        let check_path = path.to_path_buf();
        let live = Arc::clone(&self.workers);
        let present = tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live)?;
            worker.contains_regular_file(&check_path)
        })
        .await
        .map_err(|error| failed("locking", name, error))??;
        if present {
            Ok(())
        } else {
            Err(HelperError::Empty(format!(
                "{name} is empty; nothing to lock."
            )))
        }
    }

    async fn refuse_stray_archive(
        &self,
        account: &Account,
        path: &Path,
        name: &str,
        verb: &str,
    ) -> Result<(), HelperError> {
        let facts = self.inspect_with(account, path, name).await?;
        if facts.archive {
            let archive = path.with_file_name(format!("{name}.7z"));
            return Err(HelperError::Failed(format!(
                "Cannot {verb} {name}: {} already exists and is not this vault's archive.",
                archive.display()
            )));
        }
        Ok(())
    }

    async fn inspect_with(
        &self,
        account: &Account,
        path: &Path,
        name: &str,
    ) -> Result<linux_vault::FilenameFacts, HelperError> {
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let vaults = self.vaults.share();
        let check = path.to_path_buf();
        let live = Arc::clone(&self.workers);
        tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live)?;
            worker.inspect(&check)
        })
        .await
        .map_err(|error| failed("locking", name, error))?
    }

    async fn files_are_open(
        &self,
        uid: u32,
        gid: u32,
        home: &Path,
        path: &Path,
        name: &str,
    ) -> Result<(), HelperError> {
        let vaults = self.vaults.share();
        let home = home.to_path_buf();
        let owner_path = path.to_path_buf();
        let owner_name = name.to_string();
        let live = Arc::clone(&self.workers);
        tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live.clone())?;
            worker.scan_open_files(&owner_name, &owner_path)
        })
        .await
        .map_err(|error| failed("checking open files", name, error))??;
        // The worker has no capabilities, so it cannot read a non-dumpable
        // root process. The helper still has CAP_SYS_PTRACE and always scans
        // root, including when the vault owner is root.
        let root_path = path.to_path_buf();
        let root_name = name.to_string();
        tokio::task::spawn_blocking(move || open_files::refuse_if_open(&root_path, &root_name, 0))
            .await
            .map_err(|error| failed("checking open files", name, error))??;
        Ok(())
    }
}

/// Names of vaults whose passphrase this process is holding.
///
/// Cloning this shares the process keyring entries. It cannot return the
/// passphrase bytes. [`Self::read`] is for Lock, which then [`Self::forget`]s
/// the key.
#[derive(Clone)]
pub struct HeldPassphrases {
    keys: ProcessKeys,
}

impl HeldPassphrases {
    fn new() -> Result<Self, HelperError> {
        Ok(Self {
            keys: ProcessKeys::new()?,
        })
    }

    pub fn contains(&self, uid: u32, name: &str) -> bool {
        self.keys.contains(uid, name)
    }

    fn insert(&self, uid: u32, name: &str, passphrase: Passphrase) -> Result<(), HelperError> {
        self.keys.insert(uid, name, passphrase)
    }

    /// The passphrase Lock feeds to `7z`. Nothing on the bus reads this.
    pub(crate) fn read(&self, uid: u32, name: &str) -> Result<Passphrase, HelperError> {
        self.keys.read(uid, name)
    }

    /// Drop the key after a successful lock.
    pub fn forget(&self, uid: u32, name: &str) -> Result<(), HelperError> {
        self.keys.forget(uid, name)
    }
}

#[interface(name = "org.linuxvault.Helper")]
impl Helper {
    async fn create(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        path: &str,
    ) -> Result<(), HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        self.registry_allows()?;
        let account = self.account_of(&caller)?;
        let name = folder_name(path)?;
        let _guard = self.locks.acquire(account.uid, &name).await;
        self.gate.ensure_open()?;
        let pinentry = self.pinentry_for(&account)?;
        let prompt = self.cancel.child();
        let passphrase = pinentry
            .ask(Purpose::Create, &name, &prompt)
            .await
            .map_err(|error| named_pin("asking for the passphrase", &name, error))?;
        let vaults = self.vaults.share();
        let home = account.home.clone();
        let uid = account.uid;
        let gid = account.gid;
        let path = path.to_string();
        let reported = path.clone();
        let live = Arc::clone(&self.workers);
        let created = tokio::task::spawn_blocking(move || {
            let mut worker =
                worker::HomeWorker::spawn(uid, gid, &home, vaults.share(), live.clone())?;
            let canonical = worker.resolve(Path::new(&path))?;
            if canonical != home && !canonical.starts_with(&home) {
                return Err(failed("creating", &path, "vault path is outside the home"));
            }
            let facts = worker.inspect(&canonical)?;
            if facts.archive {
                let archive = canonical.with_extension("7z");
                return Err(HelperError::Failed(format!(
                    "Cannot create {}: {} already exists and is not this vault's archive.",
                    canonical
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("vault"),
                    archive.display()
                )));
            }
            let created =
                vaults
                    .register_unlocked(uid, &canonical)
                    .map_err(|error| match &error {
                        linux_vault::Error::Nested { .. } => HelperError::Nested(error.to_string()),
                        _ => failed("creating", &canonical.display().to_string(), error),
                    })?;
            keep_bookmark(&mut worker, &canonical, &created.name);
            Ok(created)
        })
        .await
        .map_err(|error| failed("creating", &reported, error))??;
        self.keep(account.uid, &created.name, passphrase)?;
        self.shutdown_handle().arm_inhibitor().await;
        Ok(())
    }

    async fn lock(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        name: &str,
    ) -> Result<(), HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        self.registry_allows()?;
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "locking",
                name,
                "vault name is not a single path component",
            ));
        }
        self.owned_vault(&account, name).await?;
        let _vault_lock = self.locks.acquire(account.uid, name).await;
        self.gate.ensure_open()?;
        let vault = self.owned_vault(&account, name).await?;
        match vault.state {
            State::Unlocked | State::NeedsRecovery => {}
            state => {
                return Err(failed("locking", name, format!("that is {state}")));
            }
        }
        let path = vault.path.clone();
        self.refuse_if_empty(&account, &path, name).await?;
        self.refuse_stray_archive(&account, &path, name, "lock")
            .await?;
        // A missing key is needs_recovery even when the lock is then refused
        // because a file is open. The refusal must not leave the vault looking
        // unlocked after the passphrase is already gone.
        let held = self.passphrases.read(account.uid, name);
        if matches!(&held, Err(HelperError::Failed(message)) if passphrase_is_missing(message)) {
            self.vaults
                .mark_needs_recovery(account.uid, name)
                .map_err(|error| vault_error("locking", name, error))?;
        }
        self.files_are_open(account.uid, account.gid, &account.home, &path, name)
            .await?;
        let (passphrase, recovery) = match held {
            Ok(passphrase) => (passphrase, false),
            Err(HelperError::Failed(message)) if passphrase_is_missing(&message) => {
                let pinentry = self.pinentry_for(&account)?;
                let prompt = self.cancel.child();
                let typed = pinentry
                    .ask(Purpose::Recovery, name, &prompt)
                    .await
                    .map_err(|error| named_pin("asking for the passphrase", name, error))?;
                (typed, true)
            }
            Err(error) => return Err(error),
        };
        self.refuse_stray_archive(&account, &path, name, "lock")
            .await?;
        self.before_mutation();
        let (_stored_path, _previous) = self
            .vaults
            .begin_lock(account.uid, name)
            .map_err(|error| vault_error("locking", name, error))?;
        let mut rollback = DiskReconcile {
            armed: true,
            uid: account.uid,
            gid: account.gid,
            home: account.home.clone(),
            path: path.clone(),
            name: name.to_string(),
            vaults: self.vaults.share(),
            keys: self.passphrases.clone(),
            workers: Arc::clone(&self.workers),
        };
        let supplied = !passphrase.as_bytes().is_empty();
        let path_kind = if recovery { "recovery" } else { "held" };
        if !supplied {
            eprintln!(
                "<3>linux-vault-helper: encryption check failed for {name}: path={path_kind}, passphrase_supplied=no"
            );
            return Err(failed("locking", name, "passphrase is missing"));
        }
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let vaults = self.vaults.share();
        let pack_path = path.clone();
        let bookmark_name = name.to_string();
        let live = Arc::clone(&self.workers);
        let record_uid = account.uid;
        let record_name = name.to_string();
        let packed = tokio::task::spawn_blocking(move || {
            let mut worker =
                worker::HomeWorker::spawn(uid, gid, &home, vaults.share(), live.clone())?;
            let identity = worker.pack(&pack_path, passphrase.as_bytes())?;
            vaults
                .record_archive(record_uid, &record_name, identity)
                .map_err(|error| failed("locking", &record_name, error))?;
            worker.delete_folder(&pack_path)?;
            if let Err(error) = worker.seal(&pack_path) {
                eprintln!(
                    "<3>linux-vault-helper: sealing {record_name} for uid {record_uid}: {error}"
                );
                let _ = vaults.set_immutable(record_uid, &record_name, false);
            } else {
                let _ = vaults.set_immutable(record_uid, &record_name, true);
            }
            keep_bookmark(&mut worker, &pack_path, &bookmark_name);
            Ok(())
        })
        .await
        .map_err(|error| failed("locking", name, error))?;
        if let Err(error) = packed {
            let error = plain_archive_error(error);
            if error.to_string().contains("not encrypted") {
                eprintln!(
                    "<3>linux-vault-helper: encryption check failed for {name}: path={path_kind}, passphrase_supplied={supplied}"
                );
            }
            if error.to_string().contains("immutable") {
                eprintln!("linux-vault-helper: locking for {name}: {error}");
            }
            return Err(error);
        }
        self.vaults
            .set_state(account.uid, name, State::Locked)
            .map_err(|error| vault_error("locking", name, error))?;
        rollback.armed = false;
        self.passphrases.forget(account.uid, name)?;
        Ok(())
    }

    async fn unlock(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        name: &str,
    ) -> Result<(), HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        self.registry_allows()?;
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "unlocking",
                name,
                "vault name is not a single path component",
            ));
        }
        self.owned_vault(&account, name).await?;
        let _vault_lock = self.locks.acquire(account.uid, name).await;
        self.gate.ensure_open()?;
        let vault = self.owned_vault(&account, name).await?;
        if vault.state != State::Locked {
            return Err(failed(
                "unlocking",
                name,
                format!("that is {}", vault.state),
            ));
        }
        let facts = self.inspect_with(&account, &vault.path, name).await?;
        if facts.occupied {
            return Err(HelperError::Failed(format!(
                "Cannot unlock {name}: {} already exists and is not empty.",
                vault.path.display()
            )));
        }
        let pinentry = self.pinentry_for(&account)?;
        let prompt = self.cancel.child();
        let passphrase = pinentry
            .ask(Purpose::Unlock, name, &prompt)
            .await
            .map_err(|error| named_pin("asking for the passphrase", name, error))?;
        self.before_mutation();
        let path = self
            .vaults
            .begin_unlock(account.uid, name)
            .map_err(|error| vault_error("unlocking", name, error))?;
        let mut rollback = DiskReconcile {
            armed: true,
            uid: account.uid,
            gid: account.gid,
            home: account.home.clone(),
            path: path.clone(),
            name: name.to_string(),
            vaults: self.vaults.share(),
            keys: self.passphrases.clone(),
            workers: Arc::clone(&self.workers),
        };
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let vaults = self.vaults.share();
        let bytes = zeroize::Zeroizing::new(passphrase.as_bytes().to_vec());
        let bookmark_name = name.to_string();
        let live = Arc::clone(&self.workers);
        tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live.clone())?;
            worker.unpack(&path, &bytes)?;
            keep_bookmark(&mut worker, &path, &bookmark_name);
            Ok(())
        })
        .await
        .map_err(|error| failed("unlocking", name, error))?
        .map_err(plain_archive_error)?;
        self.vaults
            .set_state(account.uid, name, State::Unlocked)
            .map_err(|error| vault_error("unlocking", name, error))?;
        rollback.armed = false;
        self.keep(account.uid, name, passphrase)?;
        self.shutdown_handle().arm_inhibitor().await;
        Ok(())
    }

    async fn list(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<VaultStatus>, HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        self.registry_allows()?;
        self.gate.ensure_open()?;
        let account = self.account_of(&caller)?;
        let vaults = self.vaults_for(&account)?;
        let listed = tokio::task::spawn_blocking(move || vaults.list())
            .await
            .map_err(|error| failed("listing", "registry", error))?
            .map_err(|error| vault_error("listing", "registry", error))?;
        let mine: Vec<_> = listed
            .into_iter()
            .filter(|vault| {
                vault.uid == account.uid
                    && (vault.path == account.home || vault.path.starts_with(&account.home))
            })
            .collect();
        if mine.is_empty() {
            return Ok(Vec::new());
        }
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let vaults = self.vaults.share();
        let live = Arc::clone(&self.workers);
        tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live)?;
            let mut kept = Vec::new();
            for vault in mine {
                match worker.owner_of(&vault.path) {
                    Ok(owner) if owner == uid => {
                        let state = listed_state(&vault);
                        kept.push(VaultStatus {
                            name: vault.name,
                            path: vault.path.display().to_string(),
                            state,
                        })
                    }
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!("<3>linux-vault-helper: listing {}: {error}", vault.name);
                    }
                }
            }
            Ok(kept)
        })
        .await
        .map_err(|error| failed("listing", "registry", error))?
    }

    async fn remove(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        name: &str,
    ) -> Result<(), HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        self.registry_allows()?;
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "removing",
                name,
                "vault name is not a single path component",
            ));
        }
        self.owned_vault(&account, name).await?;
        let _guard = self.locks.acquire(account.uid, name).await;
        self.gate.ensure_open()?;
        let vault = self.owned_vault(&account, name).await?;
        if matches!(vault.state, State::Locking | State::Unlocking) {
            return Err(failed("removing", name, format!("that is {}", vault.state)));
        }
        if vault.state == State::Locked {
            let pinentry = self.pinentry_for(&account)?;
            let prompt = self.cancel.child();
            let passphrase = pinentry
                .ask(Purpose::Unlock, name, &prompt)
                .await
                .map_err(|error| named_pin("asking for the passphrase", name, error))?;
            self.before_mutation();
            let path = self
                .vaults
                .begin_unlock(account.uid, name)
                .map_err(|error| vault_error("removing", name, error))?;
            let mut rollback = DiskReconcile {
                armed: true,
                uid: account.uid,
                gid: account.gid,
                home: account.home.clone(),
                path: path.clone(),
                name: name.to_string(),
                vaults: self.vaults.share(),
                keys: self.passphrases.clone(),
                workers: Arc::clone(&self.workers),
            };
            let uid = account.uid;
            let gid = account.gid;
            let home = account.home.clone();
            let vaults = self.vaults.share();
            let live = Arc::clone(&self.workers);
            tokio::task::spawn_blocking(move || {
                let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, live.clone())?;
                worker.unpack(&path, passphrase.as_bytes())
            })
            .await
            .map_err(|error| failed("removing", name, error))?
            .map_err(plain_archive_error)?;
            self.vaults
                .set_state(account.uid, name, State::Unlocked)
                .map_err(|error| vault_error("removing", name, error))?;
            rollback.armed = false;
        }
        self.before_mutation();
        let vaults = self.vaults_for(&account)?;
        let uid = account.uid;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        tokio::task::spawn_blocking(move || vaults.unregister(uid, &name_owned))
            .await
            .map_err(|error| failed("removing", &vault_name, error))?
            .map_err(|error| vault_error("removing", name, error))?;
        self.passphrases.forget(account.uid, name)?;
        Ok(())
    }

    async fn terminate(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        name: &str,
    ) -> Result<(), HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        self.registry_allows()?;
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "terminating",
                name,
                "vault name is not a single path component",
            ));
        }
        self.owned_vault(&account, name).await?;
        let _guard = self.locks.acquire(account.uid, name).await;
        self.gate.ensure_open()?;
        let vault = self.owned_vault(&account, name).await?;
        if matches!(vault.state, State::Locking | State::Unlocking) {
            return Err(failed(
                "terminating",
                name,
                format!("that is {}", vault.state),
            ));
        }
        if vault.state == State::NeedsRecovery {
            return Err(failed(
                "terminating",
                name,
                "needs recovery; lock it first, then terminate",
            ));
        }
        let pinentry = self.pinentry_for(&account)?;
        let prompt = self.cancel.child();
        let typed = pinentry
            .ask(Purpose::Terminate, name, &prompt)
            .await
            .map_err(|error| named_pin("asking for the passphrase", name, error))?;
        let path = vault.path.clone();
        let live = Arc::clone(&self.workers);
        match vault.state {
            State::Locked => {
                let uid = account.uid;
                let gid = account.gid;
                let home = account.home.clone();
                let vaults = self.vaults.share();
                let path = path.clone();
                let workers = live.clone();
                tokio::task::spawn_blocking(move || {
                    let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, workers)?;
                    worker.delete_archive(&path, typed.as_bytes())
                })
                .await
                .map_err(|error| failed("terminating", name, error))?
                .map_err(plain_archive_error)?;
            }
            State::Unlocked => {
                let held = match self.passphrases.read(account.uid, name) {
                    Ok(held) => held,
                    Err(HelperError::Failed(message)) if passphrase_is_missing(&message) => {
                        return Err(failed("terminating", name, "the passphrase is not held"));
                    }
                    Err(error) => return Err(error),
                };
                if !constant_time_eq(typed.as_bytes(), held.as_bytes()) {
                    return Err(HelperError::WrongPassphrase("wrong passphrase".into()));
                }
                let uid = account.uid;
                let gid = account.gid;
                let home = account.home.clone();
                let vaults = self.vaults.share();
                let path = path.clone();
                let workers = live.clone();
                tokio::task::spawn_blocking(move || {
                    let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, workers)?;
                    worker.delete_folder(&path)
                })
                .await
                .map_err(|error| failed("terminating", name, error))??;
            }
            State::NeedsRecovery => unreachable!("refused before the prompt"),
            State::Locking | State::Unlocking => unreachable!("rejected before the prompt"),
        }
        {
            let uid = account.uid;
            let gid = account.gid;
            let home = account.home.clone();
            let vaults = self.vaults.share();
            let path = path.clone();
            let bookmark_name = name.to_string();
            let workers = live.clone();
            tokio::task::spawn_blocking(move || {
                let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults, workers)?;
                drop_bookmark(&mut worker, &path, &bookmark_name);
                Ok::<(), HelperError>(())
            })
            .await
            .map_err(|error| failed("terminating", name, error))??;
        }
        self.before_mutation();
        let vaults = self.vaults_for(&account)?;
        let uid = account.uid;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        tokio::task::spawn_blocking(move || vaults.unregister(uid, &name_owned))
            .await
            .map_err(|error| failed("terminating", &vault_name, error))?
            .map_err(|error| vault_error("terminating", name, error))?;
        self.passphrases.forget(account.uid, name)?;
        Ok(())
    }
}

struct DiskReconcile {
    armed: bool,
    uid: u32,
    gid: u32,
    home: PathBuf,
    path: PathBuf,
    name: String,
    vaults: linux_vault::Vaults,
    keys: HeldPassphrases,
    workers: Arc<Mutex<Vec<u32>>>,
}

impl Drop for DiskReconcile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = reconcile_from_disk(
            &self.vaults,
            &self.keys,
            self.uid,
            self.gid,
            &self.home,
            &self.path,
            &self.name,
            &self.workers,
        ) {
            eprintln!(
                "linux-vault-helper: reconciling {} for uid {}: {error}",
                self.name, self.uid
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_from_disk(
    vaults: &linux_vault::Vaults,
    keys: &HeldPassphrases,
    uid: u32,
    gid: u32,
    home: &Path,
    path: &Path,
    name: &str,
    workers: &Arc<Mutex<Vec<u32>>>,
) -> Result<(), HelperError> {
    let mut worker =
        worker::HomeWorker::spawn(uid, gid, home, vaults.share(), Arc::clone(workers))?;
    let facts = worker.inspect(path)?;
    if !facts.folder && !facts.archive {
        vaults
            .unregister(uid, name)
            .map_err(|error| vault_error("reconciling", name, error))?;
        drop_bookmark(&mut worker, path, name);
        return Ok(());
    }
    let recorded = vaults.archive_identity(uid, name).ok().flatten();
    let proven = facts
        .identity
        .as_ref()
        .is_some_and(|live| recorded.as_ref() == Some(live));
    if facts.folder && facts.archive && !proven {
        eprintln!(
            "<3>linux-vault-helper: {name} and its archive both exist and the archive is not this vault's; deleted nothing"
        );
        vaults
            .set_state(uid, name, State::NeedsRecovery)
            .map_err(|error| vault_error("reconciling", name, error))?;
        return Ok(());
    }
    if facts.folder && facts.archive && proven {
        worker.delete_folder(path)?;
    }
    if facts.archive {
        if let Some(identity) = facts.identity.clone() {
            let _ = vaults.record_archive(uid, name, identity);
        }
        vaults
            .set_state(uid, name, State::Locked)
            .map_err(|error| vault_error("reconciling", name, error))?;
        if let Err(error) = worker.seal(path) {
            eprintln!("<3>linux-vault-helper: sealing {name} for uid {uid}: {error}");
            let _ = vaults.set_immutable(uid, name, false);
        } else {
            let _ = vaults.set_immutable(uid, name, true);
        }
        return Ok(());
    }
    let state = if keys.contains(uid, name) {
        State::Unlocked
    } else {
        State::NeedsRecovery
    };
    vaults
        .set_state(uid, name, state)
        .map_err(|error| vault_error("reconciling", name, error))
}

fn keep_bookmark(worker: &mut worker::HomeWorker, path: &Path, name: &str) {
    if let Err(error) = worker.add_bookmark(path, name) {
        eprintln!("linux-vault-helper: cannot write the bookmark for {name}: {error}");
    }
}

fn drop_bookmark(worker: &mut worker::HomeWorker, path: &Path, name: &str) {
    if let Err(error) = worker.remove_bookmark(path) {
        eprintln!("linux-vault-helper: cannot write the bookmark for {name}: {error}");
    }
}

fn failed(step: &str, target: &str, error: impl std::fmt::Display) -> HelperError {
    HelperError::Failed(format!("{step} for {target}: {error}"))
}

/// Missing and owned by someone else are the same error, with the same text.
pub(crate) fn vault_not_found() -> HelperError {
    HelperError::NotFound("vault not found".into())
}

/// 7z's own text stays out of the error a caller can see. The full text is
/// logged at debug priority for the journal. A `<7>` prefix is syslog debug.
pub(crate) fn plain_archive_error(error: HelperError) -> HelperError {
    let HelperError::Failed(message) = &error else {
        return error;
    };
    // Classify 7z's own text, not the vault path and not our "7z failed" wrapper.
    // A killed 7z prints nothing; that is not an unreadable archive.
    let lower = seven_zip_output(message).to_ascii_lowercase();
    let plain = if lower.contains("wrong password") || lower.contains("wrong passphrase") {
        HelperError::WrongPassphrase("wrong passphrase".into())
    } else if lower.contains("no space left")
        || lower.contains("not enough space")
        || lower.contains("not enough disk space")
        || lower.contains("disk full")
        || lower.contains("os error 28")
    {
        HelperError::NoSpace("not enough disk space".into())
    } else if lower.contains("data error")
        || lower.contains("crc failed")
        || lower.contains("headers error")
        || lower.contains("is damaged")
        || lower.contains("can not open the file as archive")
    {
        HelperError::Failed("the archive is damaged".into())
    } else if !lower.is_empty() && (lower.contains("cannot open") || lower.contains("can not open"))
    {
        HelperError::Failed("the archive could not be read".into())
    } else {
        journal_debug(message);
        return error;
    };
    // Always written. systemd stores a `<7>` line at debug priority, with no
    // RUST_LOG check. `journalctl -u linux-vault-helper -p debug` shows it.
    journal_debug(message);
    plain
}

/// Text 7z itself wrote. Our wrapper is `7z failed (status …): ` and is not
/// part of that text. An empty result means 7z was stopped before it spoke.
fn seven_zip_output(message: &str) -> &str {
    let text = seven_zip_text(message);
    let Some(wrapped) = text.find("7z failed (") else {
        return text;
    };
    text[wrapped..]
        .split_once("): ")
        .map(|(_, output)| output)
        .unwrap_or("")
}

/// The helper prefixes worker failures with `step for path: `. The path is
/// not part of 7z's output.
fn seven_zip_text(message: &str) -> &str {
    const PREFIXES: &[&str] = &[
        "locking for ",
        "unlocking for ",
        "deleting the archive for ",
        "deleting the folder for ",
    ];
    for prefix in PREFIXES {
        if let Some(rest) = message.strip_prefix(prefix) {
            if let Some((_, detail)) = rest.split_once(": ") {
                return detail;
            }
        }
    }
    message
}

fn journal_debug(text: &str) {
    for line in debug_lines(text) {
        eprintln!("{line}");
    }
}

/// Every line carries the prefix. A later line without it is stored at the
/// default priority and shows up in an ordinary journal read.
fn debug_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .map(|line| format!("<7>linux-vault-helper: {line}"))
        .collect()
}

fn warn_about_nested(vaults: &[linux_vault::Vault]) {
    for (index, left) in vaults.iter().enumerate() {
        for right in vaults.iter().skip(index + 1) {
            if left.uid == right.uid && linux_vault::vaults_are_nested(&left.path, &right.path) {
                eprintln!(
                    "<4>linux-vault-helper: {} and {} are nested; leaving both as they are",
                    left.name, right.name
                );
            }
        }
    }
}

fn vault_error(step: &str, target: &str, error: linux_vault::Error) -> HelperError {
    match &error {
        linux_vault::Error::NotFound => vault_not_found(),
        linux_vault::Error::RegistryDamaged(message) => {
            HelperError::RegistryBroken(message.clone())
        }
        linux_vault::Error::Nested { .. } => HelperError::Nested(error.to_string()),
        _ => failed(step, target, error),
    }
}

fn pin_error(error: PinentryError) -> HelperError {
    match error {
        PinentryError::Cancelled => HelperError::Cancelled(error.to_string()),
        PinentryError::NotLoggedIn { .. } => HelperError::NotLoggedIn(error.to_string()),
        other => HelperError::Failed(other.to_string()),
    }
}

fn named_pin(step: &str, target: &str, error: PinentryError) -> HelperError {
    match pin_error(error) {
        HelperError::Failed(message) => failed(step, target, message),
        other => other,
    }
}

fn folder_name(path: &str) -> Result<String, HelperError> {
    if path.contains('\0') {
        return Err(HelperError::Failed("path contains NUL".into()));
    }
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| plain_vault_name(name))
        .map(str::to_string)
        .ok_or_else(|| HelperError::Failed("vault path has no folder name".into()))
}

fn listed_state(vault: &linux_vault::Vault) -> String {
    if vault.state == State::Locked && !vault.immutable {
        "locked (not immutable)".to_string()
    } else {
        state_wire(vault.state).to_string()
    }
}

fn state_wire(state: State) -> &'static str {
    match state {
        State::Unlocked => "unlocked",
        State::Locked => "locked",
        State::NeedsRecovery => "needs_recovery",
        State::Locking => "locking",
        State::Unlocking => "unlocking",
    }
}

/// Compare every byte. A mismatch does not return at the first difference.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = u8::from(left.len() != right.len());
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_byte = if index < left.len() { left[index] } else { 0 };
        let right_byte = if index < right.len() { right[index] } else { 0 };
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn passphrase_is_missing(message: &str) -> bool {
    message.contains("KeyDoesNotExist") || message.contains("KeyRevoked")
}

fn plain_vault_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

pub(crate) fn passwd_for_path(path: &Path) -> Option<Account> {
    unsafe { nix::libc::setpwent() };
    let mut best: Option<Account> = None;
    let mut best_len = 0usize;
    loop {
        let entry = unsafe { nix::libc::getpwent() };
        if entry.is_null() {
            break;
        }
        let entry = unsafe { &*entry };
        let Ok(home) = c_string(entry.pw_dir) else {
            continue;
        };
        let home_path = PathBuf::from(&home);
        // `/` is every path's prefix. System accounts use it and are not vault owners.
        if home_path == Path::new("/") || home.is_empty() {
            continue;
        }
        if (path == home_path || path.starts_with(&home_path)) && home.len() > best_len {
            let Ok(user) = c_string(entry.pw_name) else {
                continue;
            };
            best_len = home.len();
            best = Some(Account {
                user,
                uid: entry.pw_uid,
                gid: entry.pw_gid,
                home: home_path,
            });
        }
    }
    unsafe { nix::libc::endpwent() };
    best
}

pub(crate) fn ids_for_path(path: &Path) -> Option<(u32, u32, PathBuf)> {
    if let Some(account) = passwd_for_path(path) {
        return Some((account.uid, account.gid, account.home));
    }
    let meta = std::fs::metadata(path).ok()?;
    Some((
        meta.uid(),
        meta.gid(),
        path.parent().unwrap_or(path).to_path_buf(),
    ))
}

pub(crate) fn passwd_account(uid: u32) -> Result<Account, HelperError> {
    if uid == 0 {
        return Err(HelperError::Failed("root cannot own a vault".into()));
    }
    let mut buf_len = 16 * 1024;
    loop {
        let mut pwd = std::mem::MaybeUninit::<nix::libc::passwd>::zeroed();
        let mut buf = vec![0u8; buf_len];
        let mut result = std::ptr::null_mut();
        let rc = unsafe {
            nix::libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut nix::libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == nix::libc::ERANGE {
            buf_len = buf_len.saturating_mul(2);
            if buf_len > 1024 * 1024 {
                return Err(HelperError::NotAuthorized(
                    "passwd entry is too large".into(),
                ));
            }
            continue;
        }
        if rc != 0 || result.is_null() {
            return Err(HelperError::NotAuthorized(format!(
                "no passwd entry for uid {uid}"
            )));
        }
        let pwd = unsafe { pwd.assume_init() };
        let user = c_string(pwd.pw_name)?;
        let home = c_string(pwd.pw_dir)?;
        let gid = pwd.pw_gid;
        return Ok(Account {
            user,
            uid,
            gid,
            home: PathBuf::from(home),
        });
    }
}

fn c_string(ptr: *const nix::libc::c_char) -> Result<String, HelperError> {
    if ptr.is_null() {
        return Err(HelperError::NotAuthorized(
            "passwd entry is missing a field".into(),
        ));
    }
    let text = unsafe { CStr::from_ptr(ptr) };
    text.to_str()
        .map(str::to_string)
        .map_err(|_| HelperError::NotAuthorized("passwd entry is not utf-8".into()))
}

#[cfg(test)]
mod archive_errors {
    use super::{plain_archive_error, HelperError};
    use zbus::DBusError;

    #[test]
    fn seven_zip_text_becomes_a_short_error() {
        let wrong = plain_archive_error(HelperError::Failed(
            "unlocking for /home/me/Forge: wrong passphrase: ERROR: Wrong password : Forge.7z\n7-Zip banner".into(),
        ));
        assert_eq!(
            wrong.name().as_str(),
            "org.linuxvault.Error.WrongPassphrase"
        );
        assert_eq!(wrong.description(), Some("wrong passphrase"));
        assert!(!wrong.to_string().contains("7-Zip"));
        assert!(!wrong.to_string().contains("Forge.7z"));

        let space = plain_archive_error(HelperError::Failed(
            "7z failed (status Some(2)): No space left on device".into(),
        ));
        assert_eq!(space.description(), Some("not enough disk space"));

        let damaged = plain_archive_error(HelperError::Failed(
            "7z failed (status Some(2)): ERROR: Data Error : Forge.7z".into(),
        ));
        assert_eq!(damaged.description(), Some("the archive is damaged"));
        assert!(!damaged.to_string().contains("Forge.7z"));

        let stopped = plain_archive_error(HelperError::Failed(
            "unlocking for /home/me/Forge: 7z failed (status Some(1)): ".into(),
        ));
        assert!(stopped.to_string().contains("7z failed"), "{stopped}");
        assert!(!stopped.to_string().contains("could not be read"));
    }

    #[test]
    fn every_detail_line_is_debug_priority() {
        let lines = super::debug_lines(
            "7-Zip 26.02\nERROR: Wrong password : Forge.7z\n\nHeaders Error\r\n",
        );
        assert_eq!(
            lines,
            vec![
                "<7>linux-vault-helper: 7-Zip 26.02".to_string(),
                "<7>linux-vault-helper: ERROR: Wrong password : Forge.7z".to_string(),
                "<7>linux-vault-helper: Headers Error".to_string(),
            ]
        );
    }
}

#[cfg(test)]
mod compare_tests {
    use super::constant_time_eq;

    #[test]
    fn equal_bytes_match_and_a_difference_does_not() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secres"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(!constant_time_eq(b"", b"secret"));
    }
}

#[cfg(test)]
mod root_owner {
    use super::passwd_account;

    #[test]
    fn root_cannot_own_a_vault() {
        match passwd_account(0) {
            Ok(_) => panic!("root was accepted"),
            Err(error) => assert!(
                error.to_string().contains("root cannot own a vault"),
                "{error}"
            ),
        }
    }
}

#[cfg(test)]
mod not_found {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    use super::{Account, Authorizer, Helper, Prompt};
    use zbus::DBusError;

    fn account(uid: u32, home: std::path::PathBuf) -> Account {
        Account {
            user: format!("u{uid}"),
            uid,
            gid: uid,
            home,
        }
    }

    fn shows_not_found(error: &super::HelperError) -> bool {
        error.name().as_str() == "org.linuxvault.Error.NotFound"
            && error.description() == Some("vault not found")
    }

    #[tokio::test]
    async fn someone_elses_vault_matches_a_missing_name() {
        let dir = std::env::temp_dir().join(format!("lve-notfound-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("home")).unwrap();
        fs::create_dir_all(dir.join("elsewhere")).unwrap();
        let home = dir.join("home").canonicalize().unwrap();
        let elsewhere = dir.join("elsewhere").canonicalize().unwrap();
        let folder = home.join("Forge");
        fs::create_dir(&folder).unwrap();
        let (vaults, _) = linux_vault::Vaults::open(dir.join("registry"), &home)
            .unwrap()
            .trace_immutable_flag();
        let helper = Helper::new(
            Authorizer::Allow,
            vaults,
            Prompt::Program(vec!["/bin/true".into()]),
            account(10, home.clone()),
        )
        .unwrap();
        helper.vaults.register_unlocked(10, &folder).unwrap();
        let owner = account(10, home);
        let other = account(20, elsewhere);
        let missing = helper.owned_vault(&owner, "NoSuch").await.unwrap_err();
        let foreign = helper.owned_vault(&other, "Forge").await.unwrap_err();
        assert!(shows_not_found(&missing), "{missing}");
        assert_eq!(missing.to_string(), foreign.to_string());
        assert_eq!(missing.name().as_str(), foreign.name().as_str());
        assert_eq!(missing.description(), foreign.description());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_mode_700_home_refuses_a_folder_owned_by_someone_else() {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata("/proc/self").unwrap();
        let uid = meta.uid();
        let gid = meta.gid();
        let dir = std::env::temp_dir().join(format!("lve-mode700-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir(dir.join("home")).unwrap();
        let home = dir.join("home").canonicalize().unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let folder = home.join("Forge");
        fs::create_dir(&folder).unwrap();
        let (vaults, _) = linux_vault::Vaults::open(dir.join("registry"), &home)
            .unwrap()
            .trace_immutable_flag();
        let caller = Account {
            user: "caller".into(),
            uid,
            gid,
            home: home.clone(),
        };
        let helper = Helper::new(
            Authorizer::Allow,
            vaults,
            Prompt::Program(vec!["/bin/true".into()]),
            caller.clone(),
        )
        .unwrap();
        let absent = home.join("Absent");
        helper.vaults.register_unlocked(uid, &absent).unwrap();
        let unseen = helper.owned_vault(&caller, "Absent").await.unwrap_err();
        assert!(shows_not_found(&unseen), "{unseen}");
        let other = 65534u32;
        let c_folder = std::ffi::CString::new(folder.to_str().unwrap()).unwrap();
        if unsafe { nix::libc::chown(c_folder.as_ptr(), other, other) } != 0 {
            let error = std::io::Error::last_os_error();
            assert!(
                error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(nix::libc::EINVAL),
                "chown of the inner folder: {error}"
            );
            eprintln!(
                "a_mode_700_home_refuses_a_folder_owned_by_someone_else: skipped the foreign owner, chown is not permitted"
            );
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        helper.vaults.register_unlocked(uid, &folder).unwrap();
        let refused = helper.owned_vault(&caller, "Forge").await.unwrap_err();
        assert!(shows_not_found(&refused), "{refused}");
        assert_eq!(refused.to_string(), unseen.to_string());
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod dump_tests {
    #[test]
    fn core_dumps_can_be_disabled() {
        super::disable_core_dumps().unwrap();
        let dumpable = unsafe { nix::libc::prctl(nix::libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0);
    }
}
