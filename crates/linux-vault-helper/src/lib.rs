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
mod worker;

use std::ffi::{CStr, OsString};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

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
#[doc(hidden)]
pub fn limit_to_unit_capabilities() {
    const KEEP: &[i32] = &[3, 6, 7, 9, 14, 19];
    const VERSION_3: u32 = 0x2008_0522;
    const SYS_CAPGET: i64 = 125;
    const SYS_CAPSET: i64 = 126;
    const PR_CAPBSET_DROP: i32 = 24;
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
        for cap in 0..64 {
            if !KEEP.contains(&cap) {
                nix::libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
            }
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
pub use locks::VaultLocks;
pub use pinentry::{CancelToken, Passphrase, Pinentry, PinentryError, Purpose};
pub use polkit::{bus_name_subject, Authorizer};
pub use shutdown::ShutdownHandle;

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

enum Accounts {
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
        let shutdown = ShutdownHandle::new(
            Arc::clone(&gate),
            cancel.clone(),
            Arc::clone(&vaults),
            passphrases.clone(),
            Arc::clone(&inhibit),
            Arc::new(tokio::sync::Mutex::new(())),
            Arc::new(AtomicUsize::new(0)),
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
        };
        helper.reconcile_with_workers()?;
        Ok(helper)
    }

    /// One worker per user. The worker checks filenames; this process writes
    /// the registry and sets the immutable flag on archives that remain.
    fn reconcile_with_workers(&self) -> Result<(), HelperError> {
        let listed = self
            .vaults
            .list()
            .map_err(|error| failed("reconciling", "registry", error))?;
        let mut groups: Vec<(Account, Vec<linux_vault::Vault>)> = Vec::new();
        for vault in listed {
            let account = self.owner_for(&vault.path)?;
            if let Some(group) = groups
                .iter_mut()
                .find(|(owner, _)| owner.uid == account.uid)
            {
                group.1.push(vault);
            } else {
                groups.push((account, vec![vault]));
            }
        }
        for (account, vaults) in groups {
            let mut worker = worker::HomeWorker::spawn(
                account.uid,
                account.gid,
                &account.home,
                self.vaults.share(),
            )?;
            for vault in vaults {
                let facts = worker.inspect(&vault.path)?;
                if !facts.folder && !facts.archive {
                    self.vaults
                        .unregister(&vault.name)
                        .map_err(|error| failed("reconciling", &vault.name, error))?;
                    worker.remove_bookmark(&vault.path)?;
                    continue;
                }
                let state = if facts.archive {
                    linux_vault::State::Locked
                } else {
                    linux_vault::State::NeedsRecovery
                };
                self.vaults
                    .set_state(&vault.name, state)
                    .map_err(|error| failed("reconciling", &vault.name, error))?;
                if facts.archive {
                    worker.seal(&vault.path)?;
                }
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

    fn keep(&self, name: &str, passphrase: Passphrase) -> Result<(), HelperError> {
        self.passphrases.insert(name, passphrase)
    }

    async fn owned_vault(
        &self,
        account: &Account,
        name: &str,
    ) -> Result<linux_vault::Vault, HelperError> {
        let vaults = self.vaults_for(account)?;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        let vault = tokio::task::spawn_blocking(move || vaults.get(&name_owned))
            .await
            .map_err(|error| failed("reading the registry", &vault_name, error))?
            .map_err(|error| failed("reading the registry", name, error))?;
        if !caller_owns(&account.home, account.uid, &vault.path) {
            return Err(failed("reading the registry", name, "vault not found"));
        }
        Ok(vault)
    }

    /// The worker scans the owner's processes. The helper scans root's when
    /// the owner is someone else.
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
        tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults)?;
            worker.scan_open_files(&owner_name, &owner_path)
        })
        .await
        .map_err(|error| failed("checking open files", name, error))??;
        if uid != 0 {
            let root_path = path.to_path_buf();
            let root_name = name.to_string();
            tokio::task::spawn_blocking(move || {
                open_files::refuse_if_open(&root_path, &root_name, 0)
            })
            .await
            .map_err(|error| failed("checking open files", name, error))??;
        }
        Ok(())
    }

    /// A lock that stops before 7z starts. A held passphrase goes back to
    /// unlocked. No held passphrase is needs recovery.
    fn restore_before_pack(&self, name: &str) {
        let state = if self.passphrases.contains(name) {
            State::Unlocked
        } else {
            State::NeedsRecovery
        };
        if let Err(error) = self.vaults.set_state(name, state) {
            eprintln!("linux-vault-helper: locking for {name}: {error}");
        }
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

    pub fn contains(&self, name: &str) -> bool {
        self.keys.contains(name)
    }

    fn insert(&self, name: &str, passphrase: Passphrase) -> Result<(), HelperError> {
        self.keys.insert(name, passphrase)
    }

    /// The passphrase Lock feeds to `7z`. Nothing on the bus reads this.
    pub(crate) fn read(&self, name: &str) -> Result<Passphrase, HelperError> {
        self.keys.read(name)
    }

    /// Drop the key after a successful lock.
    pub fn forget(&self, name: &str) -> Result<(), HelperError> {
        self.keys.forget(name)
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
        let account = self.account_of(&caller)?;
        let name = folder_name(path)?;
        let _guard = self.locks.acquire(&name).await;
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
        let created = tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults.share())?;
            let canonical = worker.resolve(Path::new(&path))?;
            if canonical != home && !canonical.starts_with(&home) {
                return Err(failed("creating", &path, "vault path is outside the home"));
            }
            vaults
                .register_unlocked(&canonical)
                .map_err(|error| failed("creating", &canonical.display().to_string(), error))
        })
        .await
        .map_err(|error| failed("creating", &reported, error))??;
        self.keep(&created.name, passphrase)?;
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
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "locking",
                name,
                "vault name is not a single path component",
            ));
        }
        let _guard = self.locks.acquire(name).await;
        self.gate.ensure_open()?;
        let vaults = self.vaults_for(&account)?;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        let vault = tokio::task::spawn_blocking(move || vaults.get(&name_owned))
            .await
            .map_err(|error| failed("locking", &vault_name, error))?
            .map_err(|error| failed("locking", name, error))?;
        match vault.state {
            State::Unlocked | State::NeedsRecovery => {}
            state => {
                return Err(failed("locking", name, format!("that is {state}")));
            }
        }
        let path = vault.path.clone();
        let vault_name = name.to_string();
        let (_stored_path, previous) = self
            .vaults
            .begin_lock(name)
            .map_err(|error| failed("locking", name, error))?;
        if let Err(error) = self
            .files_are_open(account.uid, account.gid, &account.home, &path, name)
            .await
        {
            self.restore_before_pack(name);
            return Err(error);
        }
        let passphrase = match self.passphrases.read(name) {
            Ok(passphrase) => passphrase,
            Err(HelperError::Failed(message)) if passphrase_is_missing(&message) => {
                let pinentry = match self.pinentry_for(&account) {
                    Ok(pinentry) => pinentry,
                    Err(error) => {
                        self.restore_before_pack(name);
                        return Err(error);
                    }
                };
                let prompt = self.cancel.child();
                match pinentry.ask(Purpose::Recovery, name, &prompt).await {
                    Ok(passphrase) => passphrase,
                    Err(error) => {
                        self.restore_before_pack(name);
                        return Err(named_pin("asking for the passphrase", name, error));
                    }
                }
            }
            Err(error) => {
                self.restore_before_pack(name);
                return Err(error);
            }
        };
        let packed = {
            let uid = account.uid;
            let gid = account.gid;
            let home = account.home.clone();
            let vaults = self.vaults.share();
            let path = path.clone();
            tokio::task::spawn_blocking(move || {
                let mut worker = match worker::HomeWorker::spawn(uid, gid, &home, vaults) {
                    Ok(worker) => worker,
                    Err(error) => return Err((true, error)),
                };
                worker
                    .pack(&path, passphrase.as_bytes())
                    .map_err(|error| (false, error))
            })
            .await
        };
        match packed {
            Err(error) => {
                self.restore_before_pack(name);
                return Err(failed("locking", &vault_name, error));
            }
            Ok(Err((true, error))) => {
                self.restore_before_pack(name);
                return Err(error);
            }
            Ok(Err((false, error))) => {
                let _ = self.vaults.finish_lock(name, previous, false);
                return Err(error);
            }
            Ok(Ok(())) => {}
        }
        self.vaults
            .finish_lock(name, previous, true)
            .map_err(|error| failed("locking", name, error))?;
        self.passphrases.forget(name)?;
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
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "unlocking",
                name,
                "vault name is not a single path component",
            ));
        }
        let _guard = self.locks.acquire(name).await;
        self.gate.ensure_open()?;
        let vaults = self.vaults_for(&account)?;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        let vault = tokio::task::spawn_blocking(move || vaults.get(&name_owned))
            .await
            .map_err(|error| failed("unlocking", &vault_name, error))?
            .map_err(|error| failed("unlocking", name, error))?;
        if vault.state != State::Locked {
            return Err(failed(
                "unlocking",
                name,
                format!("that is {}", vault.state),
            ));
        }
        let pinentry = self.pinentry_for(&account)?;
        let prompt = self.cancel.child();
        let passphrase = pinentry
            .ask(Purpose::Unlock, name, &prompt)
            .await
            .map_err(|error| named_pin("asking for the passphrase", name, error))?;
        let path = self
            .vaults
            .begin_unlock(name)
            .map_err(|error| failed("unlocking", name, error))?;
        let uid = account.uid;
        let gid = account.gid;
        let home = account.home.clone();
        let vaults = self.vaults.share();
        let bytes = zeroize::Zeroizing::new(passphrase.as_bytes().to_vec());
        let unpacked = tokio::task::spawn_blocking(move || {
            let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults)?;
            worker.unpack(&path, &bytes)
        })
        .await
        .map_err(|error| failed("unlocking", name, error))?;
        if let Err(error) = unpacked {
            let _ = self.vaults.finish_unlock(name, false);
            return Err(error);
        }
        self.vaults
            .finish_unlock(name, true)
            .map_err(|error| failed("unlocking", name, error))?;
        self.keep(name, passphrase)?;
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
        self.gate.ensure_open()?;
        let account = self.account_of(&caller)?;
        let vaults = self.vaults_for(&account)?;
        let listed = tokio::task::spawn_blocking(move || vaults.list())
            .await
            .map_err(|error| failed("listing", "registry", error))?
            .map_err(|error| failed("listing", "registry", error))?;
        Ok(listed
            .into_iter()
            .filter(|vault| caller_owns(&account.home, account.uid, &vault.path))
            .map(|vault| VaultStatus {
                name: vault.name,
                path: vault.path.display().to_string(),
                state: state_wire(vault.state).to_string(),
            })
            .collect())
    }

    async fn remove(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        name: &str,
    ) -> Result<(), HelperError> {
        let _flight = self.gate.enter()?;
        let caller = self.gate(connection, &header).await?;
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "removing",
                name,
                "vault name is not a single path component",
            ));
        }
        let _guard = self.locks.acquire(name).await;
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
            let path = self
                .vaults
                .begin_unlock(name)
                .map_err(|error| failed("removing", name, error))?;
            let uid = account.uid;
            let gid = account.gid;
            let home = account.home.clone();
            let vaults = self.vaults.share();
            let unpacked = tokio::task::spawn_blocking(move || {
                let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults)?;
                worker.unpack(&path, passphrase.as_bytes())
            })
            .await
            .map_err(|error| failed("removing", name, error))?;
            if let Err(error) = unpacked {
                let _ = self.vaults.finish_unlock(name, false);
                return Err(error);
            }
            self.vaults
                .finish_unlock(name, true)
                .map_err(|error| failed("removing", name, error))?;
        }
        let vaults = self.vaults_for(&account)?;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        tokio::task::spawn_blocking(move || vaults.unregister(&name_owned))
            .await
            .map_err(|error| failed("removing", &vault_name, error))?
            .map_err(|error| failed("removing", name, error))?;
        self.passphrases.forget(name)?;
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
        let account = self.account_of(&caller)?;
        if !plain_vault_name(name) {
            return Err(failed(
                "terminating",
                name,
                "vault name is not a single path component",
            ));
        }
        let _guard = self.locks.acquire(name).await;
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
        match vault.state {
            State::Locked => {
                let uid = account.uid;
                let gid = account.gid;
                let home = account.home.clone();
                let vaults = self.vaults.share();
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults)?;
                    worker.delete_archive(&path, typed.as_bytes())
                })
                .await
                .map_err(|error| failed("terminating", name, error))??;
            }
            State::Unlocked => {
                let held = match self.passphrases.read(name) {
                    Ok(held) => held,
                    Err(HelperError::Failed(message)) if passphrase_is_missing(&message) => {
                        return Err(failed("terminating", name, "the passphrase is not held"));
                    }
                    Err(error) => return Err(error),
                };
                if !constant_time_eq(typed.as_bytes(), held.as_bytes()) {
                    return Err(failed("terminating", name, "wrong passphrase"));
                }
                let uid = account.uid;
                let gid = account.gid;
                let home = account.home.clone();
                let vaults = self.vaults.share();
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults)?;
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
            tokio::task::spawn_blocking(move || {
                let mut worker = worker::HomeWorker::spawn(uid, gid, &home, vaults)?;
                worker.remove_bookmark(&path)
            })
            .await
            .map_err(|error| failed("terminating", name, error))??;
        }
        let vaults = self.vaults_for(&account)?;
        let name_owned = name.to_string();
        let vault_name = name.to_string();
        tokio::task::spawn_blocking(move || vaults.unregister(&name_owned))
            .await
            .map_err(|error| failed("terminating", &vault_name, error))?
            .map_err(|error| failed("terminating", name, error))?;
        self.passphrases.forget(name)?;
        Ok(())
    }
}

fn failed(step: &str, target: &str, error: impl std::fmt::Display) -> HelperError {
    HelperError::Failed(format!("{step} for {target}: {error}"))
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

fn state_wire(state: State) -> &'static str {
    match state {
        State::Unlocked => "unlocked",
        State::Locked => "locked",
        State::NeedsRecovery => "needs_recovery",
        State::Locking => "locking",
        State::Unlocking => "unlocking",
    }
}

/// The vault lives in this caller's home, and its folder or archive is owned
/// by this caller's UID. Anything else is omitted, including the name.
fn caller_owns(home: &Path, uid: u32, vault: &Path) -> bool {
    if vault != home && !vault.starts_with(home) {
        return false;
    }
    match file_owner(vault) {
        Some(owner) => owner == uid,
        // Mode 700 is not stat-able as root. The path is already under this home.
        None => true,
    }
}

fn file_owner(vault: &Path) -> Option<u32> {
    let path = if vault.is_dir() {
        vault.to_path_buf()
    } else {
        let name = vault.file_name()?.to_str()?;
        let archive = vault.with_file_name(format!("{name}.7z"));
        if archive.is_file() {
            archive
        } else {
            vault.parent()?.to_path_buf()
        }
    };
    std::fs::symlink_metadata(path).ok().map(|meta| meta.uid())
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
mod dump_tests {
    #[test]
    fn core_dumps_can_be_disabled() {
        super::disable_core_dumps().unwrap();
        let dumpable = unsafe { nix::libc::prctl(nix::libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0);
    }
}
