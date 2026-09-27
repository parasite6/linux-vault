//! Lock, test, delete, and unlock a folder with 7z, and remember that in a registry.
//!
//! The passphrase is borrowed bytes. This crate does not start pinentry or talk
//! on D-Bus. `7z` runs as this process unless [`Vaults::for_user`] names the
//! vault owner's uid and gid. That call uses `setuid` and `setgid`, so the
//! child cannot switch back to root. The immutable flag is the ioctl on the
//! archive, not the `chattr` command.
//! Point [`Vaults::open`] at a registry directory and the root the vaults must
//! stay inside (a temporary directory in tests, the user's home in the helper).
//!
//! Call [`Vaults::reconcile`] once when the process starts. Recovery reads
//! filenames in the vault's parent. A `.lve-unlocking` folder or a
//! `.lve-partial` archive is an unfinished operation: it is deleted and the
//! real files stay. When both the folder and the `.7z` exist, the plaintext
//! is deleted and the vault is locked. A folder with no archive needs recovery,
//! because this process does not have the passphrase.

mod error;
mod immutable;
mod registry;
mod sevenz;

pub use sevenz::close_extra_fds;

use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use error::Result;
pub use registry::ArchiveIdentity as ArchiveId;
pub use registry::{vaults_are_nested, Nesting};
use registry::{ArchiveIdentity, LockFile, Record, Registry};
use sevenz::{
    add_command, command_args, find_seven_zip, run, run_interruptible, run_without_passphrase,
    Credentials,
};

pub use error::Error;

/// One change of the immutable bit, recorded when tests replace the ioctl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagChange {
    /// The bit was cleared.
    Clear,
    /// The bit was set.
    Set,
}

/// Calls recorded by [`Vaults::trace_immutable_flag`].
#[derive(Clone, Debug)]
pub struct ImmutableTrace {
    calls: Arc<Mutex<Vec<FlagChange>>>,
}

impl ImmutableTrace {
    pub fn calls(&self) -> Vec<FlagChange> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

type FlagHook = Arc<dyn Fn(&Path, bool) -> Result<()> + Send + Sync>;

#[derive(Clone)]
enum FlagBackend {
    Ioctl,
    Record(Arc<Mutex<Vec<FlagChange>>>),
    /// The worker opens the archive and the helper applies the ioctl.
    Hook(FlagHook),
}

/// Where a vault's bytes are, and whether a restart lost the passphrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// The folder is plaintext. The caller is holding the passphrase.
    Unlocked,
    /// The folder is gone. The sibling `.7z` archive is the vault.
    Locked,
    /// The folder is plaintext and this process does not have the passphrase.
    /// Lock asks for it again; there is no archive to check it against.
    NeedsRecovery,
    /// Lock has started. `7z` is running, and the registry file is not locked.
    Locking,
    /// Unlock has started. `7z` is running, and the registry file is not locked.
    Unlocking,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            State::Unlocked => "unlocked",
            State::Locked => "locked",
            State::NeedsRecovery => "needs recovery",
            State::Locking => "locking",
            State::Unlocking => "unlocking",
        })
    }
}

/// What [`Vaults::reconcile`] changed.
pub struct Reconciled {
    /// Vaults still registered.
    pub vaults: Vec<Vault>,
    /// Paths whose folder and archive were both gone. The registry entry was
    /// removed. These are finished terminates, not vaults that need recovery.
    pub removed: Vec<PathBuf>,
}

/// A registered vault. `path` is the plaintext folder, present or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub uid: u32,
    pub name: String,
    pub path: PathBuf,
    pub state: State,
    /// False when the vault is locked and the immutable flag could not be set.
    pub immutable: bool,
}

/// Registry plus the 7z operations that move a vault between folder and archive.
pub struct Vaults {
    registry_dir: PathBuf,
    allowed_root: PathBuf,
    /// Core methods act for this uid. The helper passes the caller explicitly.
    owner_uid: u32,
    seven_zip: PathBuf,
    /// Serializes `flock` calls. Two flocks on different descriptors in one
    /// process block each other, including on the same thread.
    registry_gate: Arc<Mutex<()>>,
    /// Uid and gid of the `7z` child. Absent means this process, which is the
    /// vault owner in tests. The helper sets it to the caller.
    run_as: Option<Credentials>,
    flags: FlagBackend,
    /// When set, an unlock that is still extracting kills `7z` and restores
    /// the immutable flag. A lock that is already packing does not look at this.
    stop_extract: Arc<AtomicBool>,
}

impl Vaults {
    /// Open a registry. Creates `registry_dir` if it is missing.
    ///
    /// `allowed_root` is the directory every vault must resolve inside.
    /// This does not reconcile. Call [`Self::reconcile`] once at process start.
    pub fn open(registry_dir: impl Into<PathBuf>, allowed_root: impl AsRef<Path>) -> Result<Self> {
        let registry_dir = registry_dir.into();
        fs::create_dir_all(&registry_dir)?;
        let _ = fs::set_permissions(&registry_dir, fs::Permissions::from_mode(0o700));
        let allowed_root = allowed_root.as_ref().canonicalize()?;
        Ok(Self {
            registry_dir,
            allowed_root,
            owner_uid: current_uid(),
            seven_zip: find_seven_zip()?,
            registry_gate: Arc::new(Mutex::new(())),
            run_as: None,
            flags: FlagBackend::Ioctl,
            stop_extract: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Same registry and `7z`, with a different directory vaults must stay inside.
    ///
    /// The registry mutex is shared, so two views of one registry do not
    /// `flock` separate descriptors at the same time.
    pub fn for_root(&self, allowed_root: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            registry_dir: self.registry_dir.clone(),
            allowed_root: allowed_root.as_ref().canonicalize()?,
            owner_uid: self.owner_uid,
            seven_zip: self.seven_zip.clone(),
            registry_gate: Arc::clone(&self.registry_gate),
            run_as: self.run_as,
            flags: self.flags.clone(),
            stop_extract: Arc::clone(&self.stop_extract),
        })
    }

    /// Another handle on the same registry. Does not touch the filesystem.
    pub fn share(&self) -> Self {
        Self {
            registry_dir: self.registry_dir.clone(),
            allowed_root: self.allowed_root.clone(),
            owner_uid: self.owner_uid,
            seven_zip: self.seven_zip.clone(),
            registry_gate: Arc::clone(&self.registry_gate),
            run_as: self.run_as,
            flags: self.flags.clone(),
            stop_extract: Arc::clone(&self.stop_extract),
        }
    }

    /// The worker uses this so an immutable-flag change is sent to the helper.
    pub fn with_flag_hook<F>(&self, hook: F) -> Self
    where
        F: Fn(&Path, bool) -> Result<()> + Send + Sync + 'static,
    {
        Self {
            registry_dir: self.registry_dir.clone(),
            allowed_root: self.allowed_root.clone(),
            owner_uid: self.owner_uid,
            seven_zip: self.seven_zip.clone(),
            registry_gate: Arc::clone(&self.registry_gate),
            run_as: None,
            flags: FlagBackend::Hook(Arc::new(hook)),
            stop_extract: Arc::clone(&self.stop_extract),
        }
    }

    /// Share one stop flag, so a signal in the worker can abort an extract.
    pub fn with_stop_flag(&self, flag: Arc<AtomicBool>) -> Self {
        Self {
            registry_dir: self.registry_dir.clone(),
            allowed_root: self.allowed_root.clone(),
            owner_uid: self.owner_uid,
            seven_zip: self.seven_zip.clone(),
            registry_gate: Arc::clone(&self.registry_gate),
            run_as: self.run_as,
            flags: self.flags.clone(),
            stop_extract: flag,
        }
    }

    /// Run `7z` as `uid`/`gid` instead of this process.
    ///
    /// The registry stays with this process. Only the `7z` child switches.
    /// Supplementary groups are cleared when this process can (`CAP_SETGID`).
    pub fn for_user(&self, uid: u32, gid: u32) -> Self {
        Self {
            registry_dir: self.registry_dir.clone(),
            allowed_root: self.allowed_root.clone(),
            owner_uid: self.owner_uid,
            seven_zip: self.seven_zip.clone(),
            registry_gate: Arc::clone(&self.registry_gate),
            run_as: Some(Credentials { uid, gid }),
            flags: self.flags.clone(),
            stop_extract: Arc::clone(&self.stop_extract),
        }
    }

    /// Kill an unlock's `7z` if it is still extracting, and restore the flag.
    pub fn request_stop_extract(&self) {
        self.stop_extract.store(true, Ordering::SeqCst);
    }

    /// Record immutable-flag changes instead of calling the ioctl.
    ///
    /// Tests use this. The helper does not: it uses the ioctl.
    pub fn trace_immutable_flag(&self) -> (Self, ImmutableTrace) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let vaults = Self {
            registry_dir: self.registry_dir.clone(),
            allowed_root: self.allowed_root.clone(),
            owner_uid: self.owner_uid,
            seven_zip: self.seven_zip.clone(),
            registry_gate: Arc::clone(&self.registry_gate),
            run_as: self.run_as,
            flags: FlagBackend::Record(Arc::clone(&calls)),
            stop_extract: Arc::clone(&self.stop_extract),
        };
        (vaults, ImmutableTrace { calls })
    }

    /// The `7z` binary this process will run. The helper resolves it once and
    /// the worker uses that path instead of searching `PATH` again.
    pub fn seven_zip(&self) -> &Path {
        &self.seven_zip
    }

    /// Use this `7z` binary instead of the one found on `PATH`.
    pub fn set_seven_zip(&mut self, path: impl Into<PathBuf>) {
        self.seven_zip = path.into();
    }

    /// Register a folder. It stays plaintext until [`Self::lock`].
    ///
    /// The vault name is the folder's file name. The path is stored in
    /// canonical form. The directory is created if it does not exist yet.
    pub fn create(&self, folder: impl AsRef<Path>) -> Result<Vault> {
        let path = prepare_folder(folder.as_ref(), &self.allowed_root)?;
        let name = vault_name(&path)?;
        if archive_for(&path).exists() {
            return Err(Error::AlreadyExists);
        }
        let uid = self.owner_uid;
        self.write(|registry| {
            registry.insert(Record {
                uid,
                name: name.clone(),
                path: path.clone(),
                state: State::Unlocked,
                archive: None,
                immutable: true,
            })?;
            Ok(())
        })?;
        Ok(Vault {
            uid,
            name,
            path,
            state: State::Unlocked,
            immutable: true,
        })
    }

    pub fn list(&self) -> Result<Vec<Vault>> {
        self.read(|registry| Ok(registry.iter().map(Vault::from).collect()))
    }

    pub fn get(&self, name: &str) -> Result<Vault> {
        self.get_for(self.owner_uid, name)
    }

    /// One vault belonging to `uid`. A different user's vault with the same
    /// folder name is not this one.
    pub fn get_for(&self, uid: u32, name: &str) -> Result<Vault> {
        self.read(|registry| registry.get(uid, name).map(Vault::from))
    }

    /// Apply recovery from the filenames in each vault's parent directory.
    ///
    /// A `.lve-unlocking` folder or a `.lve-partial` archive means that
    /// operation did not finish. The staging item is deleted. The real folder
    /// and the real archive are left as they are.
    ///
    /// After that:
    /// - Folder and archive both present: the crash was after the rename and
    ///   before the delete. The plaintext folder is deleted and the vault is
    ///   locked. Both copies are complete, and the locked one is kept.
    /// - Archive only: locked.
    /// - Folder only: needs recovery.
    /// - Neither: a terminate finished. The registry entry is removed.
    ///   [`Reconciled::removed`] is those paths, so the helper can drop the
    ///   bookmark. They are not reported as needing recovery.
    ///
    /// A `locking` or `unlocking` mark left by a killed process is not kept.
    /// The filenames decide the state, same as any other restart.
    pub fn reconcile(&self) -> Result<Reconciled> {
        let (listed, locked, removed) = self.write(|registry| {
            let keys: Vec<(u32, String)> = registry
                .iter()
                .map(|record| (record.uid, record.name.clone()))
                .collect();
            let mut locked = Vec::new();
            let mut removed = Vec::new();
            for (uid, name) in keys {
                let record = registry.get(uid, &name)?.clone();
                let parent = parent_dir(&record.path)?;
                let unlocking = parent.join(unlocking_file_name(&record.path)?);
                let partial = parent.join(partial_file_name(&record.path)?);
                if unlocking.symlink_metadata().is_ok() {
                    remove_path(&unlocking)?;
                }
                if partial.symlink_metadata().is_ok() {
                    remove_path(&partial)?;
                }
                let folder = record.path.is_dir();
                let archive_path = archive_for(&record.path);
                let archive = archive_path.is_file();
                if !folder && !archive {
                    registry.remove(uid, &name)?;
                    removed.push(record.path);
                    sync_dir(&parent)?;
                    continue;
                }
                let live = if archive {
                    ArchiveIdentity::capture(&archive_path).ok()
                } else {
                    None
                };
                let proven = live
                    .as_ref()
                    .is_some_and(|live| record.archive.as_ref() == Some(live));
                let state = if folder && archive && proven {
                    fs::remove_dir_all(&record.path)?;
                    State::Locked
                } else if folder && archive {
                    eprintln!(
                        "<3>linux-vault: {} and {} both exist and the archive is not this vault's; deleted nothing",
                        record.path.display(),
                        archive_path.display()
                    );
                    State::NeedsRecovery
                } else if archive {
                    State::Locked
                } else {
                    State::NeedsRecovery
                };
                if let Ok(entry) = registry.get_mut(uid, &name) {
                    if state == State::Locked {
                        if let Some(live) = live.clone() {
                            entry.archive = Some(live);
                        }
                    }
                }
                sync_dir(&parent)?;
                if state == State::Locked {
                    locked.push(record.path.clone());
                }
                registry.get_mut(uid, &name)?.state = state;
            }
            Ok((registry.iter().map(Vault::from).collect(), locked, removed))
        })?;
        for path in locked {
            self.mark_immutable(&path, true)?;
        }
        Ok(Reconciled {
            vaults: listed,
            removed,
        })
    }

    /// Remember the archive written by the lock that just renamed it into place.
    pub fn archive_identity(&self, uid: u32, name: &str) -> Result<Option<ArchiveIdentity>> {
        self.read(|registry| Ok(registry.get(uid, name)?.archive.clone()))
    }

    pub fn record_archive(&self, uid: u32, name: &str, identity: ArchiveIdentity) -> Result<()> {
        self.write(|registry| {
            registry.get_mut(uid, name)?.archive = Some(identity);
            Ok(())
        })
    }

    /// Whether the locked archive has the immutable flag. A filesystem that
    /// rejects the flag stays locked, and `lve ls` says so.
    pub fn set_immutable(&self, uid: u32, name: &str, immutable: bool) -> Result<()> {
        self.write(|registry| {
            registry.get_mut(uid, name)?.immutable = immutable;
            Ok(())
        })
    }

    /// The folder is still plaintext, or a lock or unlock did not finish.
    pub fn mark_needs_recovery(&self, uid: u32, name: &str) -> Result<()> {
        self.write(|registry| {
            let entry = registry.get_mut(uid, name)?;
            if matches!(
                entry.state,
                State::Unlocked | State::NeedsRecovery | State::Locking | State::Unlocking
            ) {
                entry.state = State::NeedsRecovery;
            }
            Ok(())
        })
    }

    /// Archive the folder into a partial sibling, check it, rename it into
    /// place, then delete the plaintext folder.
    ///
    /// The partial archive is `Name.7z.lve-partial` in the parent directory.
    /// The passphrase bytes are written to `7z`'s stdin and the pipe is closed.
    /// Nothing is trimmed. `7z l` with no password must fail before the test
    /// result is trusted. The rename to `Name.7z` is atomic in memory.
    /// The parent directory is fsynced after that rename and before the
    /// plaintext folder is deleted, so a power cut cannot persist the delete
    /// without the new name. On a failure before that rename, the partial
    /// archive is removed and the folder stays.
    pub fn lock(&self, name: &str, passphrase: &[u8]) -> Result<()> {
        check_passphrase(passphrase)?;
        let uid = self.owner_uid;
        let record = self.write(|registry| {
            let record = registry.get(uid, name)?.clone();
            match record.state {
                State::Unlocked | State::NeedsRecovery => {}
                state => {
                    return Err(Error::InvalidState {
                        state,
                        operation: "lock",
                    })
                }
            }
            if !record.path.is_dir() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "vault folder is missing",
                )));
            }
            refuse_escaping_symlinks(&record.path)?;
            let parent = parent_dir(&record.path)?;
            if archive_for(&record.path).exists() {
                return Err(Error::AlreadyExists);
            }
            registry.get_mut(uid, name)?.state = State::Locking;
            Ok((record, parent))
        })?;
        let (record, parent) = record;
        let packed = self.finish_pack(&record, &parent, passphrase);
        let previous = record.state;
        self.write(|registry| {
            let entry = registry.get_mut(uid, name)?;
            entry.state = if packed.is_ok()
                || (!record.path.exists() && archive_for(&record.path).is_file())
            {
                State::Locked
            } else {
                previous
            };
            Ok(())
        })?;
        packed
    }

    fn pack(&self, record: &Record, parent: &Path, passphrase: &[u8]) -> Result<ArchiveIdentity> {
        let final_path = archive_for(&record.path);
        let partial_name = partial_file_name(&record.path)?;
        let partial_path = parent.join(&partial_name);
        if partial_path.symlink_metadata().is_ok() {
            remove_path(&partial_path)?;
        }

        let archive_arg = format!("../{partial_name}");
        let mut args = match add_command(&archive_arg, passphrase) {
            Ok(args) => args,
            Err(error) => {
                eprintln!(
                    "<3>linux-vault-helper: encryption check failed for {}: passphrase_supplied=no",
                    record.path.display()
                );
                return Err(error);
            }
        };
        args.push(".".to_string());
        if let Err(error) = run(
            &self.seven_zip,
            &args,
            &record.path,
            passphrase,
            self.run_as,
        ) {
            discard_path(&partial_path);
            return Err(error);
        }

        let checked = (|| {
            sync_file(&partial_path)?;
            sync_dir(parent)?;
            if let Err(error) = self.require_encrypted(parent, &partial_name) {
                eprintln!(
                    "<3>linux-vault-helper: encryption check failed for {}: passphrase_supplied={}",
                    record.path.display(),
                    !passphrase.is_empty()
                );
                return Err(error);
            }
            let test_args = command_args("t", &partial_name, None);
            run(&self.seven_zip, &test_args, parent, passphrase, self.run_as)?;
            Ok(())
        })();
        if let Err(error) = checked {
            discard_path(&partial_path);
            return Err(error);
        }

        fs::rename(&partial_path, &final_path)?;
        // rename(2) only makes the new name atomic in the page cache. fsync
        // the parent before deleting the folder, or a power cut can persist
        // the delete and leave Name.7z.lve-partial, which reconcile removes.
        sync_dir(parent)?;
        ArchiveIdentity::capture(&final_path).map_err(Error::from)
    }

    /// Record the archive, then delete the plaintext. The identity is on disk
    /// before the folder goes, so a crash in between can still prove the archive.
    fn finish_pack(&self, record: &Record, parent: &Path, passphrase: &[u8]) -> Result<()> {
        let identity = self.pack(record, parent, passphrase)?;
        let uid = record.uid;
        let name = record.name.clone();
        self.write(|registry| {
            registry.get_mut(uid, &name)?.archive = Some(identity);
            Ok(())
        })?;
        fs::remove_dir_all(&record.path)?;
        sync_dir(parent)?;
        self.mark_immutable(&record.path, true)
    }

    /// Test the archive with `7z t`. Does not change the vault.
    pub fn test(&self, name: &str, passphrase: &[u8]) -> Result<()> {
        check_passphrase(passphrase)?;
        let uid = self.owner_uid;
        let record = self.read(|registry| Ok(registry.get(uid, name)?.clone()))?;
        if record.state != State::Locked {
            return Err(Error::InvalidState {
                state: record.state,
                operation: "test",
            });
        }
        self.test_archive(&record.path, passphrase)
    }

    /// Extract into a hidden staging folder, rename it onto the vault, then
    /// delete the archive.
    ///
    /// The staging folder is `.Name.lve-unlocking` in the parent directory.
    /// The rename is atomic in memory. The parent directory is fsynced after
    /// that rename and before the archive is deleted. A wrong passphrase
    /// removes that staging folder when this process is still running, and
    /// leaves the archive as the only copy.
    pub fn unlock(&self, name: &str, passphrase: &[u8]) -> Result<()> {
        check_passphrase(passphrase)?;
        let uid = self.owner_uid;
        let record = self.write(|registry| {
            let record = registry.get(uid, name)?.clone();
            if record.state != State::Locked {
                return Err(Error::InvalidState {
                    state: record.state,
                    operation: "unlock",
                });
            }
            if directory_occupied(&record.path)? {
                return Err(Error::AlreadyExists);
            }
            let archive = archive_for(&record.path);
            if !archive.is_file() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "vault archive is missing",
                )));
            }
            registry.get_mut(uid, name)?.state = State::Unlocking;
            Ok(record)
        })?;
        let extracted = self.extract(&record, passphrase);
        self.write(|registry| {
            let entry = registry.get_mut(uid, name)?;
            entry.state = if extracted.is_ok()
                || (record.path.is_dir() && !archive_for(&record.path).exists())
            {
                State::Unlocked
            } else {
                State::Locked
            };
            Ok(())
        })?;
        extracted
    }

    fn extract(&self, record: &Record, passphrase: &[u8]) -> Result<()> {
        let archive = archive_for(&record.path);
        let parent = parent_dir(&record.path)?;
        let archive_name = file_name(&archive)?;
        self.mark_immutable(&record.path, false)?;
        let extracted = self.extract_cleared(record, passphrase, &archive, &parent, &archive_name);
        if extracted.is_err() {
            // The archive cannot be deleted while immutable, so the flag was
            // cleared first. A wrong passphrase or any other failure puts it
            // back. The worker does this through the helper: it sends the
            // archive descriptor, and the helper runs the ioctl.
            if let Err(error) = self.mark_immutable(&record.path, true) {
                eprintln!(
                    "linux-vault: restoring the immutable flag on {}: {error}",
                    archive.display()
                );
            }
        }
        extracted
    }

    fn extract_cleared(
        &self,
        record: &Record,
        passphrase: &[u8],
        archive: &Path,
        parent: &Path,
        archive_name: &str,
    ) -> Result<()> {
        let staging_name = unlocking_file_name(&record.path)?;
        let staging = parent.join(&staging_name);
        if staging.symlink_metadata().is_ok() {
            remove_path(&staging)?;
        }
        let args = command_args("x", archive_name, Some(&staging_name));
        if let Err(error) = run_interruptible(
            &self.seven_zip,
            &args,
            parent,
            passphrase,
            self.run_as,
            &self.stop_extract,
        ) {
            discard_path(&staging);
            return Err(error);
        }
        if let Err(error) = (|| {
            // fsync each extracted file before the rename. The parent fsync
            // after the rename makes the directory entry durable; it does not
            // flush file bytes that are still in the page cache.
            sync_tree(&staging)?;
            sync_dir(parent)?;
            Ok(())
        })() {
            discard_path(&staging);
            return Err(error);
        }
        fs::rename(&staging, &record.path)?;
        // Same ordering as lock: the new directory entry must be on disk
        // before the archive is deleted. Otherwise a power cut leaves only
        // .Name.lve-unlocking, and reconcile deletes it.
        sync_dir(parent)?;
        fs::remove_file(archive)?;
        sync_dir(parent)?;
        Ok(())
    }

    fn mark_immutable(&self, vault: &Path, set: bool) -> Result<()> {
        let parent = parent_dir(vault)?;
        let name = file_name(&archive_for(vault))?;
        let owner = self.owner_uid(&parent)?;
        match &self.flags {
            FlagBackend::Ioctl => immutable::change(&parent, &name, owner, set),
            FlagBackend::Record(calls) => {
                record_flag(calls, set);
                Ok(())
            }
            FlagBackend::Hook(hook) => hook(&archive_for(vault), set),
        }
    }

    /// `fstat` the descriptor a worker sent, then change the immutable bit.
    ///
    /// A recorded backend (tests) notes the change and does not call the ioctl.
    pub fn apply_flag_fd(&self, fd: std::os::fd::RawFd, owner: u32, set: bool) -> Result<()> {
        match &self.flags {
            FlagBackend::Ioctl => immutable::change_fd(fd, owner, set),
            FlagBackend::Record(calls) => {
                record_flag(calls, set);
                Ok(())
            }
            FlagBackend::Hook(_) => Ok(()),
        }
    }

    /// Register a folder the worker has already created and canonicalized.
    ///
    /// Does not open the path. The worker checked that it is inside the home.
    pub fn register_unlocked(&self, uid: u32, path: &Path) -> Result<Vault> {
        let name = vault_name(path)?;
        if path != self.allowed_root && !path.starts_with(&self.allowed_root) {
            return Err(Error::OutsideRoot);
        }
        self.write(|registry| {
            if archive_for(path).exists() {
                return Err(Error::AlreadyExists);
            }
            registry.insert(Record {
                uid,
                name: name.clone(),
                path: path.to_path_buf(),
                state: State::Unlocked,
                archive: None,
                immutable: true,
            })?;
            Ok(())
        })?;
        Ok(Vault {
            uid,
            name,
            path: path.to_path_buf(),
            state: State::Unlocked,
            immutable: true,
        })
    }

    /// Mark a lock as started. Does not look at the home directory.
    pub fn begin_lock(&self, uid: u32, name: &str) -> Result<(PathBuf, State)> {
        self.write(|registry| {
            let record = registry.get(uid, name)?.clone();
            match record.state {
                State::Unlocked | State::NeedsRecovery => {}
                state => {
                    return Err(Error::InvalidState {
                        state,
                        operation: "lock",
                    })
                }
            }
            registry.get_mut(uid, name)?.state = State::Locking;
            Ok((record.path, record.state))
        })
    }

    pub fn finish_lock(&self, uid: u32, name: &str, previous: State, ok: bool) -> Result<()> {
        self.write(|registry| {
            registry.get_mut(uid, name)?.state = if ok { State::Locked } else { previous };
            Ok(())
        })
    }

    pub fn begin_unlock(&self, uid: u32, name: &str) -> Result<PathBuf> {
        self.write(|registry| {
            let record = registry.get(uid, name)?.clone();
            if record.state != State::Locked {
                return Err(Error::InvalidState {
                    state: record.state,
                    operation: "unlock",
                });
            }
            registry.get_mut(uid, name)?.state = State::Unlocking;
            Ok(record.path)
        })
    }

    pub fn finish_unlock(&self, uid: u32, name: &str, ok: bool) -> Result<()> {
        self.write(|registry| {
            registry.get_mut(uid, name)?.state = if ok { State::Unlocked } else { State::Locked };
            Ok(())
        })
    }

    pub fn set_state(&self, uid: u32, name: &str, state: State) -> Result<()> {
        self.write(|registry| {
            registry.get_mut(uid, name)?.state = state;
            Ok(())
        })
    }

    /// Canonicalize `folder`, create it if needed, and refuse a path outside
    /// the allowed root. The worker calls this. It does not write the registry.
    pub fn resolve_folder(&self, folder: &Path) -> Result<PathBuf> {
        prepare_folder(folder, &self.allowed_root)
    }

    /// Pack a plaintext folder and return the archive's identity. Does not
    /// write the registry and does not delete the folder. The caller records
    /// the identity, then deletes the plaintext.
    pub fn pack_folder(&self, folder: &Path, passphrase: &[u8]) -> Result<ArchiveIdentity> {
        check_passphrase(passphrase)?;
        refuse_escaping_symlinks(folder)?;
        if archive_for(folder).exists() {
            return Err(Error::AlreadyExists);
        }
        let parent = parent_dir(folder)?;
        let record = Record {
            uid: 0,
            name: vault_name(folder)?,
            path: folder.to_path_buf(),
            state: State::Unlocked,
            archive: None,
            immutable: true,
        };
        self.pack(&record, &parent, passphrase)
    }

    /// Extract an archive over `folder`. Does not write the registry.
    pub fn unpack_folder(&self, folder: &Path, passphrase: &[u8]) -> Result<()> {
        check_passphrase(passphrase)?;
        if directory_occupied(folder)? {
            return Err(Error::AlreadyExists);
        }
        let record = Record {
            uid: 0,
            name: vault_name(folder)?,
            path: folder.to_path_buf(),
            state: State::Locked,
            archive: None,
            immutable: true,
        };
        self.extract(&record, passphrase)
    }

    /// Test a locked archive, clear the immutable flag, and delete it.
    pub fn remove_locked_archive(&self, folder: &Path, passphrase: &[u8]) -> Result<()> {
        check_passphrase(passphrase)?;
        self.test_archive(folder, passphrase)?;
        self.mark_immutable(folder, false)?;
        let archive = archive_for(folder);
        if let Err(error) = fs::remove_file(&archive) {
            let _ = self.mark_immutable(folder, true);
            return Err(error.into());
        }
        if let Some(parent) = archive.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }

    /// Ask the helper to set the immutable flag on the archive.
    pub fn seal_archive(&self, folder: &Path) -> Result<()> {
        self.mark_immutable(folder, true)
    }

    pub fn remove_plain_folder(&self, folder: &Path) -> Result<()> {
        if folder.exists() {
            fs::remove_dir_all(folder)?;
        }
        Ok(())
    }

    /// Delete staging, and delete the plaintext when both copies exist.
    ///
    /// The booleans describe what remains. The worker calls this. The helper
    /// writes the registry from the result.
    pub fn filename_facts(&self, folder: &Path) -> Result<FilenameFacts> {
        let parent = parent_dir(folder)?;
        let unlocking = parent.join(unlocking_file_name(folder)?);
        let partial = parent.join(partial_file_name(folder)?);
        if unlocking.symlink_metadata().is_ok() {
            remove_path(&unlocking)?;
        }
        if partial.symlink_metadata().is_ok() {
            remove_path(&partial)?;
        }
        let folder_exists = folder.is_dir();
        let occupied = folder_exists && directory_occupied(folder).unwrap_or(true);
        let archive_path = archive_for(folder);
        let archive = archive_path.is_file();
        let identity = if archive {
            ArchiveIdentity::capture(&archive_path).ok()
        } else {
            None
        };
        sync_dir(&parent)?;
        Ok(FilenameFacts {
            folder: folder_exists,
            archive,
            occupied,
            identity,
        })
    }

    /// The caller's uid when [`Self::for_user`] set one. Otherwise the owner of
    /// the archive's parent directory, which is how startup reconcile knows
    /// whose file it is putting the flag back on.
    fn owner_uid(&self, parent: &Path) -> Result<u32> {
        if let Some(user) = self.run_as {
            return Ok(user.uid);
        }
        Ok(fs::metadata(parent)?.uid())
    }

    /// Remove the vault's bytes and its registry entry.
    ///
    /// Locked: `passphrase` is required. `7z l` with no password must fail, then
    /// the archive is tested and deleted. An unencrypted archive is left in
    /// place, and so is the registry entry.
    /// Unlocked or needs recovery: pass `None`. The plaintext folder is deleted.
    /// This crate does not hold the unlocked passphrase, so it cannot check one.
    /// The registry entry is removed only after the bytes are gone.
    pub fn delete(&self, name: &str, passphrase: Option<&[u8]>) -> Result<()> {
        self.delete_contents(name, passphrase)?;
        self.unregister(self.owner_uid, name)
    }

    /// Delete the archive or the plaintext folder. The registry entry stays,
    /// so a crash before [`Self::unregister`] still names the vault.
    pub fn delete_contents(&self, name: &str, passphrase: Option<&[u8]>) -> Result<()> {
        let uid = self.owner_uid;
        let record = self.read(|registry| Ok(registry.get(uid, name)?.clone()))?;
        match (record.state, passphrase) {
            (State::Locked, Some(passphrase)) => {
                check_passphrase(passphrase)?;
                self.test_archive(&record.path, passphrase)?;
                self.mark_immutable(&record.path, false)?;
                let archive = archive_for(&record.path);
                if let Err(error) = fs::remove_file(&archive) {
                    let _ = self.mark_immutable(&record.path, true);
                    return Err(error.into());
                }
                if let Some(parent) = archive.parent() {
                    sync_dir(parent)?;
                }
            }
            (State::Locked, None) => {
                return Err(Error::InvalidState {
                    state: State::Locked,
                    operation: "delete without a passphrase",
                })
            }
            (State::Unlocked | State::NeedsRecovery, None) => {
                if record.path.exists() {
                    fs::remove_dir_all(&record.path)?;
                }
            }
            (State::Unlocked | State::NeedsRecovery, Some(_)) => {
                return Err(Error::InvalidState {
                    state: record.state,
                    operation: "delete with a passphrase (nothing is held to check it against)",
                })
            }
            (State::Locking | State::Unlocking, _) => {
                return Err(Error::InvalidState {
                    state: record.state,
                    operation: "delete",
                })
            }
        }
        Ok(())
    }

    /// Drop the registry entry. The folder, archive, and bookmark stay.
    pub fn unregister(&self, uid: u32, name: &str) -> Result<()> {
        self.write(|registry| {
            registry.remove(uid, name)?;
            Ok(())
        })
    }

    fn test_archive(&self, vault: &Path, passphrase: &[u8]) -> Result<()> {
        let parent = parent_dir(vault)?;
        let archive_name = file_name(&archive_for(vault))?;
        self.require_encrypted(&parent, &archive_name)?;
        let args = command_args("t", &archive_name, None);
        run(&self.seven_zip, &args, &parent, passphrase, self.run_as)
    }

    /// `7z l` with stdin closed. Success means the archive is not encrypted,
    /// so a later test result is not used.
    fn require_encrypted(&self, parent: &Path, archive_name: &str) -> Result<()> {
        let args = command_args("l", archive_name, None);
        match run_without_passphrase(&self.seven_zip, &args, parent, self.run_as) {
            Ok(()) => Err(Error::NotEncrypted),
            Err(Error::SevenZip { .. } | Error::WrongPassphrase { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read `registry.json` while holding its `flock`. The lock is released
    /// before this returns.
    fn read<T>(&self, body: impl FnOnce(&Registry) -> Result<T>) -> Result<T> {
        let _gate = self
            .registry_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _file = LockFile::acquire(&self.registry_dir)?;
        let registry = Registry::load(&self.registry_dir)?;
        body(&registry)
    }

    /// Rewrite `registry.json` while holding its `flock`. The lock is released
    /// before this returns. Callers run `7z` outside this function.
    fn write<T>(&self, body: impl FnOnce(&mut Registry) -> Result<T>) -> Result<T> {
        let _gate = self
            .registry_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _file = LockFile::acquire(&self.registry_dir)?;
        let mut registry = Registry::load(&self.registry_dir)?;
        let value = body(&mut registry)?;
        registry.save()?;
        Ok(value)
    }
}

fn record_flag(calls: &Mutex<Vec<FlagChange>>, set: bool) {
    calls
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(if set {
            FlagChange::Set
        } else {
            FlagChange::Clear
        });
}

/// What remains of a vault after the worker's filename check.
pub struct FilenameFacts {
    pub folder: bool,
    pub archive: bool,
    /// The folder exists and has at least one directory entry.
    pub occupied: bool,
    pub identity: Option<ArchiveIdentity>,
}

impl From<&Record> for Vault {
    fn from(record: &Record) -> Self {
        Self {
            uid: record.uid,
            name: record.name.clone(),
            path: record.path.clone(),
            state: record.state,
            immutable: record.immutable,
        }
    }
}

fn directory_occupied(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    if !path.is_dir() {
        return Ok(true);
    }
    Ok(fs::read_dir(path)?.next().is_some())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn check_passphrase(passphrase: &[u8]) -> Result<()> {
    if passphrase.is_empty() {
        return Err(Error::InvalidPassphrase("empty"));
    }
    if passphrase.contains(&0) {
        return Err(Error::InvalidPassphrase("contains a NUL byte"));
    }
    if passphrase.contains(&b'\n') || passphrase.contains(&b'\r') {
        return Err(Error::InvalidPassphrase("contains CR or LF"));
    }
    Ok(())
}

fn prepare_folder(folder: &Path, allowed_root: &Path) -> Result<PathBuf> {
    let path = if folder.exists() {
        folder.canonicalize()?
    } else {
        let parent = folder.parent().ok_or(Error::OutsideRoot)?;
        if !parent.exists() {
            return Err(Error::OutsideRoot);
        }
        let parent = parent.canonicalize()?;
        if parent != allowed_root && !parent.starts_with(allowed_root) {
            return Err(Error::OutsideRoot);
        }
        fs::create_dir(folder)?;
        folder.canonicalize()?
    };
    if path == allowed_root || !path.starts_with(allowed_root) {
        return Err(Error::OutsideRoot);
    }
    if !path.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "vault path is not a directory",
        )));
    }
    Ok(path)
}

fn refuse_escaping_symlinks(vault: &Path) -> Result<()> {
    let mut stack = vec![vault.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_symlink() {
                let target = path.canonicalize().map_err(|_| Error::EscapingSymlink)?;
                if !target.starts_with(vault) {
                    return Err(Error::EscapingSymlink);
                }
            } else if path.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

fn archive_for(vault: &Path) -> PathBuf {
    let name = archive_file_name(vault).unwrap_or_default();
    vault.parent().unwrap_or_else(|| Path::new(".")).join(name)
}

fn archive_file_name(vault: &Path) -> Result<String> {
    Ok(format!("{}.7z", file_name(vault)?))
}

fn partial_file_name(vault: &Path) -> Result<String> {
    Ok(format!("{}.lve-partial", archive_file_name(vault)?))
}

fn unlocking_file_name(vault: &Path) -> Result<String> {
    Ok(format!(".{}.lve-unlocking", file_name(vault)?))
}

fn parent_dir(path: &Path) -> Result<PathBuf> {
    path.parent()
        .map(Path::to_path_buf)
        .ok_or(Error::OutsideRoot)
}

fn vault_name(path: &Path) -> Result<String> {
    file_name(path)
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "vault file name is not UTF-8",
            ))
        })
}

fn remove_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn discard_path(path: &Path) {
    let _ = remove_path(path);
}

fn sync_file(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    // fsync of the directory that holds the renamed entry, not of the file.
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_tree(root: &Path) -> Result<()> {
    // A file's bytes are synced on the file. Its name lives in the directory
    // that contains it, so each directory is synced too.
    sync_dir(root)?;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_symlink() {
                continue;
            }
            if path.is_dir() {
                sync_dir(&path)?;
                stack.push(path);
            } else if path.is_file() {
                sync_file(&path)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn add_command_has_the_required_switches_and_not_the_passphrase() {
        let args = super::add_command("Vault.7z", b"secret").unwrap();
        assert_eq!(
            args,
            ["a", "-p", "-mhe=on", "-mx=0", "-y", "-bd", "--", "Vault.7z"]
        );
        assert!(super::add_command("Vault.7z", b"").is_err());
        let passphrase = "secret passphrase";
        assert!(args.iter().all(|arg| !arg.contains(passphrase)));
    }

    #[test]
    fn test_and_extract_commands_answer_yes_and_hide_progress() {
        assert_eq!(
            super::command_args("t", "Vault.7z", None),
            ["t", "-y", "-bd", "--", "Vault.7z"]
        );
        assert_eq!(
            super::command_args("x", "Vault.7z", Some(".Vault.lve-unlocking")),
            ["x", "-y", "-bd", "-o.Vault.lve-unlocking", "--", "Vault.7z"]
        );
        assert_eq!(
            super::command_args("l", "Vault.7z.lve-partial", None),
            ["l", "-y", "-bd", "--", "Vault.7z.lve-partial"]
        );
    }

    #[test]
    fn passphrase_rules() {
        assert!(super::check_passphrase(b" secret ").is_ok());
        assert!(super::check_passphrase(b"").is_err());
        assert!(super::check_passphrase(b"a\nb").is_err());
        assert!(super::check_passphrase(b"a\rb").is_err());
        assert!(super::check_passphrase(b"a\0b").is_err());
    }
}
