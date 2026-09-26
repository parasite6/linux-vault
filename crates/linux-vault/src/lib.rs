//! Lock, test, delete, and unlock a folder with 7z, and remember that in a registry.
//!
//! The passphrase is borrowed bytes. This crate does not start pinentry, talk on
//! D-Bus, set the immutable flag, or drop privileges. Run it as the vault owner.
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
mod registry;
mod sevenz;

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use error::Result;
use registry::{LockFile, Record, Registry};
use sevenz::{command_args, find_seven_zip, run, run_without_passphrase};

pub use error::Error;

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
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            State::Unlocked => "unlocked",
            State::Locked => "locked",
            State::NeedsRecovery => "needs recovery",
        })
    }
}

/// A registered vault. `path` is the plaintext folder, present or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub name: String,
    pub path: PathBuf,
    pub state: State,
}

/// Registry plus the 7z operations that move a vault between folder and archive.
pub struct Vaults {
    registry_dir: PathBuf,
    allowed_root: PathBuf,
    seven_zip: PathBuf,
}

impl Vaults {
    /// Open a registry. Creates `registry_dir` if it is missing.
    ///
    /// `allowed_root` is the directory every vault must resolve inside.
    /// This does not reconcile. Call [`Self::reconcile`] once at process start.
    pub fn open(registry_dir: impl Into<PathBuf>, allowed_root: impl AsRef<Path>) -> Result<Self> {
        let registry_dir = registry_dir.into();
        fs::create_dir_all(&registry_dir)?;
        let allowed_root = allowed_root.as_ref().canonicalize()?;
        Ok(Self {
            registry_dir,
            allowed_root,
            seven_zip: find_seven_zip()?,
        })
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
        let (_lock, mut registry) = self.locked()?;
        registry.insert(Record {
            name: name.clone(),
            path: path.clone(),
            state: State::Unlocked,
        })?;
        registry.save()?;
        Ok(Vault {
            name,
            path,
            state: State::Unlocked,
        })
    }

    pub fn list(&self) -> Result<Vec<Vault>> {
        let (_lock, registry) = self.locked()?;
        Ok(registry.iter().map(Vault::from).collect())
    }

    pub fn get(&self, name: &str) -> Result<Vault> {
        let (_lock, registry) = self.locked()?;
        registry.get(name).map(Vault::from)
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
    /// - Folder only, or neither: needs recovery.
    pub fn reconcile(&self) -> Result<Vec<Vault>> {
        let (_lock, mut registry) = self.locked()?;
        let names: Vec<String> = registry.iter().map(|record| record.name.clone()).collect();
        for name in names {
            let record = registry.get(&name)?.clone();
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
            let archive = archive_for(&record.path).is_file();
            let state = match (folder, archive) {
                (true, true) => {
                    fs::remove_dir_all(&record.path)?;
                    State::Locked
                }
                (false, true) => State::Locked,
                _ => State::NeedsRecovery,
            };
            sync_dir(&parent)?;
            registry.get_mut(&name)?.state = state;
        }
        registry.save()?;
        Ok(registry.iter().map(Vault::from).collect())
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
        let (_lock, mut registry) = self.locked()?;
        let record = registry.get(name)?.clone();
        match record.state {
            State::Unlocked | State::NeedsRecovery => {}
            State::Locked => {
                return Err(Error::InvalidState {
                    state: record.state,
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
        let final_path = archive_for(&record.path);
        if final_path.exists() {
            return Err(Error::AlreadyExists);
        }
        let partial_name = partial_file_name(&record.path)?;
        let partial_path = parent.join(&partial_name);
        if partial_path.symlink_metadata().is_ok() {
            remove_path(&partial_path)?;
        }

        let archive_arg = format!("../{partial_name}");
        let mut args = command_args("a", &archive_arg, None);
        args.push(".".to_string());
        if let Err(error) = run(&self.seven_zip, &args, &record.path, passphrase) {
            discard_path(&partial_path);
            return Err(error);
        }

        let checked = (|| {
            sync_file(&partial_path)?;
            sync_dir(&parent)?;
            self.require_encrypted(&parent, &partial_name)?;
            let test_args = command_args("t", &partial_name, None);
            run(&self.seven_zip, &test_args, &parent, passphrase)?;
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
        sync_dir(&parent)?;
        fs::remove_dir_all(&record.path)?;
        sync_dir(&parent)?;
        registry.get_mut(name)?.state = State::Locked;
        registry.save()?;
        Ok(())
    }

    /// Test the archive with `7z t`. Does not change the vault.
    pub fn test(&self, name: &str, passphrase: &[u8]) -> Result<()> {
        check_passphrase(passphrase)?;
        let (_lock, registry) = self.locked()?;
        let record = registry.get(name)?.clone();
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
        let (_lock, mut registry) = self.locked()?;
        let record = registry.get(name)?.clone();
        if record.state != State::Locked {
            return Err(Error::InvalidState {
                state: record.state,
                operation: "unlock",
            });
        }
        if record.path.exists() {
            return Err(Error::AlreadyExists);
        }
        let archive = archive_for(&record.path);
        if !archive.is_file() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "vault archive is missing",
            )));
        }
        let parent = parent_dir(&record.path)?;
        let archive_name = file_name(&archive)?;
        let staging_name = unlocking_file_name(&record.path)?;
        let staging = parent.join(&staging_name);
        if staging.symlink_metadata().is_ok() {
            remove_path(&staging)?;
        }
        let args = command_args("x", &archive_name, Some(&staging_name));
        if let Err(error) = run(&self.seven_zip, &args, &parent, passphrase) {
            discard_path(&staging);
            return Err(error);
        }
        if let Err(error) = (|| {
            // fsync each extracted file before the rename. The parent fsync
            // after the rename makes the directory entry durable; it does not
            // flush file bytes that are still in the page cache.
            sync_tree(&staging)?;
            sync_dir(&parent)?;
            Ok(())
        })() {
            discard_path(&staging);
            return Err(error);
        }
        fs::rename(&staging, &record.path)?;
        // Same ordering as lock: the new directory entry must be on disk
        // before the archive is deleted. Otherwise a power cut leaves only
        // .Name.lve-unlocking, and reconcile deletes it.
        sync_dir(&parent)?;
        fs::remove_file(&archive)?;
        sync_dir(&parent)?;
        registry.get_mut(name)?.state = State::Unlocked;
        registry.save()?;
        Ok(())
    }

    /// Remove the vault's bytes and its registry entry.
    ///
    /// Locked: `passphrase` is required. `7z l` with no password must fail, then
    /// the archive is tested and deleted. An unencrypted archive is left in
    /// place, and so is the registry entry.
    /// Unlocked or needs recovery: pass `None`. The plaintext folder is deleted.
    /// This crate does not hold the unlocked passphrase, so it cannot check one.
    pub fn delete(&self, name: &str, passphrase: Option<&[u8]>) -> Result<()> {
        let (_lock, mut registry) = self.locked()?;
        let record = registry.get(name)?.clone();
        match (record.state, passphrase) {
            (State::Locked, Some(passphrase)) => {
                check_passphrase(passphrase)?;
                self.test_archive(&record.path, passphrase)?;
                let archive = archive_for(&record.path);
                fs::remove_file(&archive)?;
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
        }
        registry.remove(name)?;
        registry.save()?;
        Ok(())
    }

    fn test_archive(&self, vault: &Path, passphrase: &[u8]) -> Result<()> {
        let parent = parent_dir(vault)?;
        let archive_name = file_name(&archive_for(vault))?;
        self.require_encrypted(&parent, &archive_name)?;
        let args = command_args("t", &archive_name, None);
        run(&self.seven_zip, &args, &parent, passphrase)
    }

    /// `7z l` with stdin closed. Success means the archive is not encrypted,
    /// so a later test result is not used.
    fn require_encrypted(&self, parent: &Path, archive_name: &str) -> Result<()> {
        let args = command_args("l", archive_name, None);
        match run_without_passphrase(&self.seven_zip, &args, parent) {
            Ok(()) => Err(Error::NotEncrypted),
            Err(Error::SevenZip { .. } | Error::WrongPassphrase { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn locked(&self) -> Result<(LockFile, Registry)> {
        let lock = LockFile::acquire(&self.registry_dir)?;
        let registry = Registry::load(&self.registry_dir)?;
        Ok((lock, registry))
    }
}

impl From<&Record> for Vault {
    fn from(record: &Record) -> Self {
        Self {
            name: record.name.clone(),
            path: record.path.clone(),
            state: record.state,
        }
    }
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
        let args = super::command_args("a", "Vault.7z", None);
        assert_eq!(
            args,
            ["a", "-p", "-mhe=on", "-mx=0", "-y", "-bd", "--", "Vault.7z"]
        );
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
