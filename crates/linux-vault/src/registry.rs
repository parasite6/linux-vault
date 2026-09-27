use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::sync_dir;
use crate::State;

const FILE_NAME: &str = "registry.json";
const LOCK_NAME: &str = ".lock";
const DAMAGED_NAME: &str = "registry.damaged";

/// How a new folder sits relative to a vault the caller already owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nesting {
    /// The new folder is under the other vault.
    Inside,
    /// The new folder is an ancestor of the other vault.
    Contains,
}

/// Identity of the archive this vault wrote. Reconcile deletes the plaintext
/// folder only when `Name.7z` still matches.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveIdentity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
}

impl ArchiveIdentity {
    pub fn capture(path: &Path) -> std::io::Result<Self> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive is not a regular file",
            ));
        }
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        })
    }

    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..8].copy_from_slice(&self.dev.to_le_bytes());
        out[8..16].copy_from_slice(&self.ino.to_le_bytes());
        out[16..24].copy_from_slice(&self.size.to_le_bytes());
        out[24..32].copy_from_slice(&self.mtime_sec.to_le_bytes());
        out[32..40].copy_from_slice(&self.mtime_nsec.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        Some(Self {
            dev: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            ino: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            size: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
            mtime_sec: i64::from_le_bytes(bytes[24..32].try_into().ok()?),
            mtime_nsec: i64::from_le_bytes(bytes[32..40].try_into().ok()?),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub uid: u32,
    pub name: String,
    pub path: PathBuf,
    pub state: State,
    /// Set after the lock rename and directory sync, before the plaintext is deleted.
    #[serde(default)]
    pub archive: Option<ArchiveIdentity>,
    /// False when the archive is locked but the immutable flag could not be set.
    /// Missing on older files, which are treated as protected until a seal fails.
    #[serde(default = "protected_by_default")]
    pub immutable: bool,
}

fn protected_by_default() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
struct FileBody {
    version: u32,
    vaults: Vec<Record>,
}

pub struct Registry {
    path: PathBuf,
    vaults: Vec<Record>,
}

/// Exclusive `flock` on `.lock`. The kernel drops it when this file is closed
/// or the process dies. The file itself stays, so the next caller locks the
/// same inode.
pub struct LockFile {
    file: File,
}

impl Drop for LockFile {
    fn drop(&mut self) {
        // Closing `file` is what releases the flock.
        let _open_until_drop = &self.file;
    }
}

impl LockFile {
    pub fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        restrict(&path);
        file.lock()?;
        Ok(Self { file })
    }
}

impl Registry {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(FILE_NAME);
        if let Some(note) = damaged_note(dir) {
            return Err(Error::RegistryDamaged(note));
        }
        if !path.exists() {
            return Ok(Self {
                path,
                vaults: Vec::new(),
            });
        }
        restrict(&path);
        let mut file = File::open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let body = serde_json::from_slice::<FileBody>(&bytes);
        let vaults = match body {
            Ok(body) if body.version == 2 => body.vaults,
            _ => {
                let broken = quarantine(&path)?;
                let note = damage_message(&broken);
                eprintln!("<3>linux-vault: {note}");
                let _ = fs::write(dir.join(DAMAGED_NAME), format!("{}\n", broken.display()));
                return Err(Error::RegistryDamaged(note));
            }
        };
        Ok(Self { path, vaults })
    }

    pub fn save(&self) -> Result<()> {
        let body = FileBody {
            version: 2,
            vaults: self.vaults.clone(),
        };
        let data =
            serde_json::to_vec_pretty(&body).map_err(|error| Error::Registry(error.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            restrict(&tmp);
            file.write_all(&data)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        restrict(&self.path);
        if let Some(parent) = self.path.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.vaults.iter()
    }

    pub fn get(&self, uid: u32, name: &str) -> Result<&Record> {
        self.vaults
            .iter()
            .find(|record| record.uid == uid && record.name == name)
            .ok_or(Error::NotFound)
    }

    pub fn get_mut(&mut self, uid: u32, name: &str) -> Result<&mut Record> {
        self.vaults
            .iter_mut()
            .find(|record| record.uid == uid && record.name == name)
            .ok_or(Error::NotFound)
    }

    pub fn insert(&mut self, record: Record) -> Result<()> {
        if self
            .vaults
            .iter()
            .any(|existing| existing.uid == record.uid && existing.name == record.name)
        {
            return Err(Error::AlreadyExists);
        }
        if self
            .vaults
            .iter()
            .any(|existing| existing.path == record.path)
        {
            return Err(Error::AlreadyExists);
        }
        let new_path = canonical_path(&record.path);
        if self.vaults.iter().any(|existing| {
            existing.uid == record.uid && canonical_path(&existing.path) == new_path
        }) {
            return Err(Error::AlreadyExists);
        }
        if let Some((other, nesting)) = self.vaults.iter().find_map(|existing| {
            if existing.uid != record.uid {
                return None;
            }
            nesting_between(&existing.path, &record.path)
                .map(|nesting| (existing.name.clone(), nesting))
        }) {
            return Err(Error::Nested {
                name: record.name,
                other,
                nesting,
            });
        }
        self.vaults.push(record);
        self.vaults.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(())
    }

    pub fn remove(&mut self, uid: u32, name: &str) -> Result<Record> {
        let index = self
            .vaults
            .iter()
            .position(|record| record.uid == uid && record.name == name)
            .ok_or(Error::NotFound)?;
        Ok(self.vaults.remove(index))
    }
}

fn restrict(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

/// `Some` when `new_path` is inside `existing`, or contains it.
///
/// Comparison is by whole path component after each existing prefix is
/// canonicalized. `Forge` and `Forge2` share a name prefix and are not nested.
pub(crate) fn nesting_between(existing: &Path, new_path: &Path) -> Option<Nesting> {
    let existing = canonical_path(existing);
    let new_path = canonical_path(new_path);
    if existing == new_path {
        return None;
    }
    if new_path.starts_with(&existing) {
        Some(Nesting::Inside)
    } else if existing.starts_with(&new_path) {
        Some(Nesting::Contains)
    } else {
        None
    }
}

pub fn vaults_are_nested(left: &Path, right: &Path) -> bool {
    nesting_between(left, right).is_some()
}

/// Resolve symlinks in the longest existing prefix, then keep the remaining
/// components. A locked vault's folder is gone, so the final component stays.
fn canonical_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => {
                let next = out.join(part);
                match fs::canonicalize(&next) {
                    Ok(canon) => out = canon,
                    Err(_) => out = next,
                }
            }
        }
    }
    out
}

fn damage_message(kept: &Path) -> String {
    format!(
        "the vault registry is damaged; {} was kept aside. Restore or fix that file, then restart the helper",
        kept.display()
    )
}

fn damaged_note(dir: &Path) -> Option<String> {
    let path = dir.join(DAMAGED_NAME);
    let text = fs::read_to_string(&path).ok()?;
    let kept = text.trim();
    if kept.is_empty() {
        return None;
    }
    Some(damage_message(Path::new(kept)))
}

fn quarantine(path: &Path) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let broken = parent.join(format!("registry.json.broken-{stamp}"));
    fs::rename(path, &broken)?;
    Ok(broken)
}

#[cfg(test)]
mod nest_tests {
    use std::path::Path;

    use super::{nesting_between, Nesting};

    #[test]
    fn a_shared_name_prefix_is_not_nested() {
        let forge = Path::new("/var/tmp/lve-nest-check/Forge");
        let forge2 = Path::new("/var/tmp/lve-nest-check/Forge2");
        assert!(nesting_between(forge, forge2).is_none());
        assert!(nesting_between(forge2, forge).is_none());
        let inner = Path::new("/var/tmp/lve-nest-check/Forge/Inner");
        assert_eq!(nesting_between(forge, inner), Some(Nesting::Inside));
        assert_eq!(nesting_between(inner, forge), Some(Nesting::Contains));
    }
}
