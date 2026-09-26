use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::sync_dir;
use crate::State;

const FILE_NAME: &str = "registry.json";
const LOCK_NAME: &str = ".lock";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub path: PathBuf,
    pub state: State,
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
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.lock()?;
        Ok(Self { file })
    }
}

impl Registry {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(FILE_NAME);
        if !path.exists() {
            return Ok(Self {
                path,
                vaults: Vec::new(),
            });
        }
        let mut file = File::open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let body: FileBody =
            serde_json::from_slice(&bytes).map_err(|error| Error::Registry(error.to_string()))?;
        if body.version != 1 {
            return Err(Error::Registry(format!(
                "unsupported registry version {}",
                body.version
            )));
        }
        Ok(Self {
            path,
            vaults: body.vaults,
        })
    }

    pub fn save(&self) -> Result<()> {
        let body = FileBody {
            version: 1,
            vaults: self.vaults.clone(),
        };
        let data =
            serde_json::to_vec_pretty(&body).map_err(|error| Error::Registry(error.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = File::create(&tmp)?;
            file.write_all(&data)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.vaults.iter()
    }

    pub fn get(&self, name: &str) -> Result<&Record> {
        self.vaults
            .iter()
            .find(|record| record.name == name)
            .ok_or(Error::NotFound)
    }

    pub fn get_mut(&mut self, name: &str) -> Result<&mut Record> {
        self.vaults
            .iter_mut()
            .find(|record| record.name == name)
            .ok_or(Error::NotFound)
    }

    pub fn insert(&mut self, record: Record) -> Result<()> {
        if self
            .vaults
            .iter()
            .any(|existing| existing.name == record.name)
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
        self.vaults.push(record);
        self.vaults.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<Record> {
        let index = self
            .vaults
            .iter()
            .position(|record| record.name == name)
            .ok_or(Error::NotFound)?;
        Ok(self.vaults.remove(index))
    }
}
