//! The immutable flag, changed with `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS`.
//!
//! The archive is opened `O_RDONLY|O_NOFOLLOW` from a descriptor for its parent
//! directory. `fstat` has to show a regular file owned by the caller before
//! the immutable bit is the only flag that changes.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::{Error, Result};

/// `FS_IMMUTABLE_FL` from `linux/fs.h`. libc does not export it.
const FS_IMMUTABLE_FL: libc::c_long = 0x10;

/// Flip only `FS_IMMUTABLE_FL` in a flags word from `FS_IOC_GETFLAGS`.
pub(crate) fn apply_immutable(flags: libc::c_long, set: bool) -> libc::c_long {
    let bit = FS_IMMUTABLE_FL;
    if set {
        flags | bit
    } else {
        flags & !bit
    }
}

#[cfg(test)]
fn is_set(parent: &Path, file_name: &str) -> Result<bool> {
    let directory = open_directory(parent)?;
    let file = open_nofollow(directory.as_raw_fd(), file_name)?;
    let flags = get_flags(file.as_raw_fd())?;
    Ok((flags & FS_IMMUTABLE_FL) != 0)
}

/// Set or clear the immutable bit on `file_name` in `parent`.
pub(crate) fn change(parent: &Path, file_name: &str, owner: u32, set: bool) -> Result<()> {
    let directory = open_directory(parent)?;
    let file = open_nofollow(directory.as_raw_fd(), file_name)?;
    let info = stat_fd(file.as_raw_fd())?;
    let regular = info.st_mode & libc::S_IFMT == libc::S_IFREG;
    if !regular || info.st_uid != owner {
        return Err(Error::UnexpectedFile);
    }
    let mut flags = get_flags(file.as_raw_fd())?;
    flags = apply_immutable(flags, set);
    set_flags(file.as_raw_fd(), flags)
}

fn open_directory(path: &Path) -> Result<OwnedFd> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path contains NUL",
        ))
    })?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    owned(fd)
}

fn open_nofollow(dir: libc::c_int, file_name: &str) -> Result<OwnedFd> {
    let name = CString::new(file_name).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "archive name contains NUL",
        ))
    })?;
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned(fd)
}

fn owned(fd: libc::c_int) -> Result<OwnedFd> {
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Set or clear the immutable bit on an archive the worker already opened.
///
/// `fstat` must show a regular file owned by `owner`. The helper calls this
/// on a descriptor received with `SCM_RIGHTS`. It does not open the path.
pub fn change_fd(fd: libc::c_int, owner: u32, set: bool) -> Result<()> {
    let info = stat_fd(fd)?;
    let regular = info.st_mode & libc::S_IFMT == libc::S_IFREG;
    if !regular || info.st_uid != owner {
        return Err(Error::UnexpectedFile);
    }
    let mut flags = get_flags(fd)?;
    flags = apply_immutable(flags, set);
    set_flags(fd, flags)
}

fn stat_fd(fd: libc::c_int) -> Result<libc::stat> {
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut info) };
    if rc != 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(info)
}

fn get_flags(fd: libc::c_int) -> Result<libc::c_long> {
    let mut flags: libc::c_long = 0;
    let rc = unsafe { libc::ioctl(fd, libc::FS_IOC_GETFLAGS, &mut flags) };
    if rc != 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(flags)
}

fn set_flags(fd: libc::c_int, flags: libc::c_long) -> Result<()> {
    let rc = unsafe { libc::ioctl(fd, libc::FS_IOC_SETFLAGS, &flags) };
    if rc != 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    use super::{apply_immutable, change, is_set};
    use crate::Error;

    #[test]
    fn only_the_immutable_bit_changes() {
        let other = 0x20;
        assert_eq!(apply_immutable(other, true), other | 0x10);
        assert_eq!(apply_immutable(other | 0x10, false), other);
        assert_eq!(apply_immutable(0, false), 0);
    }

    #[test]
    fn a_symlink_or_a_different_owner_is_not_changed() {
        let dir = std::env::temp_dir().join(format!("linux-vault-flag-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Forge.7z"), b"archive").unwrap();
        let owner = fs::metadata(dir.join("Forge.7z")).unwrap().uid();
        let wrong = change(&dir, "Forge.7z", owner.wrapping_add(1), true).unwrap_err();
        assert!(matches!(wrong, Error::UnexpectedFile), "{wrong}");

        std::os::unix::fs::symlink("Forge.7z", dir.join("link")).unwrap();
        let followed = change(&dir, "link", owner, true).unwrap_err();
        assert!(matches!(followed, Error::Io(_)), "{followed}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_can_set_and_clear_the_immutable_bit() {
        if !can_change_immutable() {
            return;
        }
        let dir =
            std::env::temp_dir().join(format!("linux-vault-flag-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Forge.7z"), b"archive").unwrap();
        let owner = fs::metadata(dir.join("Forge.7z")).unwrap().uid();
        change(&dir, "Forge.7z", owner, true).unwrap();
        assert!(is_set(&dir, "Forge.7z").unwrap());
        change(&dir, "Forge.7z", owner, false).unwrap();
        assert!(!is_set(&dir, "Forge.7z").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    fn can_change_immutable() -> bool {
        const CAP_LINUX_IMMUTABLE: u64 = 1 << 9;
        let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
        let root = status
            .lines()
            .any(|line| line.starts_with("Uid:") && line.contains("\t0\t"));
        let cap = status
            .lines()
            .find(|line| line.starts_with("CapEff:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .unwrap_or(0);
        root && cap & CAP_LINUX_IMMUTABLE != 0
    }
}
