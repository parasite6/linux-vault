//! Open files inside a vault, seen from `/proc`.
//!
//! A normal lock refuses when a file, a mapping, or a working directory inside
//! the vault is actually found open. The error names that process. The worker
//! scans the vault owner's processes. The helper scans root's. Any other uid
//! is skipped. A process that cannot be read, or that is not dumpable, is
//! skipped and logged at debug level. That skip never refuses the lock.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::HelperError;

const CAP_SYS_PTRACE: u64 = 19;
/// `PF_KTHREAD` in `/proc/<pid>/stat`. Kernel threads have no user files.
const PF_KTHREAD: u64 = 0x0020_0000;

struct Holder {
    pid: u32,
    name: String,
    what: String,
}

enum Miss {
    /// The process exited, or this one `/proc` entry is already gone.
    Gone,
    /// `EACCES` or `EPERM`, including a process that is not dumpable.
    Denied,
    /// Some other read error. Not a reason to refuse the lock.
    Other,
}

/// How the open-file scan reads `/proc`. Tests hand this a stand-in.
trait ProcFs {
    fn read_dir(&self, path: &Path) -> std::io::Result<Vec<std::io::Result<ProcEntry>>>;
    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf>;
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
}

struct ProcEntry {
    name: std::ffi::OsString,
    path: PathBuf,
}

struct HostFs;

impl ProcFs for HostFs {
    fn read_dir(&self, path: &Path) -> std::io::Result<Vec<std::io::Result<ProcEntry>>> {
        let mut listed = Vec::new();
        for entry in fs::read_dir(path)? {
            listed.push(match entry {
                Ok(entry) => Ok(ProcEntry {
                    name: entry.file_name(),
                    path: entry.path(),
                }),
                Err(error) => Err(error),
            });
        }
        Ok(listed)
    }

    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }
}

/// Refuse when a process of `uid` has a file, a mapping, or a working directory
/// inside `vault`. Other uids are ignored. `vault_name` is the name in the error.
pub fn refuse_if_open(vault: &Path, vault_name: &str, uid: u32) -> Result<(), HelperError> {
    scan(Path::new("/proc"), vault, vault_name, uid, &HostFs)
}

fn scan(
    proc_root: &Path,
    vault: &Path,
    vault_name: &str,
    uid: u32,
    files: &dyn ProcFs,
) -> Result<(), HelperError> {
    let vault = match vault.canonicalize() {
        Ok(path) => path,
        // A mode 700 home is not readable as root without CAP_DAC_OVERRIDE.
        // The stored path was canonicalized by the worker.
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied && vault.is_absolute() =>
        {
            vault.to_path_buf()
        }
        Err(error) => {
            return Err(HelperError::Failed(format!(
                "cannot resolve the vault path: {error}"
            )))
        }
    };
    let mut holders = Vec::new();
    let entries = files.read_dir(proc_root).map_err(|error| {
        HelperError::Failed(format!("cannot read {}: {error}", proc_root.display()))
    })?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = pid_from(&entry.name) else {
            continue;
        };
        let dir = entry.path;
        if is_kernel_thread(files, &dir) {
            continue;
        }
        // The worker passes the owner's uid. The helper passes root's.
        // Everyone else is skipped, including a process whose uid cannot be read.
        if process_uid(files, &dir) != Some(uid) {
            continue;
        }
        match inspect(files, &dir, pid, &vault) {
            Ok(Some(holder)) => holders.push(holder),
            Ok(None) => {}
            Err(Miss::Gone | Miss::Other) => {}
            Err(Miss::Denied) => {
                debug_skip(pid, &process_name(files, &dir));
            }
        }
    }
    if !holders.is_empty() {
        holders.sort_by_key(|holder| holder.pid);
        holders.dedup_by_key(|holder| holder.pid);
        return Err(HelperError::Failed(busy_message(vault_name, &holders)));
    }
    Ok(())
}

fn debug_skip(pid: u32, name: &str) {
    let show = std::env::var("RUST_LOG")
        .ok()
        .is_some_and(|value| value.to_ascii_lowercase().contains("debug"));
    if show {
        eprintln!(
            "linux-vault-helper: debug: open-file scan skipped {name} (pid {pid}): permission denied or not dumpable"
        );
    }
}

fn inspect(files: &dyn ProcFs, dir: &Path, pid: u32, vault: &Path) -> Result<Option<Holder>, Miss> {
    let mut denied = false;
    for found in [
        scan_fds(files, dir, vault),
        scan_maps(files, dir, vault),
        scan_cwd(files, dir, vault),
    ] {
        match found {
            Ok(Some(path)) => return Ok(Some(holder(files, dir, pid, vault, &path))),
            Ok(None) => {}
            Err(Miss::Gone) => return Err(Miss::Gone),
            Err(Miss::Denied) => denied = true,
            Err(Miss::Other) => {}
        }
    }
    if denied {
        Err(Miss::Denied)
    } else {
        Ok(None)
    }
}

fn scan_fds(files: &dyn ProcFs, dir: &Path, vault: &Path) -> Result<Option<PathBuf>, Miss> {
    let entries = match files.read_dir(&dir.join("fd")) {
        Ok(entries) => entries,
        Err(error) => return Err(classify(&error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| classify(&error))?;
        match files.read_link(&entry.path) {
            Ok(target) => {
                let target = opened_path(&target);
                if is_inside(vault, &target) {
                    return Ok(Some(target));
                }
            }
            Err(error) if is_exited(&error) => return Err(Miss::Gone),
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(classify(&error)),
        }
    }
    Ok(None)
}

fn scan_maps(files: &dyn ProcFs, dir: &Path, vault: &Path) -> Result<Option<PathBuf>, Miss> {
    let text = match files.read_to_string(&dir.join("maps")) {
        Ok(text) => text,
        Err(error) => return Err(classify(&error)),
    };
    for line in text.lines() {
        let Some(path) = mapped_path(line) else {
            continue;
        };
        let path = opened_path(Path::new(path));
        if is_inside(vault, &path) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn scan_cwd(files: &dyn ProcFs, dir: &Path, vault: &Path) -> Result<Option<PathBuf>, Miss> {
    match files.read_link(&dir.join("cwd")) {
        Ok(path) => {
            let path = opened_path(&path);
            if is_inside(vault, &path) {
                Ok(Some(path))
            } else {
                Ok(None)
            }
        }
        Err(error) => Err(classify(&error)),
    }
}

fn holder(files: &dyn ProcFs, dir: &Path, pid: u32, vault: &Path, path: &Path) -> Holder {
    Holder {
        pid,
        name: process_name(files, dir),
        what: label(vault, path),
    }
}

fn busy_message(vault_name: &str, holders: &[Holder]) -> String {
    if holders.len() == 1 {
        let holder = &holders[0];
        return format!(
            "cannot lock {vault_name}: {} is open in {} (pid {})",
            holder.what, holder.name, holder.pid
        );
    }
    let shown = holders.len().min(8);
    let names = holders[..shown]
        .iter()
        .map(|holder| format!("{} (pid {})", holder.name, holder.pid))
        .collect::<Vec<_>>()
        .join(", ");
    let extra = holders.len() - shown;
    if extra == 0 {
        format!("cannot lock {vault_name}: files are open in {names}")
    } else {
        format!("cannot lock {vault_name}: files are open in {names}, and {extra} more")
    }
}

fn label(vault: &Path, path: &Path) -> String {
    if path == vault {
        "the vault directory".to_string()
    } else {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("a file")
            .to_string()
    }
}

fn process_name(files: &dyn ProcFs, dir: &Path) -> String {
    files
        .read_to_string(&dir.join("comm"))
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "process".to_string())
}

/// Real uid from `/proc/<pid>/status`, when that file is present.
fn process_uid(files: &dyn ProcFs, dir: &Path) -> Option<u32> {
    let text = files.read_to_string(&dir.join("status")).ok()?;
    let line = text.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn pid_from(name: &std::ffi::OsString) -> Option<u32> {
    let text = name.to_str()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Whole path components, so an open file in `Forge2` is not inside `Forge`.
/// `vault` is canonical. A trailing ` (deleted)` has already been removed.
fn is_inside(vault: &Path, path: &Path) -> bool {
    path == vault || path.starts_with(vault)
}

fn opened_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    text.strip_suffix(" (deleted)")
        .map(PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf())
}

/// The pathname in a `/proc/<pid>/maps` line, when it is a file.
fn mapped_path(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut index = 0;
    for _ in 0..5 {
        while index < bytes.len() && bytes[index] == b' ' {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        while index < bytes.len() && bytes[index] != b' ' {
            index += 1;
        }
    }
    while index < bytes.len() && bytes[index] == b' ' {
        index += 1;
    }
    let path = line[index..].trim_end();
    path.starts_with('/').then_some(path)
}

fn is_kernel_thread(files: &dyn ProcFs, dir: &Path) -> bool {
    let Ok(stat) = files.read_to_string(&dir.join("stat")) else {
        return false;
    };
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    let Some(flags) = rest.split_whitespace().nth(6) else {
        return false;
    };
    flags
        .parse::<u64>()
        .is_ok_and(|flags| flags & PF_KTHREAD != 0)
}

fn classify(error: &std::io::Error) -> Miss {
    if is_gone(error) {
        Miss::Gone
    } else if is_permission(error) {
        Miss::Denied
    } else {
        Miss::Other
    }
}

/// The process or this `/proc` entry is gone. `ESRCH` is not `ErrorKind::NotFound`.
fn is_gone(error: &std::io::Error) -> bool {
    is_exited(error)
        || matches!(
            error.raw_os_error(),
            Some(code) if code == nix::libc::ENOENT || code == nix::libc::ENOTDIR
        )
        || matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        )
}

fn is_exited(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ESRCH)
}

fn is_permission(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == nix::libc::EACCES || code == nix::libc::EPERM
    ) || error.kind() == std::io::ErrorKind::PermissionDenied
}

/// True when this process can read every other process's open files.
pub(crate) fn ptrace_is_effective() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return true;
    };
    let Some(hex) = status.lines().find_map(|line| {
        line.strip_prefix("CapEff:\t")
            .or_else(|| line.strip_prefix("CapEff: "))
            .or_else(|| line.strip_prefix("CapEff:"))
    }) else {
        return true;
    };
    let hex = hex.trim();
    let low = if hex.len() > 16 {
        &hex[hex.len() - 16..]
    } else {
        hex
    };
    let bits = u64::from_str_radix(low, 16).unwrap_or(u64::MAX);
    bits & (1 << CAP_SYS_PTRACE) != 0
}

/// The installed helper calls this once. Tests do not: they have no such capability,
/// and permission errors there are ignored on purpose.
pub(crate) fn warn_if_ptrace_missing() {
    if ptrace_is_effective() {
        return;
    }
    eprintln!(
        "linux-vault-helper: CAP_SYS_PTRACE is not effective. The open-file check is best-effort, so root processes that cannot be inspected are skipped and a lock can proceed while one of them holds a vault file open. The helper unit must keep CAP_SYS_PTRACE effective."
    );
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct Temp {
        path: PathBuf,
    }

    impl Temp {
        fn new() -> Self {
            static TEMPS: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "lve-proc-{}-{}",
                std::process::id(),
                TEMPS.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// The tests that plant a `/proc` tree read it from disk.
    fn scan(proc_root: &Path, vault: &Path, vault_name: &str) -> Result<(), HelperError> {
        super::scan(proc_root, vault, vault_name, 0, &HostFs)
    }

    /// `fd` cannot be read. Root would still read a mode `000` directory.
    struct DenyFd;

    impl ProcFs for DenyFd {
        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<std::io::Result<ProcEntry>>> {
            if path.ends_with("fd") {
                return Err(std::io::Error::from_raw_os_error(nix::libc::EACCES));
            }
            HostFs.read_dir(path)
        }

        fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
            HostFs.read_link(path)
        }

        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            HostFs.read_to_string(path)
        }
    }

    fn process(root: &Path, pid: u32, comm: &str, flags: u64, cwd: &Path) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(dir.join("fd")).unwrap();
        fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
        fs::write(dir.join("status"), "Uid:\t0\t0\t0\t0\n").unwrap();
        fs::write(dir.join("maps"), "").unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} ({comm}) R 1 1 1 0 -1 {flags}\n"),
        )
        .unwrap();
        std::os::unix::fs::symlink(cwd, dir.join("cwd")).unwrap();
    }

    #[test]
    fn an_open_descriptor_a_mapping_and_a_working_directory_refuse_the_lock() {
        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let note = vault.join("my note.txt");
        fs::write(&note, b"hello").unwrap();
        let elsewhere = temp.path.join("other");
        fs::create_dir(&elsewhere).unwrap();
        let proc_root = temp.path.join("proc");

        process(&proc_root, 10, "nvim", 0, &elsewhere);
        std::os::unix::fs::symlink(&note, proc_root.join("10/fd/4")).unwrap();
        let error = scan(&proc_root, &vault, "Forge").unwrap_err().to_string();
        assert!(
            error.contains("cannot lock Forge: my note.txt is open in nvim (pid 10)"),
            "{error}"
        );

        process(&proc_root, 11, "bash", 0, &vault);
        fs::remove_file(proc_root.join("10/fd/4")).unwrap();
        let error = scan(&proc_root, &vault, "Forge").unwrap_err().to_string();
        assert!(
            error.contains("cannot lock Forge: the vault directory is open in bash (pid 11)"),
            "{error}"
        );

        fs::remove_file(proc_root.join("11/cwd")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, proc_root.join("11/cwd")).unwrap();
        let mapped = format!(
            "7f000000-7f001000 r--p 00000000 00:10 1 {}\n",
            note.display()
        );
        fs::write(proc_root.join("11/maps"), mapped).unwrap();
        let error = scan(&proc_root, &vault, "Forge").unwrap_err().to_string();
        assert!(
            error.contains("cannot lock Forge: my note.txt is open in bash (pid 11)"),
            "{error}"
        );
    }

    #[test]
    fn a_sibling_directory_and_a_kernel_thread_are_not_the_vault() {
        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let sibling = temp.path.join("Forge-extra");
        fs::create_dir(&sibling).unwrap();
        let decoy = sibling.join("note.txt");
        fs::write(&decoy, b"nope").unwrap();
        let proc_root = temp.path.join("proc");
        process(&proc_root, 3, "kthread", PF_KTHREAD, &vault);
        std::os::unix::fs::symlink(&decoy, proc_root.join("3/fd/1")).unwrap();
        process(&proc_root, 4, "cat", 0, &sibling);
        std::os::unix::fs::symlink(&decoy, proc_root.join("4/fd/1")).unwrap();
        let deleted = format!("{} (deleted)", decoy.display());
        fs::write(
            proc_root.join("4/maps"),
            format!("7f000000-7f001000 r--p 00000000 00:10 1 {deleted}\n"),
        )
        .unwrap();
        scan(&proc_root, &vault, "Forge").unwrap();
    }

    #[test]
    fn an_unreadable_or_undumpable_process_does_not_refuse_the_lock() {
        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let proc_root = temp.path.join("proc");
        process(&proc_root, 8, "hidden", 0, &temp.path);
        super::scan(&proc_root, &vault, "Forge", 0, &DenyFd).unwrap();
    }

    #[test]
    fn another_users_process_is_skipped_and_the_owners_open_file_refuses() {
        if std::env::var_os("LVE_SCAN_LIMITED").is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "open_files::tests::another_users_process_is_skipped_and_the_owners_open_file_refuses",
                    "--test-threads=1",
                ])
                .env("LVE_SCAN_LIMITED", "1")
                .status()
                .unwrap();
            assert!(status.success(), "limited-capability scan failed: {status}");
            return;
        }
        crate::limit_to_unit_capabilities();
        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let note = vault.join("note.txt");
        fs::write(&note, b"yes").unwrap();
        let proc_root = temp.path.join("proc");
        process(&proc_root, 8, "hidden", 0, &temp.path);
        fs::write(proc_root.join("8/status"), "Uid:\t42\t42\t42\t42\n").unwrap();
        std::os::unix::fs::symlink(&note, proc_root.join("8/fd/1")).unwrap();
        super::scan(&proc_root, &vault, "Forge", 1000, &HostFs).unwrap();

        process(&proc_root, 9, "cat", 0, &temp.path);
        fs::write(proc_root.join("9/status"), "Uid:\t1000\t1000\t1000\t1000\n").unwrap();
        std::os::unix::fs::symlink(&note, proc_root.join("9/fd/1")).unwrap();
        let error = super::scan(&proc_root, &vault, "Forge", 1000, &HostFs)
            .unwrap_err()
            .to_string();
        assert!(error.contains("note.txt is open in cat (pid 9)"), "{error}");
    }

    #[test]
    fn forge_does_not_match_an_open_file_in_forge2() {
        let temp = Temp::new();
        fs::create_dir(temp.path.join("Forge")).unwrap();
        fs::create_dir(temp.path.join("Forge2")).unwrap();
        let forge = temp.path.join("Forge").canonicalize().unwrap();
        let forge2 = temp.path.join("Forge2").canonicalize().unwrap();
        let outside = forge2.join("x");
        fs::write(&outside, b"no").unwrap();
        let note = forge.join("note.txt");
        fs::write(&note, b"yes").unwrap();
        assert!(
            outside
                .to_string_lossy()
                .starts_with(&*forge.to_string_lossy()),
            "the string prefix is the trap this test is for"
        );
        assert!(!outside.starts_with(&forge));

        let proc_root = temp.path.join("proc");
        let elsewhere = temp.path.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        process(&proc_root, 20, "cat", 0, &elsewhere);
        std::os::unix::fs::symlink(&outside, proc_root.join("20/fd/3")).unwrap();
        let via_dotdot = forge.join("../Forge");
        scan(&proc_root, &via_dotdot, "Forge").unwrap();

        let deleted = format!("{} (deleted)", note.display());
        std::os::unix::fs::symlink(deleted, proc_root.join("20/fd/4")).unwrap();
        let error = scan(&proc_root, &via_dotdot, "Forge")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("note.txt is open in cat (pid 20)"),
            "{error}"
        );
    }

    #[test]
    fn a_process_that_exits_during_the_scan_is_skipped() {
        assert!(is_gone(&std::io::Error::from_raw_os_error(
            nix::libc::ESRCH
        )));
        assert!(is_gone(&std::io::Error::from_raw_os_error(
            nix::libc::ENOENT
        )));
        assert!(!is_gone(&std::io::Error::from_raw_os_error(
            nix::libc::EACCES
        )));
        assert!(is_permission(&std::io::Error::from_raw_os_error(
            nix::libc::EACCES
        )));
        assert!(!is_permission(&std::io::Error::from_raw_os_error(
            nix::libc::ESRCH
        )));

        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let proc_root = temp.path.join("proc");
        process(&proc_root, 9, "gone", 0, &vault);
        fs::remove_file(proc_root.join("9/maps")).unwrap();
        scan(&proc_root, &vault, "Forge").unwrap();
    }

    #[test]
    fn a_real_open_file_and_a_mapping_name_this_process() {
        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let note = vault.join("note.txt");
        let mut file = File::create(&note).unwrap();
        file.write_all(&[0u8; 4096]).unwrap();
        let owner = fs::metadata("/proc/self").unwrap().uid();
        let error = refuse_if_open(&vault, "Forge", owner)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("note.txt is open in")
                && error.contains(&format!("pid {}", std::process::id())),
            "{error}"
        );
        drop(file);

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&note)
            .unwrap();
        let ptr = unsafe {
            nix::libc::mmap(
                std::ptr::null_mut(),
                4096,
                nix::libc::PROT_READ,
                nix::libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(ptr, nix::libc::MAP_FAILED);
        drop(file);
        let owner = fs::metadata("/proc/self").unwrap().uid();
        let error = refuse_if_open(&vault, "Forge", owner)
            .unwrap_err()
            .to_string();
        assert!(error.contains("note.txt"), "{error}");
        unsafe {
            nix::libc::munmap(ptr, 4096);
        }
    }

    #[test]
    fn a_working_directory_inside_the_vault_names_that_process() {
        let temp = Temp::new();
        let vault = temp.path.join("Forge");
        fs::create_dir(&vault).unwrap();
        let mut child = Command::new("sleep")
            .arg("30")
            .current_dir(&vault)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let owner = fs::metadata("/proc/self").unwrap().uid();
        let error = refuse_if_open(&vault, "Forge", owner)
            .unwrap_err()
            .to_string();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            error.contains("the vault directory is open in sleep")
                && error.contains(&format!("pid {}", child.id())),
            "{error}"
        );
    }
}
