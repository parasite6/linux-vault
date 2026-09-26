use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};

/// Arguments for archive, test, extract, and list. The passphrase is not here.
///
/// Create passes bare `-p`, which makes 7z encrypt and read the passphrase
/// from stdin. Test, extract, and list omit `-p`: on 7-Zip 26.02 a bare `-p`
/// is an empty password, and 7z then does not read stdin. An encrypted archive
/// makes test and extract ask on their own, and that prompt reads stdin.
/// `output_dir` is the `-o` directory for extract.
pub fn command_args(verb: &str, archive_name: &str, output_dir: Option<&str>) -> Vec<String> {
    let mut args = vec![verb.to_string()];
    if verb == "a" {
        args.extend(["-p", "-mhe=on", "-mx=0"].map(str::to_string));
    }
    args.extend(["-y", "-bd"].map(str::to_string));
    if let Some(dir) = output_dir {
        args.push(format!("-o{dir}"));
    }
    args.extend(["--", archive_name].map(str::to_string));
    args
}

pub fn run(
    seven_zip: &Path,
    args: &[String],
    cwd: &Path,
    passphrase: &[u8],
    user: Option<Credentials>,
) -> Result<()> {
    finish(spawn(seven_zip, args, cwd, user)?, Some(passphrase), None)
}

/// Same as [`run`], but kill `7z` once `stop` is set.
///
/// Unlock uses this while extracting. Lock does not: a pack that has started
/// is left to finish.
pub fn run_interruptible(
    seven_zip: &Path,
    args: &[String],
    cwd: &Path,
    passphrase: &[u8],
    user: Option<Credentials>,
    stop: &AtomicBool,
) -> Result<()> {
    finish(
        spawn(seven_zip, args, cwd, user)?,
        Some(passphrase),
        Some(stop),
    )
}

/// Run 7z with stdin closed and no passphrase bytes.
///
/// `7z l` on an archive with encrypted headers fails this way. A list that
/// succeeds means the archive is not encrypted.
pub fn run_without_passphrase(
    seven_zip: &Path,
    args: &[String],
    cwd: &Path,
    user: Option<Credentials>,
) -> Result<()> {
    finish(spawn(seven_zip, args, cwd, user)?, None, None)
}

/// Uid and gid for the `7z` child. `setuid`/`setgid` replace the real,
/// effective, and saved ids, so the child cannot switch back to root.
#[derive(Clone, Copy)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
}

fn spawn(
    seven_zip: &Path,
    args: &[String],
    cwd: &Path,
    user: Option<Credentials>,
) -> Result<std::process::Child> {
    let mut command = Command::new(seven_zip);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(user) = user {
        // `CommandExt::groups` is still unstable. `pre_exec` runs in the child
        // before exec. `setgroups` has to happen before `setuid`, so the uid
        // and gid switch are in the same hook: a later `Command::uid` would
        // drop privileges first and `setgroups` would then fail.
        let clear_groups = must_clear_groups();
        // SAFETY: the closure runs between fork and exec. It only calls
        // setgroups, setgid, and setuid, which are async-signal-safe.
        unsafe {
            command.pre_exec(move || drop_privileges(user, clear_groups));
        }
    }
    command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::SevenZipMissing
        } else {
            Error::Io(error)
        }
    })
}

/// Switch the child to `user`. Supplementary groups are cleared when this
/// process is allowed to, so a root helper does not hand `7z` root's groups.
///
/// `setgroups`, `setgid`, and `setuid` are async-signal-safe. `setuid` sets
/// the real, effective, and saved ids, so the child cannot return to root.
///
/// A failure from any of those calls is returned. `Command::spawn` then does
/// not exec, so `7z` does not keep running as root.
fn drop_privileges(user: Credentials, clear_groups: bool) -> std::io::Result<()> {
    if clear_groups {
        // SAFETY: size 0 clears the supplementary group list. No list is read.
        let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let rc = unsafe { libc::setgid(user.gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::setuid(user.uid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `CAP_SETUID` or `CAP_SETGID` in the effective set.
///
/// The helper has both. A test run as the vault owner has neither, and
/// `setgroups` would fail there.
fn must_clear_groups() -> bool {
    const CAP_SETGID: u64 = 1 << 6;
    const CAP_SETUID: u64 = 1 << 7;
    match effective_caps() {
        Some(caps) => caps & (CAP_SETGID | CAP_SETUID) != 0,
        None => true,
    }
}

fn effective_caps() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = text.lines().find(|line| line.starts_with("CapEff:"))?;
    let hex = line.split_whitespace().nth(1)?;
    u64::from_str_radix(hex, 16).ok()
}

fn finish(
    mut child: std::process::Child,
    passphrase: Option<&[u8]>,
    stop: Option<&AtomicBool>,
) -> Result<()> {
    let write_error = match passphrase {
        Some(passphrase) => child.stdin.take().and_then(|mut stdin| {
            stdin
                .write_all(passphrase)
                .err()
                .or_else(|| stdin.flush().err())
        }),
        None => {
            drop(child.stdin.take());
            None
        }
    };

    let output = match stop {
        Some(stop) => wait_or_stop(&mut child, stop)?,
        None => child.wait_with_output()?,
    };
    if output.status.success() {
        if let Some(error) = write_error {
            return Err(error.into());
        }
        return Ok(());
    }

    let message = clamp_message(&output.stdout, &output.stderr);
    if is_wrong_passphrase(&message) {
        return Err(Error::WrongPassphrase { message });
    }
    Err(Error::SevenZip {
        status: output.status.code(),
        message,
    })
}

/// Poll until `7z` exits. If `stop` is set, kill it. `try_wait` returning
/// `Some` has already reaped the child, so this does not call
/// `wait_with_output` afterwards.
///
/// Stdout and stderr are read on other threads so a full pipe cannot stall
/// `7z` while this thread is polling.
fn wait_or_stop(child: &mut std::process::Child, stop: &AtomicBool) -> Result<Output> {
    let stdout = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let status = loop {
        if stop.load(Ordering::SeqCst) {
            let _ = child.kill();
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(Output {
        status,
        stdout: stdout
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_default(),
        stderr: stderr
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_default(),
    })
}

fn is_wrong_passphrase(message: &str) -> bool {
    message.to_ascii_lowercase().contains("wrong password")
}

fn clamp_message(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&String::from_utf8_lossy(stderr));
    let text = text.trim().to_string();
    const MAX: usize = 2_000;
    if text.len() <= MAX {
        text
    } else {
        let mut end = MAX;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    }
}

pub fn find_seven_zip() -> Result<std::path::PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("7z");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let fallback = std::path::PathBuf::from("/usr/bin/7z");
    if fallback.is_file() {
        return Ok(fallback);
    }
    Err(Error::SevenZipMissing)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::spawn;
    use super::Credentials;

    #[test]
    fn the_child_runs_as_the_given_user() {
        let dir = std::env::temp_dir().join(format!(
            "linux-vault-ids-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("7z");
        let report = dir.join("ids");
        let program = format!(
            "#!/usr/bin/env python3\nimport os\nopen({:?}, 'w').write(f'{{os.getuid()}} {{os.getgid()}}\\n')\n",
            report
        );
        let mut file = std::fs::File::create(&script).unwrap();
        file.write_all(program.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let meta = std::fs::metadata("/proc/self").unwrap();
        let user = Credentials {
            uid: meta.uid(),
            gid: meta.gid(),
        };
        let mut child = spawn(&script, &[], &dir, Some(user)).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "{status}");
        let text = std::fs::read_to_string(&report).unwrap();
        assert_eq!(text, format!("{} {}\n", user.uid, user.gid));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_credential_switch_does_not_run_the_child() {
        let dir = std::env::temp_dir().join(format!("linux-vault-ids-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("7z");
        let report = dir.join("ids");
        let program = format!(
            "#!/usr/bin/env python3\nimport os\nopen({:?}, 'w').write(f'{{os.getuid()}} {{os.getgid()}}\\n')\n",
            report
        );
        let mut file = std::fs::File::create(&script).unwrap();
        file.write_all(program.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        // `(uid_t)-1`. `setuid` rejects it with `EINVAL` for every caller,
        // including root, so the child is never executed.
        let gid = std::fs::metadata("/proc/self").unwrap().gid();
        let user = Credentials {
            uid: 4_294_967_295,
            gid,
        };
        let error = spawn(&script, &[], &dir, Some(user)).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::Io(ref io) if io.raw_os_error() == Some(libc::EINVAL)
            ),
            "{error}"
        );
        assert!(
            !report.exists(),
            "7z ran after setgroups, setgid, or setuid failed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
