use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use linux_vault::{Error, FlagChange, State, Vaults};

struct Temp {
    root: PathBuf,
}

impl Temp {
    fn new() -> Self {
        static TEMPS: AtomicU64 = AtomicU64::new(0);
        let n = TEMPS.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("linux-vault-{}-{n}", process::id()));
        fs::create_dir_all(root.join("registry")).unwrap();
        Self { root }
    }

    fn vaults(&self) -> Vaults {
        Vaults::open(self.root.join("registry"), &self.root)
            .unwrap()
            .trace_immutable_flag()
            .0
    }

    fn folder(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn current_ids() -> (u32, u32) {
    let meta = fs::metadata("/proc/self").unwrap();
    (meta.uid(), meta.gid())
}

fn write_vault(dir: &Path) {
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(dir.join("nested/hello.txt"), b"hello vault\n").unwrap();
}

#[test]
fn archive_and_extracted_files_are_owned_by_the_caller() {
    let temp = Temp::new();
    let (uid, gid) = current_ids();
    let vaults = temp.vaults().for_user(uid, gid);
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    vaults.lock("Forge", b"secret").unwrap();
    let archive = temp.folder("Forge.7z");
    let archive_meta = fs::metadata(&archive).unwrap();
    assert_eq!(archive_meta.uid(), uid);
    assert_eq!(archive_meta.gid(), gid);

    vaults.unlock("Forge", b"secret").unwrap();
    let file_meta = fs::metadata(folder.join("nested/hello.txt")).unwrap();
    assert_eq!(file_meta.uid(), uid);
    assert_eq!(file_meta.gid(), gid);
    let dir_meta = fs::metadata(&folder).unwrap();
    assert_eq!(dir_meta.uid(), uid);
    assert_eq!(dir_meta.gid(), gid);
}

#[test]
fn the_immutable_flag_follows_lock_unlock_and_terminate() {
    let temp = Temp::new();
    let (vaults, trace) = Vaults::open(temp.root.join("registry"), &temp.root)
        .unwrap()
        .trace_immutable_flag();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    vaults.lock("Forge", b"secret").unwrap();
    assert_eq!(trace.calls(), vec![FlagChange::Set]);

    let wrong = vaults.unlock("Forge", b"nope").unwrap_err();
    assert!(matches!(wrong, Error::WrongPassphrase { .. }), "{wrong}");
    assert_eq!(
        trace.calls(),
        vec![FlagChange::Set, FlagChange::Clear, FlagChange::Set]
    );

    let (vaults, trace) = Vaults::open(temp.root.join("registry"), &temp.root)
        .unwrap()
        .trace_immutable_flag();
    vaults.reconcile().unwrap();
    assert_eq!(trace.calls(), vec![FlagChange::Set]);

    let refused = vaults.delete("Forge", Some(b"nope")).unwrap_err();
    assert!(
        matches!(refused, Error::WrongPassphrase { .. }),
        "{refused}"
    );
    assert_eq!(trace.calls(), vec![FlagChange::Set]);

    vaults.delete("Forge", Some(b"secret")).unwrap();
    assert_eq!(trace.calls(), vec![FlagChange::Set, FlagChange::Clear]);

    let (vaults, trace) = Vaults::open(temp.root.join("registry"), &temp.root)
        .unwrap()
        .trace_immutable_flag();
    let folder = temp.folder("Keep");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Keep", b"secret").unwrap();
    assert_eq!(trace.calls(), vec![FlagChange::Set]);
    vaults.unlock("Keep", b"secret").unwrap();
    assert_eq!(trace.calls(), vec![FlagChange::Set, FlagChange::Clear]);
}

#[test]
fn lock_and_unlock_round_trip() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);

    let created = vaults.create(&folder).unwrap();
    assert_eq!(created.name, "Forge");
    assert_eq!(created.state, State::Unlocked);

    vaults.lock("Forge", b"secret").unwrap();
    let locked = vaults.get("Forge").unwrap();
    assert_eq!(locked.state, State::Locked);
    assert!(!locked.path.exists());
    assert!(temp.folder("Forge.7z").is_file());
    assert!(!temp.folder("Forge.7z.lve-partial").exists());

    vaults.unlock("Forge", b"secret").unwrap();
    let unlocked = vaults.get("Forge").unwrap();
    assert_eq!(unlocked.state, State::Unlocked);
    assert!(!temp.folder("Forge.7z").exists());
    assert_eq!(
        fs::read(unlocked.path.join("nested/hello.txt")).unwrap(),
        b"hello vault\n"
    );
    assert!(!temp.folder(".Forge.lve-unlocking").exists());
}

#[test]
fn wrong_passphrase_changes_nothing() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();

    let error = vaults.unlock("Forge", b"nope").unwrap_err();
    assert!(matches!(error, Error::WrongPassphrase { .. }), "{error}");
    assert!(matches!(
        vaults.test("Forge", b"nope").unwrap_err(),
        Error::WrongPassphrase { .. }
    ));
    vaults.test("Forge", b"secret").unwrap();

    let vault = vaults.get("Forge").unwrap();
    assert_eq!(vault.state, State::Locked);
    assert!(!vault.path.exists());
    assert!(temp.folder("Forge.7z").is_file());
    assert!(!temp.folder(".Forge.lve-unlocking").exists());
}

#[test]
fn spaces_and_non_ascii_passphrases_round_trip() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Spaced");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    let passphrase = " secret ".as_bytes();
    vaults.lock("Spaced", passphrase).unwrap();
    assert!(matches!(
        vaults.unlock("Spaced", b"secret").unwrap_err(),
        Error::WrongPassphrase { .. }
    ));
    vaults.unlock("Spaced", passphrase).unwrap();

    let folder = temp.folder("Accent");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    let passphrase = "sécret".as_bytes();
    vaults.lock("Accent", passphrase).unwrap();
    vaults.unlock("Accent", passphrase).unwrap();
    assert_eq!(
        fs::read(temp.folder("Accent/nested/hello.txt")).unwrap(),
        b"hello vault\n"
    );
}

#[test]
fn rejected_passphrases_do_not_touch_the_folder() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    for passphrase in [b"".as_slice(), b"a\nb", b"a\rb", b"a\0b"] {
        let error = vaults.lock("Forge", passphrase).unwrap_err();
        assert!(matches!(error, Error::InvalidPassphrase(_)), "{error}");
    }
    assert!(folder.join("nested/hello.txt").is_file());
    assert!(!temp.folder("Forge.7z").exists());
    assert_eq!(vaults.get("Forge").unwrap().state, State::Unlocked);
}

#[test]
fn escaping_symlink_is_refused() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let outside = temp.folder("outside.txt");
    fs::write(&outside, b"secret outside\n").unwrap();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    std::os::unix::fs::symlink(&outside, folder.join("leak")).unwrap();
    vaults.create(&folder).unwrap();

    let error = vaults.lock("Forge", b"secret").unwrap_err();
    assert!(matches!(error, Error::EscapingSymlink), "{error}");
    assert!(folder.join("nested/hello.txt").is_file());
    assert!(!temp.folder("Forge.7z").exists());
}

#[test]
fn a_symlink_in_the_parent_outside_home_is_not_written() {
    let temp = Temp::new();
    let home = temp.folder("home");
    let outside = temp.folder("outside");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("marker"), b"untouched\n").unwrap();
    std::os::unix::fs::symlink(&outside, home.join("linked")).unwrap();
    let vaults = Vaults::open(temp.root.join("registry"), &home).unwrap();

    let error = vaults
        .create(home.join("linked").join("Forge"))
        .unwrap_err();
    assert!(matches!(error, Error::OutsideRoot), "{error}");
    assert_eq!(fs::read(outside.join("marker")).unwrap(), b"untouched\n");
    assert!(!outside.join("Forge").exists());
}

#[test]
fn lock_does_not_follow_a_symlink_out_of_the_parent() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    let outside = temp.folder("outside-archive");
    fs::write(&outside, b"untouched\n").unwrap();
    std::os::unix::fs::symlink(&outside, temp.folder("Forge.7z.lve-partial")).unwrap();

    vaults.lock("Forge", b"secret").unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"untouched\n");
    let archive = temp.folder("Forge.7z");
    let meta = fs::symlink_metadata(&archive).unwrap();
    assert!(meta.is_file(), "archive should be a regular file");
    assert!(!meta.file_type().is_symlink());
}

#[test]
fn path_outside_the_allowed_root_is_refused() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let outside = std::env::temp_dir().join(format!("linux-vault-outside-{}", process::id()));
    fs::create_dir_all(&outside).unwrap();
    let error = vaults.create(&outside).unwrap_err();
    assert!(matches!(error, Error::OutsideRoot), "{error}");
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn reconcile_discards_a_partial_archive_and_marks_recovery() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    fs::write(temp.folder("Forge.7z.lve-partial"), b"partial").unwrap();

    let vaults = temp.vaults();
    let listed = vaults.reconcile().unwrap().vaults;
    assert_eq!(listed[0].state, State::NeedsRecovery);
    assert!(!temp.folder("Forge.7z.lve-partial").exists());
    assert!(!temp.folder("Forge.7z").exists());
    assert!(folder.join("nested/hello.txt").is_file());
}

#[test]
fn reconcile_keeps_a_finished_lock_and_a_finished_unlock() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();

    let registry = temp.root.join("registry/registry.json");
    let text = fs::read_to_string(&registry).unwrap();
    fs::write(&registry, text.replace("\"locked\"", "\"unlocked\"")).unwrap();

    let vaults = temp.vaults();
    let listed = vaults.reconcile().unwrap().vaults;
    assert_eq!(listed[0].state, State::Locked);
    assert!(temp.folder("Forge.7z").is_file());
    assert!(!folder.exists());

    vaults.unlock("Forge", b"secret").unwrap();
    let text = fs::read_to_string(&registry).unwrap();
    fs::write(&registry, text.replace("\"unlocked\"", "\"locked\"")).unwrap();
    let listed = temp.vaults().reconcile().unwrap().vaults;
    assert_eq!(listed[0].state, State::NeedsRecovery);
    assert!(folder.join("nested/hello.txt").is_file());
    assert!(!temp.folder("Forge.7z").exists());
}

#[test]
fn reconcile_drops_a_finished_terminate_when_nothing_is_left() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();
    fs::remove_file(temp.folder("Forge.7z")).unwrap();

    let reconciled = temp.vaults().reconcile().unwrap();
    assert!(reconciled.vaults.is_empty());
    assert_eq!(reconciled.removed, vec![folder]);
    let text = fs::read_to_string(temp.root.join("registry/registry.json")).unwrap();
    assert!(
        !text.contains("Forge"),
        "a finished terminate is not recovery: {text}"
    );
}

#[test]
fn stopping_an_extract_restores_the_flag_and_leaves_the_archive() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();

    let script = temp.folder("slow-7z");
    fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let (mut vaults, trace) = Vaults::open(temp.root.join("registry"), &temp.root)
        .unwrap()
        .trace_immutable_flag();
    vaults.set_seven_zip(&script);
    vaults.request_stop_extract();
    let error = vaults.unlock("Forge", b"secret").unwrap_err();
    assert!(matches!(error, Error::SevenZip { .. }), "{error}");
    assert!(temp.folder("Forge.7z").is_file());
    assert!(!folder.exists());
    assert!(!temp.folder(".Forge.lve-unlocking").exists());
    assert_eq!(trace.calls(), vec![FlagChange::Clear, FlagChange::Set]);
    assert_eq!(temp.vaults().list().unwrap()[0].state, State::Locked);
}

#[test]
fn a_stop_request_does_not_abort_a_lock() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.request_stop_extract();
    vaults.lock("Forge", b"secret").unwrap();
    assert!(temp.folder("Forge.7z").is_file());
    assert!(!folder.exists());
}

#[test]
fn delete_locked_tests_the_passphrase_and_delete_unlocked_removes_the_folder() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();

    let error = vaults.delete("Forge", Some(b"nope")).unwrap_err();
    assert!(matches!(error, Error::WrongPassphrase { .. }), "{error}");
    assert!(temp.folder("Forge.7z").is_file());
    assert!(vaults.delete("Forge", None).is_err());

    vaults.delete("Forge", Some(b"secret")).unwrap();
    assert!(vaults.get("Forge").is_err());
    assert!(!temp.folder("Forge.7z").exists());

    let folder = temp.folder("Plain");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    assert!(vaults.delete("Plain", Some(b"secret")).is_err());
    vaults.delete("Plain", None).unwrap();
    assert!(!folder.exists());
    assert!(vaults.get("Plain").is_err());
}

#[test]
fn a_failing_seven_zip_leaves_the_plaintext_folder() {
    let temp = Temp::new();
    let mut vaults = temp.vaults();
    let script = temp.root.join("fail-7z");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&script)
            .unwrap();
        use std::io::Write;
        writeln!(file, "#!/bin/sh\nexit 1").unwrap();
    }
    vaults.set_seven_zip(&script);

    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    let error = vaults.lock("Forge", b"secret").unwrap_err();
    assert!(matches!(error, Error::SevenZip { .. }), "{error}");
    assert!(folder.join("nested/hello.txt").is_file());
    assert!(!temp.folder("Forge.7z").exists());
    assert!(!temp.folder("Forge.7z.lve-partial").exists());
    assert_eq!(vaults.get("Forge").unwrap().state, State::Unlocked);
}

#[test]
fn lock_is_refused_when_already_locked() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();
    let error = vaults.lock("Forge", b"secret").unwrap_err();
    assert!(matches!(error, Error::InvalidState { .. }), "{error}");
}

#[test]
fn killed_unlock_mid_extract_reconciles_to_locked() {
    if std::env::var_os("LVE_CRASH").is_some() {
        crash_unlock();
    }

    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();
    let archive = fs::read(temp.folder("Forge.7z")).unwrap();

    let script = temp.root.join("kill-unlock");
    write_script(
        &script,
        r#"#!/bin/sh
outdir=
for arg in "$@"; do
  case $arg in
    -o*) outdir=${arg#-o} ;;
  esac
done
mkdir -p "$outdir/nested"
printf 'partial extract\n' > "$outdir/nested/hello.txt"
kill -9 "$PPID"
exit 137
"#,
    );
    let status = spawn_crash(
        "killed_unlock_mid_extract_reconciles_to_locked",
        &temp.root,
        &script,
    );
    assert_eq!(status.signal(), Some(9), "child status {status}");
    assert!(temp
        .folder(".Forge.lve-unlocking/nested/hello.txt")
        .is_file());
    assert_eq!(fs::read(temp.folder("Forge.7z")).unwrap(), archive);
    assert!(
        fs::read_to_string(temp.root.join("registry/registry.json"))
            .unwrap()
            .contains("\"unlocking\""),
        "a killed unlock must leave the unlocking mark"
    );

    let listed = temp.vaults().reconcile().unwrap().vaults;
    assert_eq!(listed[0].state, State::Locked);
    assert!(!temp.folder(".Forge.lve-unlocking").exists());
    assert!(!folder.exists());
    assert_eq!(fs::read(temp.folder("Forge.7z")).unwrap(), archive);
    temp.vaults().test("Forge", b"secret").unwrap();
}

#[test]
fn killed_lock_mid_write_keeps_the_folder_and_drops_the_partial() {
    if std::env::var_os("LVE_CRASH").is_some() {
        crash_lock();
    }

    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    let script = temp.root.join("kill-lock");
    write_script(
        &script,
        r#"#!/bin/sh
archive=
next=0
for arg in "$@"; do
  if [ "$next" = 1 ]; then
    archive=$arg
    break
  fi
  if [ "$arg" = "--" ]; then
    next=1
  fi
done
printf 'not a finished archive\n' > "$archive"
kill -9 "$PPID"
exit 137
"#,
    );
    let status = spawn_crash(
        "killed_lock_mid_write_keeps_the_folder_and_drops_the_partial",
        &temp.root,
        &script,
    );
    assert_eq!(status.signal(), Some(9), "child status {status}");
    assert!(temp.folder("Forge.7z.lve-partial").is_file());
    assert_eq!(
        fs::read(folder.join("nested/hello.txt")).unwrap(),
        b"hello vault\n"
    );
    assert!(
        fs::read_to_string(temp.root.join("registry/registry.json"))
            .unwrap()
            .contains("\"locking\""),
        "a killed lock must leave the locking mark"
    );

    let listed = temp.vaults().reconcile().unwrap().vaults;
    assert_eq!(listed[0].state, State::NeedsRecovery);
    assert!(!temp.folder("Forge.7z.lve-partial").exists());
    assert!(!temp.folder("Forge.7z").exists());
    assert_eq!(
        fs::read(folder.join("nested/hello.txt")).unwrap(),
        b"hello vault\n"
    );
}

#[test]
fn both_complete_copies_reconcile_to_locked() {
    let temp = Temp::new();
    let vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();
    write_vault(&folder);

    let registry = temp.root.join("registry/registry.json");
    let text = fs::read_to_string(&registry).unwrap();
    fs::write(&registry, text.replace("\"locked\"", "\"unlocked\"")).unwrap();

    let listed = temp.vaults().reconcile().unwrap().vaults;
    assert_eq!(listed[0].state, State::Locked);
    assert!(!folder.exists());
    assert!(temp.folder("Forge.7z").is_file());

    temp.vaults().unlock("Forge", b"secret").unwrap();
    assert_eq!(
        fs::read(temp.folder("Forge/nested/hello.txt")).unwrap(),
        b"hello vault\n"
    );
}

#[test]
fn unencrypted_archive_is_refused_by_lock_and_terminate() {
    let temp = Temp::new();
    let mut vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    let wrapper = temp.root.join("plain-7z");
    write_script(
        &wrapper,
        r#"#!/usr/bin/env python3
import os, sys
sys.stdin.read()
fd = os.open("/dev/null", os.O_RDONLY)
os.dup2(fd, 0)
args = sys.argv[1:]
if args and args[0] == "a":
    args = [arg for arg in args if arg not in ("-p", "-mhe=on")]
os.execv("/usr/bin/7z", ["/usr/bin/7z", *args])
"#,
    );
    vaults.set_seven_zip(&wrapper);
    let error = vaults.lock("Forge", b"secret").unwrap_err();
    assert!(matches!(error, Error::NotEncrypted), "{error}");
    assert!(folder.join("nested/hello.txt").is_file());
    assert!(!temp.folder("Forge.7z").exists());
    assert!(!temp.folder("Forge.7z.lve-partial").exists());
    assert_eq!(vaults.get("Forge").unwrap().state, State::Unlocked);

    let vaults = temp.vaults();
    vaults.lock("Forge", b"secret").unwrap();
    fs::remove_file(temp.folder("Forge.7z")).unwrap();
    let source = temp.folder("plain-src");
    write_vault(&source);
    let status = Command::new("/usr/bin/7z")
        .args([
            "a",
            "-mx=0",
            "-y",
            "-bd",
            "--",
            temp.folder("Forge.7z").to_str().unwrap(),
            ".",
        ])
        .current_dir(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let archive = fs::read(temp.folder("Forge.7z")).unwrap();

    let error = vaults.delete("Forge", Some(b"secret")).unwrap_err();
    assert!(matches!(error, Error::NotEncrypted), "{error}");
    assert_eq!(fs::read(temp.folder("Forge.7z")).unwrap(), archive);
    assert_eq!(vaults.get("Forge").unwrap().state, State::Locked);
    assert!(vaults.delete("Forge", None).is_err());
}

#[test]
fn list_runs_while_seven_zip_holds_no_registry_lock() {
    let temp = Temp::new();
    let mut vaults = temp.vaults();
    let folder = temp.folder("Forge");
    write_vault(&folder);
    vaults.create(&folder).unwrap();

    let started = temp.root.join("started");
    let release = temp.root.join("release");
    let script = temp.root.join("slow-7z");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf started > '{}'\nwhile [ ! -f '{}' ]; do sleep 0.02; done\nexit 1\n",
            started.display(),
            release.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    vaults.set_seven_zip(&script);

    let lock_path = temp.root.join("registry/.lock");
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = fs::write(&release, b"1");
        });
        scope.spawn(|| {
            let _ = vaults.lock("Forge", b"secret");
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !started.exists() {
            if std::time::Instant::now() > deadline {
                panic!("7z did not start");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let listed = vaults.list().unwrap();
        assert_eq!(listed[0].state, State::Locking);
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        held.try_lock()
            .expect("registry flock is held while 7z runs");
        held.unlock().unwrap();
        fs::write(&release, b"1").unwrap();
    });
    assert_eq!(vaults.get("Forge").unwrap().state, State::Unlocked);
    assert!(folder.is_dir());
}

fn crash_unlock() -> ! {
    let root = PathBuf::from(std::env::var("LVE_ROOT").unwrap());
    let (mut vaults, _) = Vaults::open(root.join("registry"), &root)
        .unwrap()
        .trace_immutable_flag();
    vaults.set_seven_zip(std::env::var("LVE_7Z").unwrap());
    let _ = vaults.unlock("Forge", b"secret");
    process::exit(2);
}

fn crash_lock() -> ! {
    let root = PathBuf::from(std::env::var("LVE_ROOT").unwrap());
    let (mut vaults, _) = Vaults::open(root.join("registry"), &root)
        .unwrap()
        .trace_immutable_flag();
    vaults.set_seven_zip(std::env::var("LVE_7Z").unwrap());
    let _ = vaults.lock("Forge", b"secret");
    process::exit(2);
}

fn spawn_crash(test_name: &str, root: &Path, seven_zip: &Path) -> process::ExitStatus {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--test-threads=1"])
        .env("LVE_CRASH", "1")
        .env("LVE_ROOT", root)
        .env("LVE_7Z", seven_zip)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait()
        .unwrap()
}

fn write_script(path: &Path, body: &str) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(path)
        .unwrap();
    file.write_all(body.as_bytes()).unwrap();
}
