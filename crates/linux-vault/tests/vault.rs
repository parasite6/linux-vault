use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use linux_vault::{Error, State, Vaults};

struct Temp {
    root: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("linux-vault-{}-{nanos}", process::id()));
        fs::create_dir_all(root.join("registry")).unwrap();
        Self { root }
    }

    fn vaults(&self) -> Vaults {
        Vaults::open(self.root.join("registry"), &self.root).unwrap()
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

fn write_vault(dir: &Path) {
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(dir.join("nested/hello.txt"), b"hello vault\n").unwrap();
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
    let listed = vaults.reconcile().unwrap();
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
    let listed = vaults.reconcile().unwrap();
    assert_eq!(listed[0].state, State::Locked);
    assert!(temp.folder("Forge.7z").is_file());
    assert!(!folder.exists());

    vaults.unlock("Forge", b"secret").unwrap();
    let text = fs::read_to_string(&registry).unwrap();
    fs::write(&registry, text.replace("\"unlocked\"", "\"locked\"")).unwrap();
    let listed = temp.vaults().reconcile().unwrap();
    assert_eq!(listed[0].state, State::NeedsRecovery);
    assert!(folder.join("nested/hello.txt").is_file());
    assert!(!temp.folder("Forge.7z").exists());
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

    let listed = temp.vaults().reconcile().unwrap();
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

    let listed = temp.vaults().reconcile().unwrap();
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

    let listed = temp.vaults().reconcile().unwrap();
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

fn crash_unlock() -> ! {
    let root = PathBuf::from(std::env::var("LVE_ROOT").unwrap());
    let mut vaults = Vaults::open(root.join("registry"), &root).unwrap();
    vaults.set_seven_zip(std::env::var("LVE_7Z").unwrap());
    let _ = vaults.unlock("Forge", b"secret");
    process::exit(2);
}

fn crash_lock() -> ! {
    let root = PathBuf::from(std::env::var("LVE_ROOT").unwrap());
    let mut vaults = Vaults::open(root.join("registry"), &root).unwrap();
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
        .mode(0o755)
        .open(path)
        .unwrap();
    file.write_all(body.as_bytes()).unwrap();
}
