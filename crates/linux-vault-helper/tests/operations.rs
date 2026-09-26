use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;

use linux_vault::{FlagChange, Vaults};
use linux_vault_dbus::{HelperProxy, OBJECT_PATH};
use linux_vault_helper::{Account, Authorizer, Helper, Prompt};
use zbus::connection::Builder;
use zbus::Guid;

const SCRIPT: &str = r#"#!/usr/bin/env python3
import sys
import time

log_path, mode = sys.argv[1], sys.argv[2]

def say(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()

say("OK Pleased to meet you")
description = ""
for raw in sys.stdin:
    line = raw.rstrip("\r\n")
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(line + "\n")
    if line.startswith("SETDESC "):
        description = line
    if line == "BYE" or line.startswith("BYE "):
        say("OK")
        break
    if line != "GETPIN":
        say("OK")
        continue
    if mode == "cancel":
        say("ERR 83886179 Operation cancelled")
    elif mode == "sleep":
        time.sleep(30)
        say("S PIN_REPEATED")
        say("D secret")
        say("OK")
    elif mode == "wrong" or (mode == "terminate-wrong" and "Terminate" in description):
        say("D wrong")
        say("OK")
    else:
        say("S PIN_REPEATED")
        say("D secret")
        say("OK")
"#;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static TEMPS: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lve-ops-{}-{}",
            process::id(),
            TEMPS.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Session {
    client: zbus::Connection,
    _server: zbus::Connection,
    dir: TempDir,
    held: linux_vault_helper::HeldPassphrases,
    flags: linux_vault::ImmutableTrace,
    log: PathBuf,
    shutdown: linux_vault_helper::ShutdownHandle,
}

async fn session(mode: &str) -> Session {
    let dir = TempDir::new();
    let script = dir.path.join("pinentry");
    let log = dir.path.join("log");
    let mut file = fs::File::create(&script).unwrap();
    file.write_all(SCRIPT.as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    let (vaults, flags) = Vaults::open(dir.path.join("registry"), &dir.path)
        .unwrap()
        .trace_immutable_flag();
    let helper = Helper::new(
        Authorizer::Allow,
        vaults,
        Prompt::Program(vec![
            script.as_os_str().to_os_string(),
            log.as_os_str().to_os_string(),
            mode.into(),
        ]),
        account(&dir.path),
    )
    .unwrap();
    let held = helper.held_passphrases();
    let shutdown = helper.shutdown_handle();
    let guid = Guid::generate();
    let (client_stream, server_stream) = UnixStream::pair().unwrap();
    let server = Builder::unix_stream(server_stream)
        .server(guid)
        .unwrap()
        .p2p()
        .serve_at(OBJECT_PATH, helper)
        .unwrap()
        .build();
    let client = Builder::unix_stream(client_stream).p2p().build();
    let (client, server) = tokio::try_join!(client, server).unwrap();
    Session {
        client,
        _server: server,
        dir,
        held,
        flags,
        log,
        shutdown,
    }
}

fn account(home: &std::path::Path) -> Account {
    let meta = fs::metadata("/proc/self").unwrap();
    Account {
        user: "tester".into(),
        uid: meta.uid(),
        gid: meta.gid(),
        home: home.to_path_buf(),
    }
}

async fn proxy(connection: &zbus::Connection) -> HelperProxy<'_> {
    HelperProxy::builder(connection)
        .path(OBJECT_PATH)
        .unwrap()
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn create_asks_twice_and_registers_the_folder() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    assert!(folder.is_dir());
    assert!(session.held.contains("Forge"));
    let transcript = fs::read_to_string(&session.log).unwrap();
    assert!(
        transcript.contains("SETREPEAT Repeat passphrase:"),
        "{transcript}"
    );
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert_eq!(
        vaults.get("Forge").unwrap().state,
        linux_vault::State::Unlocked
    );
}

#[tokio::test]
async fn cancelling_create_registers_nothing() {
    let session = session("cancel").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    let error = proxy.create(folder.to_str().unwrap()).await.unwrap_err();
    assert!(error.to_string().contains("cancelled"), "{error}");
    assert!(!session.held.contains("Forge"));
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert!(vaults.get("Forge").is_err());
}

#[tokio::test]
async fn unlock_extracts_with_the_typed_passphrase() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    let ids = fs::metadata("/proc/self").unwrap();
    let (vaults, _) = Vaults::open(session.dir.path.join("registry"), &session.dir.path)
        .unwrap()
        .for_user(ids.uid(), ids.gid())
        .trace_immutable_flag();
    vaults.lock("Forge", b"secret").unwrap();
    assert!(!folder.exists());
    let archive = fs::metadata(session.dir.path.join("Forge.7z")).unwrap();
    assert_eq!(archive.uid(), ids.uid());
    assert_eq!(archive.gid(), ids.gid());

    proxy.unlock("Forge").await.unwrap();
    assert_eq!(fs::read(folder.join("note.txt")).unwrap(), b"hello\n");
    let extracted = fs::metadata(folder.join("note.txt")).unwrap();
    assert_eq!(extracted.uid(), ids.uid());
    assert_eq!(extracted.gid(), ids.gid());
    assert!(!session.dir.path.join("Forge.7z").exists());
    assert!(session.held.contains("Forge"));
}

#[tokio::test]
async fn a_wrong_passphrase_leaves_the_archive_locked() {
    let session = session("wrong").await;
    let folder = session.dir.path.join("Forge");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    let (vaults, _) = Vaults::open(session.dir.path.join("registry"), &session.dir.path)
        .unwrap()
        .trace_immutable_flag();
    vaults.create(&folder).unwrap();
    vaults.lock("Forge", b"secret").unwrap();

    let proxy = proxy(&session.client).await;
    let error = proxy.unlock("Forge").await.unwrap_err();
    assert!(error.to_string().contains("wrong passphrase"), "{error}");
    assert!(session.dir.path.join("Forge.7z").is_file());
    assert!(!folder.exists());
    assert!(!session.held.contains("Forge"));
}

#[tokio::test]
async fn lock_packs_the_folder_and_forgets_the_passphrase() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();

    proxy.lock("Forge").await.unwrap();
    assert!(!folder.exists());
    assert!(session.dir.path.join("Forge.7z").is_file());
    assert!(!session.held.contains("Forge"));
    assert_eq!(session.flags.calls(), vec![FlagChange::Set]);
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert_eq!(
        vaults.get("Forge").unwrap().state,
        linux_vault::State::Locked
    );
}

#[tokio::test]
async fn lock_refuses_while_a_file_is_open_and_keeps_the_passphrase() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    let note = fs::File::create(folder.join("note.txt")).unwrap();

    let error = proxy.lock("Forge").await.unwrap_err().to_string();
    assert!(
        error.contains("note.txt is open in") && error.contains(&process::id().to_string()),
        "{error}"
    );
    let listed = proxy.list().await.unwrap();
    assert_eq!(listed[0].state, "unlocked", "{listed:?}");
    assert!(folder.is_dir());
    assert!(session.held.contains("Forge"));
    assert!(session.flags.calls().is_empty());
    drop(note);
    proxy.lock("Forge").await.unwrap();
    assert!(!folder.exists());
}

#[tokio::test]
async fn a_refused_lock_without_a_passphrase_needs_recovery() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    session.held.forget("Forge").unwrap();
    let note = fs::File::create(folder.join("note.txt")).unwrap();

    let error = proxy.lock("Forge").await.unwrap_err().to_string();
    assert!(error.contains("note.txt is open in"), "{error}");
    let listed = proxy.list().await.unwrap();
    assert_eq!(listed[0].state, "needs_recovery", "{listed:?}");
    drop(note);
    proxy.lock("Forge").await.unwrap();
    assert!(!folder.exists());
    let listed = proxy.list().await.unwrap();
    assert_eq!(listed[0].state, "locked", "{listed:?}");
}

#[tokio::test]
async fn open_file_scan_under_the_unit_capabilities() {
    if std::env::var_os("LVE_UNIT_CAPS").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "open_file_scan_under_the_unit_capabilities",
                "--test-threads=1",
            ])
            .env("LVE_UNIT_CAPS", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "limited-capability child failed: {status}"
        );
        return;
    }
    linux_vault_helper::limit_to_unit_capabilities();
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    let note = folder.join("note.txt");
    fs::write(&note, b"hello\n").unwrap();

    let mut quiet = std::process::Command::new("python3")
        .arg("-c")
        .arg("import ctypes, time\nctypes.CDLL(None).prctl(4, 0, 0, 0, 0)\ntime.sleep(120)\n")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let maps = format!("/proc/{}/maps", quiet.id());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match fs::read(&maps) {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => break,
            _ if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            other => panic!("non-dumpable process stayed readable: {other:?}"),
        }
    }
    proxy.lock("Forge").await.unwrap();
    let _ = quiet.kill();
    let _ = quiet.wait();
    assert!(!folder.exists());

    proxy.unlock("Forge").await.unwrap();
    assert!(note.is_file(), "unlock did not restore the note");
    let holder_err = session.dir.path.join("holder-err");
    let mut holder = std::process::Command::new("python3")
        .arg("-c")
        .arg("import sys, time\nf = open(sys.argv[1], 'rb')\ntime.sleep(120)\n")
        .arg(&note)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(fs::File::create(&holder_err).unwrap())
        .spawn()
        .unwrap();
    let fd_dir = format!("/proc/{}/fd", holder.id());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = holder.try_wait().unwrap() {
            panic!(
                "holder exited {status}: {}",
                fs::read_to_string(&holder_err).unwrap_or_default()
            );
        }
        let links: Vec<_> = fs::read_dir(&fd_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|entry| fs::read_link(entry.path()).ok())
                    .collect()
            })
            .unwrap_or_default();
        if links.iter().any(|link| link == &note) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("holder did not open {}: {links:?}", note.display());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let error = proxy.lock("Forge").await.unwrap_err().to_string();
    assert!(
        error.contains("note.txt is open in") && error.contains(&holder.id().to_string()),
        "{error}"
    );
    let listed = proxy.list().await.unwrap();
    assert_eq!(listed[0].state, "unlocked", "{listed:?}");
    let _ = holder.kill();
    let _ = holder.wait();
    proxy.lock("Forge").await.unwrap();
    assert!(!folder.exists());
}

#[tokio::test]
async fn lock_without_a_held_passphrase_asks_twice_and_forgets_it() {
    let session = session("secret").await;
    let folder = session.dir.path.join("Forge");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    let (vaults, _) = Vaults::open(session.dir.path.join("registry"), &session.dir.path)
        .unwrap()
        .trace_immutable_flag();
    vaults.create(&folder).unwrap();

    let proxy = proxy(&session.client).await;
    proxy.lock("Forge").await.unwrap();
    assert!(!folder.exists());
    assert!(session.dir.path.join("Forge.7z").is_file());
    assert!(!session.held.contains("Forge"));
    let transcript = fs::read_to_string(&session.log).unwrap();
    assert!(
        transcript.contains("SETREPEAT Repeat passphrase:")
            && transcript.contains("Confirm the passphrase for Forge."),
        "{transcript}"
    );
}

#[tokio::test]
async fn recovery_without_a_repeated_passphrase_leaves_the_folder() {
    let session = session("wrong").await;
    let folder = session.dir.path.join("Forge");
    let (vaults, _) = Vaults::open(session.dir.path.join("registry"), &session.dir.path)
        .unwrap()
        .trace_immutable_flag();
    vaults.create(&folder).unwrap();

    let proxy = proxy(&session.client).await;
    let error = proxy.lock("Forge").await.unwrap_err().to_string();
    assert!(error.contains("did not confirm the passphrase"), "{error}");
    assert!(folder.is_dir());
    assert!(!session.dir.path.join("Forge.7z").exists());
    assert!(!session.held.contains("Forge"));
}

#[tokio::test]
async fn list_returns_this_caller_s_vaults_and_not_another_path() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();

    let outside_root = std::env::temp_dir();
    let outside = outside_root.join(format!("lve-foreign-{}", process::id()));
    let _ = fs::remove_dir_all(&outside);
    let (vaults, _) = Vaults::open(session.dir.path.join("registry"), &outside_root)
        .unwrap()
        .trace_immutable_flag();
    vaults.create(&outside).unwrap();

    let listed = proxy.list().await.unwrap();
    assert!(listed.iter().any(|vault| vault.name == "Forge"
        && vault.state == "unlocked"
        && vault.path == folder.to_str().unwrap()));
    assert!(listed
        .iter()
        .all(|vault| vault.name != "Foreign" && !vault.path.contains("lve-foreign")));
    let _ = fs::remove_dir_all(&outside);

    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    proxy.lock("Forge").await.unwrap();
    let listed = proxy.list().await.unwrap();
    assert_eq!(listed[0].state, "locked");
}

#[tokio::test]
async fn remove_of_an_unlocked_vault_drops_the_registry_entry_and_the_key() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    let bookmarks = session.dir.path.join(".config/gtk-3.0");
    fs::create_dir_all(&bookmarks).unwrap();
    fs::write(
        bookmarks.join("bookmarks"),
        format!("file://{}\n", folder.display()),
    )
    .unwrap();

    proxy.remove("Forge").await.unwrap();
    assert!(folder.is_dir());
    assert!(!session.held.contains("Forge"));
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert!(vaults.get("Forge").is_err());
    let text = fs::read_to_string(bookmarks.join("bookmarks")).unwrap();
    assert!(text.contains("Forge"), "{text}");
}

#[tokio::test]
async fn remove_of_a_locked_vault_unlocks_then_forgets_the_key() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    proxy.lock("Forge").await.unwrap();

    proxy.remove("Forge").await.unwrap();
    assert_eq!(fs::read(folder.join("note.txt")).unwrap(), b"hello\n");
    assert!(!session.held.contains("Forge"));
    assert_eq!(
        session.flags.calls(),
        vec![FlagChange::Set, FlagChange::Clear]
    );
    let transcript = fs::read_to_string(&session.log).unwrap();
    assert!(transcript.contains("Unlock Forge."), "{transcript}");
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert!(vaults.get("Forge").is_err());
}

#[tokio::test]
async fn terminate_of_an_unlocked_vault_checks_the_held_key_and_deletes_the_folder() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    let bookmarks = session.dir.path.join(".config/gtk-3.0");
    fs::create_dir_all(&bookmarks).unwrap();
    fs::write(
        bookmarks.join("bookmarks"),
        format!(
            "file://{}\nfile://{}/Anvil\n",
            folder.display(),
            session.dir.path.display()
        ),
    )
    .unwrap();

    proxy.terminate("Forge").await.unwrap();
    assert!(!folder.exists());
    assert!(!session.held.contains("Forge"));
    let text = fs::read_to_string(bookmarks.join("bookmarks")).unwrap();
    assert!(!text.contains("Forge"), "{text}");
    assert!(text.contains("Anvil"), "{text}");
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert!(vaults.get("Forge").is_err());
}

#[tokio::test]
async fn terminate_rejects_a_passphrase_that_does_not_match_the_held_key() {
    let session = session("terminate-wrong").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();

    let error = proxy.terminate("Forge").await.unwrap_err().to_string();
    assert!(error.contains("wrong passphrase"), "{error}");
    assert!(folder.is_dir());
    assert!(session.held.contains("Forge"));
}

#[tokio::test]
async fn terminate_of_a_locked_vault_tests_the_archive_and_removes_the_registry_last() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    proxy.lock("Forge").await.unwrap();

    proxy.terminate("Forge").await.unwrap();
    assert!(!session.dir.path.join("Forge.7z").exists());
    assert!(!session.held.contains("Forge"));
    assert_eq!(
        session.flags.calls(),
        vec![FlagChange::Set, FlagChange::Clear]
    );
    let transcript = fs::read_to_string(&session.log).unwrap();
    assert!(transcript.contains("Terminate Forge."), "{transcript}");
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert!(vaults.get("Forge").is_err());
}

#[tokio::test]
async fn terminate_of_a_vault_that_needs_recovery_says_to_lock_first() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    let registry = session.dir.path.join("registry/registry.json");
    let text = fs::read_to_string(&registry).unwrap();
    fs::write(
        &registry,
        text.replace("\"unlocked\"", "\"needs_recovery\""),
    )
    .unwrap();

    let error = proxy.terminate("Forge").await.unwrap_err().to_string();
    assert!(error.contains("needs recovery; lock it first"), "{error}");
    assert!(folder.is_dir());
    let transcript = fs::read_to_string(&session.log).unwrap();
    assert!(
        !transcript.contains("Terminate"),
        "terminate must not prompt: {transcript}"
    );
    let text = fs::read_to_string(&registry).unwrap();
    assert!(text.contains("Forge"), "{text}");
}

#[tokio::test]
async fn a_finished_terminate_drops_the_registry_entry_and_the_bookmark() {
    let dir = TempDir::new();
    fs::create_dir_all(dir.path.join("registry")).unwrap();
    let vaults = Vaults::open(dir.path.join("registry"), &dir.path).unwrap();
    let folder = dir.path.join("Forge");
    fs::create_dir_all(folder.join("nested")).unwrap();
    fs::write(folder.join("nested/hello.txt"), b"hello\n").unwrap();
    vaults.create(&folder).unwrap();
    fs::remove_dir_all(&folder).unwrap();
    let bookmarks = dir.path.join(".config/gtk-3.0");
    fs::create_dir_all(&bookmarks).unwrap();
    fs::write(
        bookmarks.join("bookmarks"),
        format!("file://{}\nfile:///keep/Other\n", folder.display()),
    )
    .unwrap();

    let _helper = Helper::new(
        Authorizer::Allow,
        Vaults::open(dir.path.join("registry"), &dir.path).unwrap(),
        Prompt::Program(vec!["true".into()]),
        account(&dir.path),
    )
    .unwrap();
    let text = fs::read_to_string(dir.path.join("registry/registry.json")).unwrap();
    assert!(
        !text.contains("Forge"),
        "a finished terminate is not recovery: {text}"
    );
    let marks = fs::read_to_string(bookmarks.join("bookmarks")).unwrap();
    assert!(!marks.contains("Forge"), "{marks}");
    assert!(marks.contains("/keep/Other"), "{marks}");
}

#[tokio::test]
async fn shutdown_locks_a_held_vault_even_when_a_file_is_open() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    let open = fs::File::open(folder.join("note.txt")).unwrap();

    session.shutdown.shut_down().await;
    drop(open);
    assert!(!folder.exists());
    assert!(session.dir.path.join("Forge.7z").is_file());
    assert!(!session.held.contains("Forge"));
    let error = proxy.list().await.unwrap_err().to_string();
    assert!(error.contains("shutting down"), "{error}");
}

#[tokio::test]
async fn a_second_shutdown_finds_the_vault_already_locked() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();

    session.shutdown.shut_down().await;
    assert_eq!(session.shutdown.lock_attempts(), 1);
    let archive = fs::metadata(session.dir.path.join("Forge.7z")).unwrap();
    let inode = archive.ino();
    let modified = archive.mtime();

    session.shutdown.shut_down().await;
    assert_eq!(session.shutdown.lock_attempts(), 1);
    let archive = fs::metadata(session.dir.path.join("Forge.7z")).unwrap();
    assert_eq!(archive.ino(), inode);
    assert_eq!(archive.mtime(), modified);
    assert!(!folder.exists());
    assert!(!session.held.contains("Forge"));
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert_eq!(
        vaults.get("Forge").unwrap().state,
        linux_vault::State::Locked
    );
}

#[tokio::test]
async fn shutdown_marks_an_unlocked_vault_with_no_key_as_recovery() {
    let session = session("secret").await;
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    session.held.forget("Forge").unwrap();

    session.shutdown.shut_down().await;
    assert!(folder.is_dir());
    assert!(!session.dir.path.join("Forge.7z").exists());
    let vaults = Vaults::open(session.dir.path.join("registry"), &session.dir.path).unwrap();
    assert_eq!(
        vaults.get("Forge").unwrap().state,
        linux_vault::State::NeedsRecovery
    );
}

#[tokio::test]
async fn shutdown_cancels_an_open_prompt_and_a_call_waiting_behind_it() {
    let session = session("sleep").await;
    let folder = session.dir.path.join("Forge");
    let path = folder.to_str().unwrap().to_string();
    let client = session.client.clone();
    let first_path = path.clone();
    let first = tokio::spawn(async move {
        proxy(&client)
            .await
            .create(first_path.as_str())
            .await
            .unwrap_err()
            .to_string()
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let transcript = fs::read_to_string(&session.log).unwrap_or_default();
        if transcript.contains("GETPIN") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "prompt did not start: {transcript}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let client = session.client.clone();
    let second = tokio::spawn(async move {
        proxy(&client)
            .await
            .create(path.as_str())
            .await
            .unwrap_err()
            .to_string()
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    session.shutdown.shut_down().await;
    let first = first.await.unwrap();
    let second = second.await.unwrap();
    assert!(
        first.contains("cancelled") || first.contains("shutting down"),
        "{first}"
    );
    assert!(
        second.contains("shutting down") || second.contains("cancelled"),
        "{second}"
    );
    assert!(!folder.exists());
    assert!(!session.held.contains("Forge"));
}

#[tokio::test]
async fn a_mode_700_home_works_without_dac_caps() {
    if std::env::var_os("LVE_LIMITED_CAPS").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "a_mode_700_home_works_without_dac_caps",
                "--test-threads=1",
            ])
            .env("LVE_LIMITED_CAPS", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "limited-capability child failed: {status}"
        );
        return;
    }
    drop_to_unit_caps();
    let unit = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/systemd/linux-vault-helper.service"
    ))
    .unwrap();
    assert!(unit.contains("PrivateTmp=yes"), "{unit}");
    let session = session("secret").await;
    fs::set_permissions(&session.dir.path, fs::Permissions::from_mode(0o700)).unwrap();
    let proxy = proxy(&session.client).await;
    let folder = session.dir.path.join("Forge");
    proxy.create(folder.to_str().unwrap()).await.unwrap();
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    proxy.lock("Forge").await.unwrap();
    assert!(!folder.exists());
    assert!(session.dir.path.join("Forge.7z").is_file());
    let listed = proxy.list().await.unwrap();
    assert_eq!(listed[0].state, "locked");
    assert!(
        fs::read_dir(&session.dir.path)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".lve-worker-")),
        "worker scratch directory was left in the home"
    );
}

fn drop_to_unit_caps() {
    linux_vault_helper::limit_to_unit_capabilities();
}
