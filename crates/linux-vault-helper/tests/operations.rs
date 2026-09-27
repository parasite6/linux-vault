use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;

use linux_vault::{FlagChange, Vaults};
use linux_vault_dbus::{HelperProxy, OBJECT_PATH};
use linux_vault_helper::{Account, Authorizer, Helper, Prompt};
use zbus::connection::Builder;
use zbus::Guid;

/// Drop the override capabilities before tokio starts threads, so every thread
/// inherits the unit's six. The home is mode 700; a later thread that still
/// had those capabilities could still reach the test binary.
#[used]
#[link_section = ".init_array"]
static EARLY_LIMIT: extern "C" fn() = limit_if_requested;

extern "C" fn limit_if_requested() {
    // SAFETY: getenv only reads the environment the loader has already set up.
    let requested = unsafe {
        !nix::libc::getenv(c"LVE_UNIT_CAPS".as_ptr()).is_null()
            || !nix::libc::getenv(c"LVE_LIMITED_CAPS".as_ptr()).is_null()
    };
    if requested {
        linux_vault_helper::limit_to_unit_capabilities();
    }
}

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
        clear_immutable_tree(&self.path);
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Session {
    client: zbus::Connection,
    _server: zbus::Connection,
    dir: TempDir,
    held: linux_vault_helper::HeldPassphrases,
    flags: Option<linux_vault::ImmutableTrace>,
    log: PathBuf,
    shutdown: linux_vault_helper::ShutdownHandle,
}

async fn session(mode: &str) -> Session {
    session_parts(mode, None, true, None).await
}

async fn session_parts(
    mode: &str,
    seven_zip: Option<&std::path::Path>,
    record_flags: bool,
    owner: Option<Account>,
) -> Session {
    let dir = TempDir::new();
    fs::set_permissions(&dir.path, fs::Permissions::from_mode(0o755)).unwrap();
    let home = owner
        .as_ref()
        .map(|owner| owner.home.clone())
        .unwrap_or_else(|| dir.path.clone());
    let script = dir.path.join("pinentry");
    let log = dir.path.join("log");
    let mut file = fs::File::create(&script).unwrap();
    file.write_all(SCRIPT.as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    let mut log_mode = fs::File::create(&log)
        .unwrap()
        .metadata()
        .unwrap()
        .permissions();
    log_mode.set_mode(0o666);
    fs::set_permissions(&log, log_mode).unwrap();
    let opened = Vaults::open(dir.path.join("registry"), &home).unwrap();
    let (mut vaults, flags) = if record_flags {
        let (vaults, flags) = opened.trace_immutable_flag();
        (vaults, Some(flags))
    } else {
        (opened, None)
    };
    if let Some(path) = seven_zip {
        vaults.set_seven_zip(path);
    }
    let helper = Helper::new(
        Authorizer::Allow,
        vaults,
        Prompt::Program(vec![
            script.as_os_str().to_os_string(),
            log.as_os_str().to_os_string(),
            mode.into(),
        ]),
        owner.unwrap_or_else(|| account(&dir.path)),
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

fn caller_uid() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
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
    assert!(session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
    assert_eq!(session.flags.unwrap().calls(), vec![FlagChange::Set]);
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
    assert!(session.held.contains(caller_uid(), "Forge"));
    assert!(session.flags.unwrap().calls().is_empty());
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
    session.held.forget(caller_uid(), "Forge").unwrap();
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
    sweep_stale_test_dirs();
    if std::env::var_os("LVE_UNIT_CAPS").is_none() {
        reexec_limited(
            "open_file_scan_under_the_unit_capabilities",
            "LVE_UNIT_CAPS",
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

    let mut quiet = std::process::Command::new("python3");
    quiet
        .arg("-c")
        .arg(
            "import ctypes, os, time\nctypes.CDLL(None).prctl(4, 0, 0, 0, 0)\nos.write(1, b'ready\\n')\ntime.sleep(120)\n",
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut quiet = quiet.spawn().unwrap();
    let mut ready_pipe = quiet.stdout.take().unwrap();
    {
        use std::os::fd::AsRawFd;
        let fd = ready_pipe.as_raw_fd();
        unsafe {
            let flags = nix::libc::fcntl(fd, nix::libc::F_GETFL);
            nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK);
        }
    }
    let maps = format!("/proc/{}/maps", quiet.id());
    let ptrace = cap_eff() & (1 << 19) != 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut announced = [0u8; 6];
    let mut filled = 0usize;
    loop {
        if filled < announced.len() {
            use std::io::Read;
            match ready_pipe.read(&mut announced[filled..]) {
                Ok(0) => {}
                Ok(n) => filled += n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
        if &announced[..filled] == b"ready\n" {
            let readable = fs::read(&maps).is_ok();
            if ptrace {
                assert!(
                    readable,
                    "helper could not read a non-dumpable root process"
                );
            } else {
                assert!(
                    !readable,
                    "a process without CAP_SYS_PTRACE read a non-dumpable process"
                );
            }
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("process did not finish prctl; stdout so far: {announced:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
    assert_eq!(
        session.flags.unwrap().calls(),
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
    assert_eq!(
        session.flags.unwrap().calls(),
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    assert!(!session.held.contains(caller_uid(), "Forge"));
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
    session.held.forget(caller_uid(), "Forge").unwrap();

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
    assert!(!session.held.contains(caller_uid(), "Forge"));
}

#[tokio::test]
async fn a_mode_700_home_works_without_dac_caps() {
    sweep_stale_test_dirs();
    if std::env::var_os("LVE_LIMITED_CAPS").is_none() {
        let unit = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/systemd/linux-vault-helper.service"
        ))
        .unwrap();
        assert!(unit.contains("PrivateTmp=yes"), "{unit}");
        reexec_limited("a_mode_700_home_works_without_dac_caps", "LVE_LIMITED_CAPS");
        return;
    }
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

#[tokio::test]
async fn shutdown_aborts_an_extract_running_in_the_worker() {
    sweep_stale_test_dirs();
    if std::env::var_os("LVE_UNIT_CAPS").is_none() {
        let _root = root_tests_lock();
        let prepared = prepare_unprivileged_home();
        let (helper, _staged) = stage_outside_home(&helper_binary());
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "shutdown_aborts_an_extract_running_in_the_worker",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LVE_UNIT_CAPS", "1")
            .env("LVE_HELPER_BIN", &helper);
        if let Some(prepared) = &prepared {
            command
                .env("LVE_VAULT_HOME", &prepared.home)
                .env("LVE_SLOW_7Z", &prepared.script);
        }
        let output = supervised(command);
        let text = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "limited-capability child failed: {}\n{out}{text}",
            output.status
        );
        eprint!("{text}");
        print!("{out}");
        return;
    }
    linux_vault_helper::limit_to_unit_capabilities();
    let effective = cap_eff();
    const SIX: u64 = (1 << 3) | (1 << 6) | (1 << 7) | (1 << 9) | (1 << 14) | (1 << 19);
    if effective & (1 << 9) == 0 || effective & (1 << 3) == 0 {
        eprintln!(
            "shutdown_aborts_an_extract_running_in_the_worker: skipped, CAP_LINUX_IMMUTABLE is not effective ({effective:#x})"
        );
        return;
    }
    assert_eq!(
        effective & !SIX,
        0,
        "capabilities outside the unit set are still effective: {effective:#x}"
    );
    let home = PathBuf::from(std::env::var("LVE_VAULT_HOME").expect("LVE_VAULT_HOME"));
    let script = PathBuf::from(std::env::var("LVE_SLOW_7Z").expect("LVE_SLOW_7Z"));
    let (uid, gid) = nobody_ids();
    let session = session_parts(
        "secret",
        Some(&script),
        false,
        Some(Account {
            user: "nobody".into(),
            uid,
            gid,
            home: home.clone(),
        }),
    )
    .await;
    let api = proxy(&session.client).await;
    let folder = home.join("Forge");
    api.create(folder.to_str().unwrap()).await.unwrap();
    write_as(uid, gid, &folder.join("note.txt"), b"hello\n");
    api.lock("Forge").await.unwrap();
    let archive = home.join("Forge.7z");
    assert!(
        immutable_is_set(&archive),
        "lock did not set the immutable flag"
    );
    let client = session.client.clone();
    let unlocking = tokio::spawn(async move { proxy(&client).await.unlock("Forge").await });
    let caps_path = home.join("worker-caps.txt");
    let started = std::time::Instant::now();
    while !caps_path.is_file() {
        if started.elapsed() > std::time::Duration::from_secs(10) {
            panic!("extract did not start");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    session.shutdown.shut_down().await;
    let error = unlocking.await.unwrap().unwrap_err().to_string();
    assert!(
        error.contains("7z failed") || error.contains("stopped") || error.contains("signal"),
        "{error}"
    );
    assert!(archive.is_file());
    assert!(!folder.exists());
    let registry = fs::read_to_string(session.dir.path.join("registry/registry.json")).unwrap();
    assert!(registry.contains("\"locked\""), "{registry}");
    let caps = fs::read_to_string(home.join("worker-caps.txt")).unwrap();
    let worker_eff = caps
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .unwrap_or("");
    assert!(
        worker_eff.ends_with("0000000000000000"),
        "worker could still change the immutable flag: {worker_eff}"
    );
    assert!(
        immutable_is_set(&archive),
        "aborted extract left Forge.7z without the immutable flag"
    );
}

#[tokio::test]
async fn another_user_cannot_operate_the_vault() {
    if std::env::var_os("LVE_PEER").is_some() {
        peer_client().await;
        return;
    }
    sweep_stale_test_dirs();
    if std::env::var_os("LVE_WATCH").is_none() {
        watch_test("another_user_cannot_operate_the_vault");
        return;
    }
    let root = TempDir::new();
    fs::set_permissions(&root.path, fs::Permissions::from_mode(0o755)).unwrap();
    let Some(a) = TempUser::try_create("a", &root.path) else {
        eprintln!("another_user_cannot_operate_the_vault: skipped, useradd cannot create a second uid here");
        return;
    };
    let Some(b) = TempUser::try_create("b", &root.path) else {
        eprintln!("another_user_cannot_operate_the_vault: skipped, useradd cannot create a second uid here");
        return;
    };
    let script = root.path.join("pinentry");
    fs::write(&script, SCRIPT).unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    let log = root.path.join("log");
    fs::write(&log, b"").unwrap();
    let mut log_mode = fs::metadata(&log).unwrap().permissions();
    log_mode.set_mode(0o666);
    fs::set_permissions(&log, log_mode).unwrap();
    let registry = root.path.join("registry");
    let sock = root.path.join("sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o777)).unwrap();

    let created = peer_round(
        &listener,
        &a,
        &sock,
        &registry,
        &root.path,
        &script,
        &log,
        "create",
        a.home.join("Forge").to_str().unwrap(),
    )
    .await;
    assert!(created.contains("OK"), "{created}");

    let missing = peer_round(
        &listener, &a, &sock, &registry, &root.path, &script, &log, "lock", "NoSuch",
    )
    .await;
    for command in ["lock", "unlock", "terminate"] {
        let reply = peer_round(
            &listener, &b, &sock, &registry, &root.path, &script, &log, command, "Forge",
        )
        .await;
        eprintln!("B {command}: {reply}");
        assert_eq!(reply, missing, "{command}");
        assert!(
            reply.contains("org.linuxvault.Error.NotFound"),
            "{command}: {reply}"
        );
        assert!(reply.contains("vault not found"), "{command}: {reply}");
    }
    let listed = peer_round(
        &listener, &b, &sock, &registry, &root.path, &script, &log, "list", "",
    )
    .await;
    eprintln!("B list: {listed}");
    assert!(listed.starts_with("OK"), "{listed}");
    assert!(!listed.contains("Forge"), "{listed}");
}

async fn peer_client() {
    let spec = std::env::var("LVE_PEER").unwrap();
    let mut parts = spec.split('|');
    let sock = parts.next().unwrap();
    let command = parts.next().unwrap();
    let arg = parts.next().unwrap_or("");
    let stream = {
        let mut connected = None;
        for _ in 0..50 {
            match tokio::net::UnixStream::connect(sock).await {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        connected.expect("helper socket")
    };
    let connection = Builder::unix_stream(stream).p2p().build().await.unwrap();
    let proxy = proxy(&connection).await;
    let result = match command {
        "create" => proxy
            .create(arg)
            .await
            .map(|_| "created".to_string())
            .map_err(|error| error.to_string()),
        "lock" => proxy
            .lock(arg)
            .await
            .map(|_| "locked".to_string())
            .map_err(|error| error.to_string()),
        "unlock" => proxy
            .unlock(arg)
            .await
            .map(|_| "unlocked".to_string())
            .map_err(|error| error.to_string()),
        "terminate" => proxy
            .terminate(arg)
            .await
            .map(|_| "terminated".to_string())
            .map_err(|error| error.to_string()),
        "list" => proxy
            .list()
            .await
            .map(|vaults| {
                vaults
                    .into_iter()
                    .map(|vault| vault.name)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .map_err(|error| error.to_string()),
        other => Err(format!("unknown {other}")),
    };
    let line = match result {
        Ok(text) => format!("OK {text}"),
        Err(text) => format!("ERR {text}"),
    };
    write_peer_reply(&line);
}

static REPLY_FILES: AtomicU64 = AtomicU64::new(0);

/// The reply is not written to stdout. The test harness prints there, and a
/// line that starts with `OK` would be glued onto the harness's own line.
fn write_peer_reply(line: &str) {
    let path = std::env::var("LVE_PEER_REPLY").expect("LVE_PEER_REPLY");
    let mut file = fs::File::create(&path).expect("reply file");
    writeln!(file, "{line}").unwrap();
    file.sync_all().unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn peer_round(
    listener: &tokio::net::UnixListener,
    user: &TempUser,
    sock: &std::path::Path,
    registry: &std::path::Path,
    root: &std::path::Path,
    script: &std::path::Path,
    log: &std::path::Path,
    command: &str,
    arg: &str,
) -> String {
    let (program, _staged) = stage_outside_home(&std::env::current_exe().unwrap());
    let reply_path = root.join(format!(
        "reply-{}-{}",
        user.uid,
        REPLY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&reply_path, b"").unwrap();
    fs::set_permissions(&reply_path, fs::Permissions::from_mode(0o666)).unwrap();
    let mut child = std::process::Command::new(&program);
    child
        .args([
            "--exact",
            "another_user_cannot_operate_the_vault",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("LVE_PEER", format!("{}|{command}|{arg}", sock.display()))
        .env("LVE_PEER_REPLY", &reply_path)
        .current_dir("/tmp")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let uid = user.uid;
    let gid = user.gid;
    unsafe {
        child.pre_exec(move || {
            if nix::libc::setgid(gid) != 0 || nix::libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = child.spawn().unwrap();
    let peer_out = child.stdout.take();
    let peer_err = child.stderr.take();
    let out_thread = std::thread::spawn(move || read_pipe(peer_out));
    let err_thread = std::thread::spawn(move || read_pipe(peer_err));
    let accepted =
        tokio::time::timeout(std::time::Duration::from_secs(15), listener.accept()).await;
    let Ok(accepted) = accepted else {
        let _ = child.kill();
        let _ = child.wait();
        let stderr = String::from_utf8_lossy(&err_thread.join().unwrap_or_default()).into_owned();
        panic!("peer connect\n{stderr}");
    };
    let (stream, _) = accepted.unwrap();
    let (vaults, _) = Vaults::open(registry, root).unwrap().trace_immutable_flag();
    let helper = Helper::for_passwd(
        Authorizer::Allow,
        vaults,
        Prompt::Program(vec![
            script.as_os_str().to_os_string(),
            log.as_os_str().to_os_string(),
            "secret".into(),
        ]),
    )
    .unwrap();
    let guid = Guid::generate();
    let server = Builder::unix_stream(stream)
        .server(guid)
        .unwrap()
        .p2p()
        .serve_at(OBJECT_PATH, helper)
        .unwrap()
        .build();
    let served = tokio::time::timeout(std::time::Duration::from_secs(20), server).await;
    let Ok(served) = served else {
        let _ = child.kill();
        let _ = child.wait();
        let stderr = String::from_utf8_lossy(&err_thread.join().unwrap_or_default()).into_owned();
        panic!("peer {command} did not finish\n{stderr}");
    };
    let _server = served.unwrap();
    // `#[tokio::test]` is a current-thread runtime. Waiting here on that
    // thread never polls the connection, so the peer's call cannot be answered.
    let peer_pid = child.id();
    let waiter = tokio::task::spawn_blocking(move || child.wait());
    let status = match tokio::time::timeout(std::time::Duration::from_secs(20), waiter).await {
        Ok(Ok(Ok(status))) => status,
        Ok(Ok(Err(error))) => panic!("peer {command} wait: {error}"),
        Ok(Err(error)) => panic!("peer {command} join: {error}"),
        Err(_) => {
            unsafe {
                nix::libc::kill(peer_pid as i32, nix::libc::SIGKILL);
            }
            let _stdout = out_thread.join().unwrap_or_default();
            let stderr = err_thread.join().unwrap_or_default();
            let raw = fs::read_to_string(&reply_path).unwrap_or_default();
            panic!(
                "peer {command} did not finish\nreply file: {raw}{}",
                String::from_utf8_lossy(&stderr)
            );
        }
    };
    let _stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    let raw = fs::read_to_string(&reply_path).unwrap_or_default();
    let line = raw.lines().next().unwrap_or("");
    if line.starts_with("OK ") || line.starts_with("ERR ") {
        return line.trim().to_string();
    }
    eprintln!(
        "peer {command} status {status}, no reply in {}\n{}",
        reply_path.display(),
        String::from_utf8_lossy(&stderr)
    );
    format!("peer {command} status {status}, no reply")
}

struct TempUser {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
}

impl TempUser {
    fn try_create(which: &str, root: &std::path::Path) -> Option<Self> {
        let name = format!("lve{which}{}", std::process::id());
        let home = root.join(&name);
        fs::create_dir_all(&home).unwrap();
        let mut child = std::process::Command::new("useradd");
        child
            .args(["-M", "-d"])
            .arg(&home)
            .args(["-s", "/sbin/nologin", &name])
            .stderr(std::process::Stdio::piped());
        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(error) => {
                eprintln!("useradd {name}: {error}");
                let _ = fs::remove_dir_all(&home);
                return None;
            }
        };
        let started = std::time::Instant::now();
        let status = loop {
            if started.elapsed() > std::time::Duration::from_secs(15) {
                eprintln!("useradd {name}: timed out waiting for the passwd lock");
                let _ = child.kill();
                let kill_at = std::time::Instant::now();
                while kill_at.elapsed() < std::time::Duration::from_secs(2)
                    && child.try_wait().ok().flatten().is_none()
                {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                let _ = fs::remove_dir_all(&home);
                return None;
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(error) => {
                    eprintln!("useradd {name}: {error}");
                    let _ = fs::remove_dir_all(&home);
                    return None;
                }
            }
        };
        let err = child
            .stderr
            .take()
            .map(|mut pipe| {
                use std::io::Read;
                let mut buf = String::new();
                let _ = pipe.read_to_string(&mut buf);
                buf
            })
            .unwrap_or_default();
        if !status.success() {
            eprintln!("useradd {name}: {err}");
            let _ = fs::remove_dir_all(&home);
            return None;
        }
        let uid = id_number(&name, "-u");
        let gid = id_number(&name, "-g");
        let c_home = std::ffi::CString::new(home.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { nix::libc::chown(c_home.as_ptr(), uid, gid) }, 0);
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        Some(Self {
            name,
            uid,
            gid,
            home,
        })
    }
}

impl Drop for TempUser {
    fn drop(&mut self) {
        let _ = std::process::Command::new("userdel")
            .arg(&self.name)
            .status();
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn id_number(name: &str, flag: &str) -> u32 {
    let output = std::process::Command::new("id")
        .args([flag, name])
        .output()
        .unwrap();
    assert!(output.status.success(), "id {flag} {name}");
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn nobody_ids() -> (u32, u32) {
    let name = std::ffi::CString::new("nobody").unwrap();
    let pwd = unsafe { nix::libc::getpwnam(name.as_ptr()) };
    assert!(!pwd.is_null(), "nobody is not in the password database");
    unsafe { ((*pwd).pw_uid, (*pwd).pw_gid) }
}

struct PreparedHome {
    _dir: TempDir,
    home: PathBuf,
    script: PathBuf,
}

/// A home owned by nobody, prepared while this process can still chown.
/// The limited child has no CAP_CHOWN. The worker then runs as nobody, so an
/// exec does not refill capabilities from the bounding set the way uid 0 does.
fn prepare_unprivileged_home() -> Option<PreparedHome> {
    let (uid, gid) = nobody_ids();
    let dir = TempDir::new();
    fs::set_permissions(&dir.path, fs::Permissions::from_mode(0o755)).unwrap();
    let script = dir.path.join("slow-7z");
    let program = r#"#!/usr/bin/env python3
import os, sys, time
if len(sys.argv) > 1 and sys.argv[1] == "x":
    with open("worker-caps.txt", "w", encoding="utf-8") as out:
        out.write(open("/proc/self/status", encoding="utf-8").read())
    time.sleep(30)
    sys.exit(1)
os.execv("/usr/bin/7z", ["/usr/bin/7z", *sys.argv[1:]])
"#;
    fs::write(&script, program).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let home = dir.path.join("home");
    fs::create_dir(&home).unwrap();
    let c_home = std::ffi::CString::new(home.to_str().unwrap()).unwrap();
    if unsafe { nix::libc::chown(c_home.as_ptr(), uid, gid) } != 0 {
        return None;
    }
    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
    Some(PreparedHome {
        _dir: dir,
        home,
        script,
    })
}

fn write_as(uid: u32, gid: u32, path: &Path, bytes: &[u8]) {
    let mut child = std::process::Command::new("python3");
    child
        .arg("-c")
        .arg("import sys; open(sys.argv[1], 'wb').write(sys.stdin.buffer.read())")
        .arg(path)
        .stdin(std::process::Stdio::piped());
    unsafe {
        child.pre_exec(move || {
            if nix::libc::setgid(gid) != 0 || nix::libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = child.spawn().unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "writing {} as {uid}: {status}",
        path.display()
    );
}

fn cap_eff() -> u64 {
    // `/proc/self/status` is the thread-group leader. The limit applies to
    // the calling thread, which is what file access and exec use.
    let status = fs::read_to_string("/proc/thread-self/status")
        .or_else(|_| fs::read_to_string("/proc/self/status"))
        .unwrap();
    let hex = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap();
    u64::from_str_radix(hex, 16).unwrap()
}

/// One hard link outside the home, removed when this value is dropped.
/// A full copy on every peer round filled `/tmp`, which is RAM.
fn stage_outside_home(source: &Path) -> (PathBuf, StagedBin) {
    static COPIES: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lve-bin-{}-{}",
        process::id(),
        COPIES.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let dest = dir.join(source.file_name().unwrap());
    if fs::hard_link(source, &dest).is_err() {
        fs::copy(source, &dest).unwrap();
    }
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
    (dest, StagedBin { dir })
}

struct StagedBin {
    dir: PathBuf,
}

impl Drop for StagedBin {
    fn drop(&mut self) {
        clear_immutable_tree(&self.dir);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn helper_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("LVE_HELPER_BIN") {
        return PathBuf::from(path);
    }
    let current = std::env::current_exe().unwrap();
    let helper = current
        .parent()
        .and_then(|deps| deps.parent())
        .map(|debug| debug.join("linux-vault-helper"))
        .expect("test binary has no parent");
    assert!(
        helper.is_file(),
        "helper binary is missing at {}",
        helper.display()
    );
    helper
}

fn reexec_limited(test_name: &str, flag: &str) {
    let _root = root_tests_lock();
    sweep_stale_test_dirs();
    let (helper, _staged) = stage_outside_home(&helper_binary());
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
        .env(flag, "1")
        .env("LVE_HELPER_BIN", &helper);
    let output = supervised(command);
    let text = String::from_utf8_lossy(&output.stderr);
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "limited-capability child failed: {}\n{out}{text}",
        output.status
    );
    eprint!("{text}");
    print!("{out}");
}

fn watch_test(test_name: &str) {
    let _root = root_tests_lock();
    sweep_stale_test_dirs();
    // The worker execs this after setuid. A copy under a mode 700 home is
    // unreachable by the other user, so the watched process gets one outside.
    let (helper, _staged) = stage_outside_home(&helper_binary());
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
        .env("LVE_WATCH", "1")
        .env("LVE_HELPER_BIN", &helper);
    let output = supervised(command);
    let text = String::from_utf8_lossy(&output.stderr);
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{test_name} failed: {}\n{out}{text}",
        output.status
    );
    eprint!("{text}");
    print!("{out}");
}

/// Run `command` in its own process group and kill that group after 60 seconds.
fn supervised(mut command: std::process::Command) -> std::process::Output {
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_thread = std::thread::spawn(move || read_pipe(stdout));
    let err_thread = std::thread::spawn(move || read_pipe(stderr));
    let start = std::time::Instant::now();
    let limit = std::time::Duration::from_secs(60);
    let mut timed_out = false;
    let status = loop {
        if start.elapsed() > limit {
            timed_out = true;
            let pgid = process_group(pid);
            if pgid == Some(pid as i32) {
                unsafe {
                    nix::libc::kill(-(pid as i32), nix::libc::SIGKILL);
                }
            }
            let _ = child.kill();
            break child.wait().unwrap();
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    cleanup_after(pid);
    if timed_out {
        panic!(
            "test exceeded 60s and was killed\n{}",
            String::from_utf8_lossy(&stderr)
        );
    }
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

fn read_pipe(mut pipe: Option<impl std::io::Read>) -> Vec<u8> {
    let Some(ref mut pipe) = pipe else {
        return Vec::new();
    };
    read_limited(pipe)
}

fn read_limited(pipe: &mut dyn std::io::Read) -> Vec<u8> {
    const CAP: usize = 64 * 1024;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < CAP {
                    let keep = n.min(CAP - buf.len());
                    buf.extend_from_slice(&chunk[..keep]);
                }
            }
        }
    }
    buf
}

fn root_tests_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn process_group(pid: u32) -> Option<i32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(2)?.parse().ok()
}

fn remove_test_dirs(pid: u32) {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if dir_pid(&name) == Some(pid) {
            clear_immutable_tree(&entry.path());
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Drop `lve-bin-*` and `lve-ops-*` left by a process that is already gone.
fn sweep_stale_test_dirs() {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = dir_pid(&name) else {
            continue;
        };
        if pid == process::id() || Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        clear_immutable_tree(&entry.path());
        let _ = fs::remove_dir_all(entry.path());
    }
}

fn dir_pid(name: &str) -> Option<u32> {
    let rest = name
        .strip_prefix("lve-bin-")
        .or_else(|| name.strip_prefix("lve-ops-"))?;
    rest.split('-').next()?.parse().ok()
}

fn cleanup_after(pid: u32) {
    kill_descendants(pid);
    // Temps created in the child are named with the child's pid. The staged
    // helper in this process is removed by `StagedBin`, not by a prefix on
    // our own pid: other tests in this process share that pid.
    remove_test_dirs(pid);
    for which in ["a", "b"] {
        let _ = std::process::Command::new("userdel")
            .arg(format!("lve{which}{pid}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn kill_descendants(root: u32) {
    let mut children = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let ppid = rest
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse().ok());
        if ppid == Some(root) {
            children.push(pid);
        }
    }
    for pid in children {
        kill_descendants(pid);
        unsafe {
            nix::libc::kill(pid as i32, nix::libc::SIGKILL);
        }
    }
}

fn clear_immutable_tree(path: &Path) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                clear_immutable_tree(&entry.path());
            }
        }
        return;
    }
    if meta.is_file() {
        clear_immutable_file(path);
    }
}

fn clear_immutable_file(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let fd = unsafe { nix::libc::open(name.as_ptr(), nix::libc::O_RDONLY | nix::libc::O_CLOEXEC) };
    if fd < 0 {
        return;
    }
    let mut flags: nix::libc::c_long = 0;
    if unsafe { nix::libc::ioctl(fd, nix::libc::FS_IOC_GETFLAGS, &mut flags) } == 0
        && flags & 0x10 != 0
    {
        flags &= !0x10;
        unsafe {
            nix::libc::ioctl(fd, nix::libc::FS_IOC_SETFLAGS, &flags);
        }
    }
    unsafe {
        nix::libc::close(fd);
    }
}

/// `FS_IMMUTABLE_FL`. Reading it does not require a capability.
fn immutable_is_set(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { nix::libc::open(name.as_ptr(), nix::libc::O_RDONLY | nix::libc::O_CLOEXEC) };
    assert!(fd >= 0, "opening {} for the immutable flag", path.display());
    let mut flags: nix::libc::c_long = 0;
    let rc = unsafe { nix::libc::ioctl(fd, nix::libc::FS_IOC_GETFLAGS, &mut flags) };
    unsafe { nix::libc::close(fd) };
    assert_eq!(rc, 0, "reading the immutable flag on {}", path.display());
    flags & 0x10 != 0
}
