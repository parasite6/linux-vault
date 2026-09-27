use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use linux_vault::Vaults;
use linux_vault_dbus::OBJECT_PATH;
use linux_vault_helper::{Account, Authorizer, Helper, Prompt};
use linux_vault_lve::{
    parse, run, write_usage, Invocation, CANCELLED, NEEDS_RECOVERY, NOT_AUTHORIZED, NOT_FOUND, OK,
    OPEN_FILE, USAGE, WRONG_PASSPHRASE,
};
use tokio::net::UnixStream;
use zbus::connection::Builder;
use zbus::Guid;

const SCRIPT: &str = r#"#!/usr/bin/env python3
import sys

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
            "lve-cli-{}-{}",
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
}

async fn session(mode: &str, authorizer: Authorizer) -> Session {
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
    let (vaults, _) = Vaults::open(dir.path.join("registry"), &dir.path)
        .unwrap()
        .trace_immutable_flag();
    let meta = fs::metadata("/proc/self").unwrap();
    let helper = Helper::new(
        authorizer,
        vaults,
        Prompt::Program(vec![
            script.as_os_str().to_os_string(),
            log.as_os_str().to_os_string(),
            mode.into(),
        ]),
        Account {
            user: "tester".into(),
            uid: meta.uid(),
            gid: meta.gid(),
            home: dir.path.clone(),
        },
    )
    .unwrap();
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
    }
}

fn request(args: &[&str]) -> linux_vault_lve::Request {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    match parse(&args).unwrap() {
        Invocation::Run(request) => request,
        Invocation::Help => panic!("help"),
    }
}

async fn invoke(session: &Session, args: &[&str]) -> (u8, String, String) {
    let request = request(args);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(&session.client, &request, &mut stdout, &mut stderr).await;
    (
        code,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn usage_does_not_need_the_helper() {
    let mut err = Vec::new();
    write_usage(&mut err);
    assert!(parse(&[]).unwrap_err() == USAGE);
    assert!(String::from_utf8(err).unwrap().contains("--help"));
}

#[tokio::test]
async fn commands_list_lock_and_remind() {
    let session = session("secret", Authorizer::Allow).await;
    let folder = session.dir.path.join("Forge");
    let (code, out, err) = invoke(&session, &["create", folder.to_str().unwrap()]).await;
    assert_eq!(code, OK, "{err}");
    assert!(out.contains("Registered"), "{out}");
    assert!(folder.is_dir());

    let registry = session.dir.path.join("registry/registry.json");
    let text = fs::read_to_string(&registry).unwrap();
    fs::write(
        &registry,
        text.replace("\"unlocked\"", "\"needs_recovery\""),
    )
    .unwrap();

    let (code, out, err) = invoke(&session, &["ls"]).await;
    assert_eq!(code, OK);
    assert!(out.contains("Forge\tneeds_recovery\t"), "{out}");
    assert!(
        err.contains("Forge needs recovery; lock it to set the passphrase."),
        "{err}"
    );

    let (code, out, err) = invoke(&session, &["--json", "ls"]).await;
    assert_eq!(code, OK);
    assert!(out.contains("\"event\":\"vault\""), "{out}");
    assert!(
        !out.contains("recovery_needed"),
        "the reminder stays off stdout: {out}"
    );
    assert!(
        err.contains("{\"type\":\"recovery_needed\",\"vault\":\"Forge\"}"),
        "{err}"
    );

    let (code, out, err) = invoke(&session, &["terminate", "Forge"]).await;
    assert_eq!(code, NEEDS_RECOVERY, "{err} {out}");
    assert!(folder.is_dir());
    assert!(err.contains("needs recovery; lock it first"), "{err}");
}

#[tokio::test]
async fn lock_and_unlock_round_trip_in_json() {
    let session = session("secret", Authorizer::Allow).await;
    let folder = session.dir.path.join("Forge");
    invoke(&session, &["create", folder.to_str().unwrap()]).await;
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();

    let (code, out, err) = invoke(&session, &["--json", "lock", "Forge"]).await;
    assert_eq!(code, OK, "{err} {out}");
    assert!(out.contains("\"event\":\"locked\""), "{out}");
    assert!(!folder.exists());
    assert!(session.dir.path.join("Forge.7z").is_file());

    let (code, out, err) = invoke(&session, &["--json", "unlock", "Forge"]).await;
    assert_eq!(code, OK, "{err} {out}");
    assert!(out.contains("\"event\":\"unlocked\""), "{out}");
    assert_eq!(fs::read(folder.join("note.txt")).unwrap(), b"hello\n");
}

#[tokio::test]
async fn an_open_file_a_wrong_passphrase_and_a_denial_have_their_own_codes() {
    let allowed = session("secret", Authorizer::Allow).await;
    let folder = allowed.dir.path.join("Forge");
    invoke(&allowed, &["create", folder.to_str().unwrap()]).await;
    let note = fs::File::create(folder.join("note.txt")).unwrap();
    let (code, _out, err) = invoke(&allowed, &["lock", "Forge"]).await;
    assert_eq!(code, OPEN_FILE, "{err}");
    assert!(err.contains("is open in"), "{err}");
    drop(note);

    let wrong = session("terminate-wrong", Authorizer::Allow).await;
    let folder = wrong.dir.path.join("Forge");
    invoke(&wrong, &["create", folder.to_str().unwrap()]).await;
    fs::write(folder.join("note.txt"), b"hello\n").unwrap();
    invoke(&wrong, &["lock", "Forge"]).await;
    let (code, _out, err) = invoke(&wrong, &["terminate", "Forge"]).await;
    assert_eq!(code, WRONG_PASSPHRASE, "{err}");

    let denied = session("secret", Authorizer::Deny).await;
    let (code, _out, err) = invoke(&denied, &["ls"]).await;
    assert_eq!(code, NOT_AUTHORIZED, "{err}");
}

#[tokio::test]
async fn a_missing_vault_is_not_found() {
    let session = session("secret", Authorizer::Allow).await;
    let (code, _out, err) = invoke(&session, &["lock", "NoSuch"]).await;
    assert_eq!(code, NOT_FOUND, "{err}");
    assert!(err.contains("vault not found"), "{err}");
}

#[tokio::test]
async fn cancelling_the_prompt_is_its_own_code() {
    let session = session("cancel", Authorizer::Allow).await;
    let folder = session.dir.path.join("Forge");
    let (code, _out, err) = invoke(&session, &["create", folder.to_str().unwrap()]).await;
    assert_eq!(code, CANCELLED, "{err}");
    assert!(!folder.exists());
}
