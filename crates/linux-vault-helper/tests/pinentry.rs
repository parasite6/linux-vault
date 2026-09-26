use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use linux_vault_helper::{CancelToken, Passphrase, Pinentry, PinentryError, Purpose};

const SCRIPT: &str = r#"#!/usr/bin/env python3
import os
import sys
import time

log_path, mode = sys.argv[1], sys.argv[2]
getpins = 0
saw_repeat = False

def say(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()

def confirmed(data):
    say("S PIN_REPEATED")
    say(data)
    say("OK")

if mode == "nologin":
    sys.stderr.write("Failed to connect to bus: No medium found\n")
    sys.stderr.flush()
    sys.exit(1)

if mode == "hang":
    with open(log_path, "w", encoding="utf-8") as log:
        log.write(str(os.getpid()) + "\n")
        log.flush()
    say("OK Pleased to meet you")
    time.sleep(3600)
    sys.exit(0)

say("OK Pleased to meet you")
for raw in sys.stdin:
    line = raw.rstrip("\r\n")
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(line + "\n")
    if line.startswith("SETREPEAT "):
        saw_repeat = True
    if line == "BYE" or line.startswith("BYE "):
        say("OK")
        break
    if line != "GETPIN":
        say("OK")
        continue
    getpins += 1
    if mode == "percent":
        say("D 100%25")
        say("OK")
    elif mode == "lf":
        say("D secret%0A")
        say("OK")
    elif mode == "cr":
        say("D secret%0D")
        say("OK")
    elif mode == "nul":
        say("D %00")
        say("OK")
    elif mode == "cancel":
        say("ERR 83886179 Operation cancelled")
    elif mode == "empty":
        say("D ")
        say("OK")
    elif mode == "confirm":
        if saw_repeat:
            confirmed("D matched")
        else:
            say("ERR 83886141 Passphrases do not match")
    elif mode == "unconfirmed":
        say("D typedonce")
        say("OK")
    elif mode == "mismatch":
        if getpins == 1:
            say("ERR 83886141 Passphrases do not match")
        else:
            confirmed("D again")
    elif mode == "anybyte":
        say("D %41%7E")
        say("OK")
    elif mode == "badescape":
        say("D %2G")
        say("OK")
    elif mode == "timeout":
        say("ERR 83886142 Timeout")
    elif mode == "nodisplay":
        say("S ERROR qt.isatty 83918950")
        say("ERR 83918950 Inappropriate ioctl for device <Pinentry>")
    elif mode == "long":
        sys.stdout.write("D " + ("A" * 5000) + "\n")
        sys.stdout.flush()
    else:
        say("ERR 1 unknown mode")
"#;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static TEMPS: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lve-pinentry-{}-{}",
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

async fn ask(mode: &str, purpose: Purpose) -> (Result<Passphrase, PinentryError>, String) {
    ask_for(mode, purpose).await
}

async fn ask_for(mode: &str, purpose: Purpose) -> (Result<Passphrase, PinentryError>, String) {
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

    let pinentry = Pinentry::argv([script.as_os_str(), log.as_os_str(), mode.as_ref()]);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        pinentry.ask(purpose, "Forge", &CancelToken::new()),
    )
    .await
    .expect("pinentry client hung");
    let transcript = fs::read_to_string(&log).unwrap_or_default();
    let _keep = dir;
    (result, transcript)
}

fn rejection(result: Result<Passphrase, PinentryError>) -> PinentryError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("pinentry accepted a passphrase"),
    }
}

fn assert_sent(transcript: &str, lines: &[&str]) {
    let mut from = 0;
    for line in lines {
        let found = transcript[from..]
            .find(line)
            .unwrap_or_else(|| panic!("{line} missing from {transcript}"));
        from += found + line.len();
    }
}

#[tokio::test]
async fn percent_in_a_passphrase_is_decoded() {
    let (result, transcript) = ask("percent", Purpose::Unlock).await;
    let passphrase = result.unwrap();
    assert_eq!(passphrase.as_bytes(), b"100%");
    let shown = format!("{passphrase:?}");
    assert!(shown.contains("redacted"), "{shown}");
    assert!(!shown.contains("100%"), "{shown}");
    assert_sent(
        &transcript,
        &[
            "SETDESC Unlock Forge.",
            "SETPROMPT Passphrase:",
            "GETPIN",
            "BYE",
        ],
    );
    assert!(!transcript.contains("SETREPEAT "));
}

#[tokio::test]
async fn escaped_line_breaks_are_rejected() {
    for mode in ["lf", "cr"] {
        let (result, _) = ask(mode, Purpose::Unlock).await;
        let error = rejection(result);
        assert!(matches!(error, PinentryError::InvalidPassphrase), "{error}");
        assert!(!error.to_string().contains("secret"), "{error}");
    }
}

#[tokio::test]
async fn escaped_nul_is_rejected() {
    let (result, _) = ask("nul", Purpose::Unlock).await;
    let error = rejection(result);
    assert!(matches!(error, PinentryError::InvalidPassphrase), "{error}");
}

#[tokio::test]
async fn cancel_is_not_a_wrong_passphrase() {
    let (result, transcript) = ask("cancel", Purpose::Terminate).await;
    let error = rejection(result);
    assert!(matches!(error, PinentryError::Cancelled), "{error}");
    assert_eq!(error.to_string(), "cancelled");
    assert!(!error.to_string().to_lowercase().contains("wrong"));
    assert!(transcript.contains("BYE\n"), "{transcript}");
}

#[tokio::test]
async fn empty_entry_is_rejected() {
    let (result, _) = ask("empty", Purpose::Unlock).await;
    let error = rejection(result);
    assert!(matches!(error, PinentryError::InvalidPassphrase), "{error}");
}

#[tokio::test]
async fn create_and_recovery_ask_twice() {
    for purpose in [Purpose::Create, Purpose::Recovery] {
        let (result, transcript) = ask("confirm", purpose).await;
        assert_eq!(result.unwrap().as_bytes(), b"matched");
        assert_eq!(transcript.matches("GETPIN\n").count(), 1, "{transcript}");
        assert_sent(
            &transcript,
            &[
                "SETPROMPT Passphrase:",
                "SETREPEAT Repeat passphrase:",
                "SETREPEATERROR Passphrases do not match.",
                "GETPIN",
                "BYE",
            ],
        );
    }
}

#[tokio::test]
async fn repeat_mismatch_asks_again() {
    let (result, transcript) = ask("mismatch", Purpose::Create).await;
    assert_eq!(result.unwrap().as_bytes(), b"again");
    assert_eq!(transcript.matches("GETPIN\n").count(), 2, "{transcript}");
}

#[tokio::test]
async fn missing_pin_repeated_is_refused() {
    for purpose in [Purpose::Create, Purpose::Recovery] {
        let (result, _) = ask("unconfirmed", purpose).await;
        let error = rejection(result);
        assert!(matches!(error, PinentryError::NotRepeated), "{error}");
        assert!(!error.to_string().contains("typedonce"), "{error}");
        assert!(
            !error.to_string().to_lowercase().contains("cancel"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn any_percent_escape_is_decoded() {
    let (result, _) = ask("anybyte", Purpose::Unlock).await;
    assert_eq!(result.unwrap().as_bytes(), b"A~");
}

#[tokio::test]
async fn malformed_percent_escape_is_an_error() {
    let (result, _) = ask("badescape", Purpose::Unlock).await;
    let error = rejection(result);
    assert!(
        matches!(error, PinentryError::Failed(ref message) if message.contains("percent")),
        "{error}"
    );
}

#[tokio::test]
async fn timeout_and_no_display_are_not_cancelled() {
    let (timeout, _) = ask("timeout", Purpose::Unlock).await;
    let timeout = rejection(timeout);
    assert!(matches!(timeout, PinentryError::Timeout), "{timeout}");
    assert!(!matches!(timeout, PinentryError::Cancelled));

    let display = rejection(ask("nodisplay", Purpose::Unlock).await.0);
    assert!(matches!(display, PinentryError::NoDisplay), "{display}");
    assert!(!matches!(display, PinentryError::Cancelled));
    assert_ne!(timeout.to_string(), display.to_string());
}

#[tokio::test]
async fn a_pinentry_that_exits_is_a_general_failure() {
    let (result, _) = ask_for("nologin", Purpose::Unlock).await;
    let error = rejection(result);
    assert!(
        matches!(error, PinentryError::Failed(ref message) if message.contains("could not start")),
        "{error}"
    );
    assert!(
        !matches!(error, PinentryError::NotLoggedIn { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn a_missing_runtime_directory_is_not_logged_in() {
    let pinentry = Pinentry::systemd_run("nobody", u32::MAX, 65534).unwrap();
    let error = pinentry
        .ask(Purpose::Unlock, "Forge", &CancelToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(error, PinentryError::NotLoggedIn { user: Some(ref user) } if user == "nobody"),
        "{error}"
    );
    let text = error.to_string();
    assert!(text.contains("nobody"), "{text}");
    assert!(text.contains("not logged in"), "{text}");
}

#[test]
fn systemd_run_starts_pinentry_in_the_user_manager() {
    let pinentry = Pinentry::systemd_run("andrewunknown", 1000, 1000).unwrap();
    let command: Vec<_> = pinentry
        .command()
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        command[..5],
        ["systemd-run", "--user", "--pipe", "--wait", "-q",]
    );
    let unit = command[5].strip_prefix("--unit=lve-pinentry-").unwrap();
    assert!(
        unit.len() == 32 && unit.chars().all(|c| c.is_ascii_hexdigit()),
        "{unit}"
    );
    assert_eq!(command.last().map(String::as_str), Some("pinentry-qt"));
    assert!(!command.iter().any(|part| part.contains("--machine")));
    let again = Pinentry::systemd_run("andrewunknown", 1000, 1000).unwrap();
    assert_ne!(command[5], again.command()[5].to_string_lossy());
}

#[tokio::test]
async fn a_prompt_that_never_replies_can_be_cancelled() {
    let result = tokio::time::timeout(Duration::from_secs(5), hang()).await;
    result.expect("cancel hung");
}

async fn hang() {
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
    let pinentry = Pinentry::argv([script.as_os_str(), log.as_os_str(), "hang".as_ref()]);
    let cancel = CancelToken::new();
    let cancel_ask = cancel.clone();
    let asking =
        tokio::spawn(async move { pinentry.ask(Purpose::Unlock, "Forge", &cancel_ask).await });
    let pid = loop {
        if let Ok(text) = fs::read_to_string(&log) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                break pid;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    cancel.cancel();
    let error = asking.await.unwrap().unwrap_err();
    assert!(matches!(error, PinentryError::Cancelled), "{error}");
    assert_eq!(error.to_string(), "cancelled");
    let gone = tokio::time::timeout(Duration::from_secs(2), async {
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(gone.is_ok(), "pinentry pid {pid} is still running");
    let _keep = dir;
}

#[tokio::test]
async fn a_line_past_the_cap_is_an_error_without_the_bytes() {
    let (result, _) = ask("long", Purpose::Unlock).await;
    let error = rejection(result);
    let text = error.to_string();
    assert!(text.contains("too long"), "{text}");
    assert!(!text.contains("AAAA"), "{text}");
}
