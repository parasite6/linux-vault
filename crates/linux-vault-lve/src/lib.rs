//! `lve` talks to the helper. It never asks for a passphrase on stdin.
//!
//! The connection comes from [`linux_vault_dbus::connect_client`], which sets
//! no method timeout. Lock and unlock wait while pinentry and 7z run.
//! Ctrl-C ends this process; the helper still finishes the call it accepted.

use std::io::Write;
use std::time::Duration;

use linux_vault_dbus::{HelperProxy, VaultStatus, OBJECT_PATH};
use zbus::Connection;

pub const OK: u8 = 0;
pub const FAILURE: u8 = 1;
pub const USAGE: u8 = 2;
pub const WRONG_PASSPHRASE: u8 = 3;
pub const BUSY: u8 = 4;
pub const OPEN_FILE: u8 = 5;
pub const NEEDS_RECOVERY: u8 = 6;
pub const NOT_AUTHORIZED: u8 = 7;
pub const NOT_LOGGED_IN: u8 = 8;
pub const NO_SPACE: u8 = 9;
pub const CANCELLED: u8 = 10;
pub const NOT_FOUND: u8 = 11;

const HELP: &str = "\
lve — lock a folder in your home

Usage:
  lve [--json] create <path>
  lve [--json] lock <name>
  lve [--json] unlock <name>
  lve [--json] ls
  lve [--json] remove <name>
  lve [--json] terminate <name>

The passphrase is typed into pinentry, not here. --json prints one JSON
object per line on stdout. While a lock or unlock runs, a status line
reports the state locking or unlocking. That is not a percentage.
Vaults that need recovery are reported on stderr.

Exit codes:
  0   success
  1   other failure
  2   usage
  3   wrong passphrase
  4   busy
  5   a file in the vault is open
  6   needs recovery
  7   not authorized
  8   not logged in
  9   not enough free space
  10  prompt cancelled
  11  vault not found
";

#[derive(Debug)]
pub enum Invocation {
    Help,
    Run(Request),
}

#[derive(Debug)]
pub struct Request {
    pub json: bool,
    pub command: Command,
}

#[derive(Debug)]
pub enum Command {
    Create(String),
    Lock(String),
    Unlock(String),
    List,
    Remove(String),
    Terminate(String),
}

pub fn parse(args: &[String]) -> Result<Invocation, u8> {
    let mut json = false;
    let mut words = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => return Ok(Invocation::Help),
            "--json" => json = true,
            word if word.starts_with('-') => return Err(USAGE),
            word => words.push(word),
        }
    }
    let command = match words.as_slice() {
        ["create", path] => Command::Create((*path).to_string()),
        ["lock", name] => Command::Lock((*name).to_string()),
        ["unlock", name] => Command::Unlock((*name).to_string()),
        ["ls"] => Command::List,
        ["remove", name] => Command::Remove((*name).to_string()),
        ["terminate", name] => Command::Terminate((*name).to_string()),
        _ => return Err(USAGE),
    };
    Ok(Invocation::Run(Request { json, command }))
}

pub fn write_usage(err: &mut impl Write) {
    let _ = writeln!(err, "lve: see `lve --help`");
}

pub fn write_help(out: &mut impl Write) {
    let _ = write!(out, "{HELP}");
}

pub async fn run<O, E>(
    connection: &Connection,
    request: &Request,
    stdout: &mut O,
    stderr: &mut E,
) -> u8
where
    O: Write,
    E: Write,
{
    let proxy = match HelperProxy::builder(connection)
        .path(OBJECT_PATH)
        .unwrap()
        .build()
        .await
    {
        Ok(proxy) => proxy,
        Err(error) => {
            report(stdout, stderr, request.json, &error);
            return FAILURE;
        }
    };
    let code = match &request.command {
        Command::Create(path) => succeed(
            stdout,
            stderr,
            request.json,
            &proxy.create(path).await,
            serde_json::json!({"event": "created", "path": path}),
            &format!("Registered {path}."),
        ),
        Command::Lock(name) => {
            let poll = proxy.clone();
            let result = watch(poll, name, request.json, stdout, stderr, proxy.lock(name)).await;
            succeed(
                stdout,
                stderr,
                request.json,
                &result,
                serde_json::json!({"event": "locked", "name": name}),
                &format!("Locked {name}."),
            )
        }
        Command::Unlock(name) => {
            let poll = proxy.clone();
            let result = watch(poll, name, request.json, stdout, stderr, proxy.unlock(name)).await;
            succeed(
                stdout,
                stderr,
                request.json,
                &result,
                serde_json::json!({"event": "unlocked", "name": name}),
                &format!("Unlocked {name}."),
            )
        }
        Command::Remove(name) => succeed(
            stdout,
            stderr,
            request.json,
            &proxy.remove(name).await,
            serde_json::json!({"event": "removed", "name": name}),
            &format!("Removed {name}."),
        ),
        Command::Terminate(name) => succeed(
            stdout,
            stderr,
            request.json,
            &proxy.terminate(name).await,
            serde_json::json!({"event": "terminated", "name": name}),
            &format!("Terminated {name}."),
        ),
        Command::List => match proxy.list().await {
            Ok(listed) => {
                write_list(stdout, request.json, &listed);
                remind(stderr, request.json, &listed);
                return OK;
            }
            Err(error) => {
                report(stdout, stderr, request.json, &error);
                exit_for_error(&error)
            }
        },
    };
    if let Ok(listed) = proxy.list().await {
        remind(stderr, request.json, &listed);
    }
    code
}

fn write_list<O: Write>(stdout: &mut O, json: bool, listed: &[VaultStatus]) {
    for vault in listed {
        if json {
            json_line(
                stdout,
                &serde_json::json!({
                    "event": "vault",
                    "name": vault.name,
                    "path": vault.path,
                    "state": vault.state,
                }),
            );
        } else {
            let _ = writeln!(stdout, "{}\t{}\t{}", vault.name, vault.state, vault.path);
        }
    }
}

fn remind<E: Write>(stderr: &mut E, json: bool, listed: &[VaultStatus]) {
    for vault in listed
        .iter()
        .filter(|vault| vault.state == "needs_recovery")
    {
        if json {
            json_line(
                stderr,
                &serde_json::json!({
                    "type": "recovery_needed",
                    "vault": vault.name,
                }),
            );
        } else {
            let _ = writeln!(
                stderr,
                "{} needs recovery; lock it to set the passphrase.",
                vault.name
            );
        }
    }
}

async fn watch<O, E>(
    poll: HelperProxy<'_>,
    name: &str,
    json: bool,
    stdout: &mut O,
    stderr: &mut E,
    call: impl std::future::Future<Output = zbus::Result<()>>,
) -> zbus::Result<()>
where
    O: Write,
    E: Write,
{
    let mut call = std::pin::pin!(call);
    let mut seen = String::new();
    loop {
        tokio::select! {
            biased;
            result = &mut call => return result,
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                let Ok(listed) = poll.list().await else { continue };
                let Some(vault) = listed.iter().find(|vault| vault.name == name) else {
                    continue;
                };
                if vault.state == seen || (vault.state != "locking" && vault.state != "unlocking") {
                    continue;
                }
                seen = vault.state.clone();
                if json {
                    json_line(
                        stdout,
                        &serde_json::json!({
                            "type": "status",
                            "vault": name,
                            "state": seen,
                        }),
                    );
                } else {
                    let _ = writeln!(stderr, "status: {name} {seen}");
                }
            }
        }
    }
}

fn succeed<O, E>(
    stdout: &mut O,
    stderr: &mut E,
    json: bool,
    result: &zbus::Result<()>,
    event: serde_json::Value,
    human: &str,
) -> u8
where
    O: Write,
    E: Write,
{
    match result {
        Ok(()) => {
            if json {
                json_line(stdout, &event);
            } else {
                let _ = writeln!(stdout, "{human}");
            }
            OK
        }
        Err(error) => {
            report(stdout, stderr, json, error);
            exit_for_error(error)
        }
    }
}

fn report<O: Write, E: Write>(stdout: &mut O, stderr: &mut E, json: bool, error: &zbus::Error) {
    let message = error_text(error);
    let code = exit_for_error(error);
    if json {
        json_line(
            stdout,
            &serde_json::json!({"event": "error", "exit": code, "message": message}),
        );
    }
    let _ = writeln!(stderr, "lve: {message}");
}

fn error_text(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(_, Some(message), _) => message.clone(),
        other => other.to_string(),
    }
}

fn exit_for_error(error: &zbus::Error) -> u8 {
    match error {
        zbus::Error::MethodError(name, message, _) => {
            exit_code_for(name.as_str(), message.as_deref().unwrap_or(""))
        }
        other => exit_code_for("", &other.to_string()),
    }
}

fn exit_code_for(name: &str, message: &str) -> u8 {
    if name.ends_with("NotAuthorized") {
        return NOT_AUTHORIZED;
    }
    if name.ends_with("NotLoggedIn") {
        return NOT_LOGGED_IN;
    }
    if name.ends_with("Cancelled") {
        return CANCELLED;
    }
    if name.ends_with("NotFound") {
        return NOT_FOUND;
    }
    let lower = message.to_ascii_lowercase();
    if lower.contains("wrong passphrase") {
        return WRONG_PASSPHRASE;
    }
    if lower.contains("is open in") || lower.contains("files are open") {
        return OPEN_FILE;
    }
    if lower.contains("needs recovery") {
        return NEEDS_RECOVERY;
    }
    if lower.contains("no space left") || lower.contains("os error 28") {
        return NO_SPACE;
    }
    if lower.contains("vault registry is busy")
        || lower.contains("that is locking")
        || lower.contains("that is unlocking")
    {
        return BUSY;
    }
    FAILURE
}

fn json_line(out: &mut impl Write, value: &serde_json::Value) {
    let _ = writeln!(out, "{value}");
}

#[cfg(test)]
mod exit_tests {
    use super::*;

    #[test]
    fn helper_errors_keep_their_exit_codes() {
        assert_eq!(
            exit_code_for("org.linuxvault.Error.NotAuthorized", "denied"),
            NOT_AUTHORIZED
        );
        assert_eq!(
            exit_code_for("org.linuxvault.Error.NotLoggedIn", "not logged in"),
            NOT_LOGGED_IN
        );
        assert_eq!(
            exit_code_for("org.linuxvault.Error.Cancelled", "cancelled"),
            CANCELLED
        );
        assert_eq!(
            exit_code_for("org.linuxvault.Error.NotFound", "vault not found"),
            NOT_FOUND
        );
        assert_eq!(
            exit_code_for("org.linuxvault.Error.Failed", "wrong passphrase: no"),
            WRONG_PASSPHRASE
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "cannot lock Forge: note.txt is open in lve (pid 1)"
            ),
            OPEN_FILE
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "cannot lock Forge: files are open in lve (pid 1)"
            ),
            OPEN_FILE
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "Forge needs recovery; lock it first, then terminate"
            ),
            NEEDS_RECOVERY
        );
        assert_eq!(
            exit_code_for("org.linuxvault.Error.Failed", "vault registry is busy"),
            BUSY
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "cannot lock a vault that is locking"
            ),
            BUSY
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "cannot unlock a vault that is unlocking"
            ),
            BUSY
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "No space left on device (os error 28)"
            ),
            NO_SPACE
        );
        assert_eq!(
            exit_code_for(
                "org.linuxvault.Error.Failed",
                "cannot lock a vault that is locked"
            ),
            FAILURE
        );
    }

    #[test]
    fn help_and_usage() {
        assert!(matches!(parse(&[]), Err(USAGE)));
        assert!(matches!(
            parse(&["--help".into()]).unwrap(),
            Invocation::Help
        ));
        let Ok(Invocation::Run(request)) = parse(&["--json".into(), "ls".into()]) else {
            panic!("ls");
        };
        assert!(request.json);
        assert!(matches!(request.command, Command::List));
        assert!(parse(&["lock".into()]).is_err());
        assert!(parse(&["--nope".into(), "ls".into()]).is_err());
    }
}
