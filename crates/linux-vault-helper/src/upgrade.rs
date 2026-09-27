//! Probe used to prove a replaced helper binary can still start workers.
//!
//! The test copies this binary, runs it, then renames a new file over that
//! path. Workers are exec'd from `/proc/self/exe`, which still names the
//! loaded inode.

use std::path::Path;

use linux_vault::Vaults;
use linux_vault_dbus::{HelperProxy, OBJECT_PATH};
use zbus::connection::Builder;
use zbus::Guid;

use crate::{Account, Authorizer, Helper, Prompt};

const PINENTRY: &str = r#"#!/usr/bin/env python3
import sys
sys.stdout.write("OK Pleased to meet you\n")
sys.stdout.flush()
for raw in sys.stdin:
    line = raw.rstrip("\r\n")
    if line == "BYE" or line.startswith("BYE "):
        sys.stdout.write("OK\n")
        sys.stdout.flush()
        break
    if line != "GETPIN":
        sys.stdout.write("OK\n")
        sys.stdout.flush()
        continue
    sys.stdout.write("S PIN_REPEATED\nD secret\nOK\n")
    sys.stdout.flush()
"#;

pub async fn replaced_binary_probe(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let script = dir.join("pinentry");
    let log = dir.join("pinentry-log");
    std::fs::write(&script, PINENTRY).map_err(|error| error.to_string())?;
    std::fs::write(&log, b"").map_err(|error| error.to_string())?;
    let mut mode = std::fs::metadata(&script)
        .map_err(|error| error.to_string())?
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&script, mode).map_err(|error| error.to_string())?;
    let vaults = Vaults::open(dir.join("registry"), dir).map_err(|error| error.to_string())?;
    let uid = unsafe { nix::libc::geteuid() };
    let gid = unsafe { nix::libc::getegid() };
    let helper = Helper::new(
        Authorizer::Allow,
        vaults,
        Prompt::Program(vec![script.into(), log.into(), "secret".into()]),
        Account {
            user: "probe".into(),
            uid,
            gid,
            home: dir.to_path_buf(),
        },
    )
    .map_err(|error| error.to_string())?;
    let shutdown = helper.shutdown_handle();
    let (client_stream, server_stream) =
        tokio::net::UnixStream::pair().map_err(|error| error.to_string())?;
    let server = Builder::unix_stream(server_stream)
        .server(Guid::generate())
        .map_err(|error| error.to_string())?
        .p2p()
        .serve_at(OBJECT_PATH, helper)
        .map_err(|error| error.to_string())?
        .build();
    let client = Builder::unix_stream(client_stream).p2p().build();
    let (client, _server) = tokio::try_join!(client, server).map_err(|error| error.to_string())?;
    let proxy = HelperProxy::builder(&client)
        .path(OBJECT_PATH)
        .map_err(|error| error.to_string())?
        .build()
        .await
        .map_err(|error| error.to_string())?;
    let folder = dir.join("Photos");
    proxy
        .create(folder.to_str().ok_or("path")?)
        .await
        .map_err(|error| error.to_string())?;
    std::fs::write(folder.join("note.txt"), b"kept\n").map_err(|error| error.to_string())?;
    std::fs::write(dir.join("ready"), b"ready\n").map_err(|error| error.to_string())?;
    let go = dir.join("go");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !go.exists() {
        if std::time::Instant::now() >= deadline {
            return Err("replacement was not signalled".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    proxy
        .lock("Photos")
        .await
        .map_err(|error| error.to_string())?;
    proxy
        .unlock("Photos")
        .await
        .map_err(|error| error.to_string())?;
    shutdown.shut_down().await;
    if folder.exists() {
        return Err("stop left the plaintext folder".into());
    }
    if !dir.join("Photos.7z").is_file() {
        return Err("stop did not leave the archive".into());
    }
    std::fs::write(dir.join("result"), b"ok\n").map_err(|error| error.to_string())?;
    Ok(())
}
