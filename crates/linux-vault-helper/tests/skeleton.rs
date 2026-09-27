use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;

use linux_vault::Vaults;
use linux_vault_dbus::{HelperProxy, OBJECT_PATH};
use linux_vault_helper::{
    bus_name_subject, caller_from_connection, Account, Authorizer, Helper, Prompt,
};
use zbus::connection::Builder;
use zbus::Guid;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static TEMPS: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lve-skeleton-{}-{}",
            process::id(),
            TEMPS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn serve(authorizer: Authorizer) -> (zbus::Connection, zbus::Connection, TempDir) {
    let dir = TempDir::new();
    let vaults = Vaults::open(dir.0.join("registry"), &dir.0).unwrap();
    let helper = Helper::new(
        authorizer,
        vaults,
        Prompt::Program(vec![OsString::from("true")]),
        {
            let meta = std::fs::metadata("/proc/self").unwrap();
            Account {
                user: "tester".into(),
                uid: meta.uid(),
                gid: meta.gid(),
                home: dir.0.clone(),
            }
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
    (client, server, dir)
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
async fn an_empty_registry_lists_nothing_and_remove_finds_no_vault() {
    let (client, _server, _dir) = serve(Authorizer::Allow).await;
    let proxy = proxy(&client).await;
    assert!(proxy.list().await.unwrap().is_empty());
    let removed = proxy.remove("Forge").await.unwrap_err().to_string();
    let terminated = proxy.terminate("Forge").await.unwrap_err().to_string();
    assert_eq!(removed, terminated);
    assert!(
        removed.contains("org.linuxvault.Error.NotFound"),
        "{removed}"
    );
    assert!(removed.contains("vault not found"), "{removed}");
}

#[tokio::test]
async fn denied_calls_are_rejected() {
    let (client, _server, _dir) = serve(Authorizer::Deny).await;
    let proxy = proxy(&client).await;
    let error = proxy.lock("Forge").await.unwrap_err();
    assert!(error.to_string().contains("NotAuthorized"), "{error}");
}

#[tokio::test]
async fn peer_credentials_name_this_process() {
    let (_client, server, _dir) = serve(Authorizer::Allow).await;
    let caller = caller_from_connection(&server, None).await.unwrap();
    assert_eq!(caller.uid, unsafe { nix::libc::getuid() });
    assert_eq!(caller.pid, process::id());
    assert!(caller.pidfd.is_some());
}

#[test]
fn polkit_subject_is_the_bus_name() {
    let (kind, details) = bus_name_subject(":1.42").unwrap();
    assert_eq!(kind, "system-bus-name");
    let name = details.get("name").unwrap().to_string();
    assert!(name.contains(":1.42"), "{name}");
}
