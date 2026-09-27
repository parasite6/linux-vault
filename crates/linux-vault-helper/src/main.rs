//! System service. Listens on the system bus.
//!
//! Create, Unlock, Lock, List, Remove, and Terminate call the vault core.
//! Startup warns when `CAP_SYS_PTRACE` is not effective.
//! `PrepareForShutdown` and `SIGTERM` lock what is still open. `SIGTERM` is
//! what makes the process exit.

use std::error::Error;

use linux_vault_dbus::{BUS_NAME, OBJECT_PATH};
use linux_vault_helper::{disable_core_dumps, Authorizer, Helper};
use tokio::signal::unix::{signal, SignalKind};
use zbus::connection;

fn main() -> Result<(), Box<dyn Error>> {
    disable_core_dumps()?;
    if std::env::args().nth(1).as_deref() == Some("--worker") {
        std::process::exit(linux_vault_helper::worker_main());
    }
    if std::env::var_os("LVE_UPGRADE_PROBE").is_some() {
        return upgrade_probe();
    }
    // Before any runtime thread exists. Later threads inherit this ring.
    // Creating it afterwards gives each of those threads an empty ring.
    linux_vault_helper::create_process_keyring()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

async fn serve() -> Result<(), Box<dyn Error>> {
    let helper = Helper::system(Authorizer::Polkit)?;
    let shutdown = helper.shutdown_handle();
    let connection = connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, helper)?
        .build()
        .await?;
    shutdown.bind_bus(connection).await;
    let watch = shutdown.clone();
    tokio::spawn(async move {
        if let Err(error) = watch.watch_prepare_for_shutdown().await {
            eprintln!("linux-vault-helper: prepare for shutdown: {error}");
        }
    });
    let mut terminate = signal(SignalKind::terminate())?;
    terminate.recv().await;
    // Info priority, flushed before the lock work. A stop that dies in the
    // handler never reaches this line.
    linux_vault_helper::stop_log("received SIGTERM");
    shutdown.shut_down().await;
    Ok(())
}

/// The helper binary, executed from a copy that the test replaces on disk.
fn upgrade_probe() -> Result<(), Box<dyn Error>> {
    if std::env::var_os("LVE_UNIT_CAPS").is_some() {
        linux_vault_helper::limit_to_unit_capabilities();
    }
    linux_vault_helper::create_process_keyring()?;
    let dir = std::path::PathBuf::from(std::env::var("LVE_PROBE_DIR")?);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(linux_vault_helper::replaced_binary_probe(&dir))
        .map_err(std::io::Error::other)?;
    Ok(())
}
