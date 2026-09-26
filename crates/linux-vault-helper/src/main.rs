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
    shutdown.shut_down().await;
    Ok(())
}
