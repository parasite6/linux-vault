//! D-Bus names and client proxy for the helper.
//!
//! The helper process serves this interface. This crate does not open vaults.

use zbus::proxy;

/// Well-known name on the system bus.
pub const BUS_NAME: &str = "org.linuxvault.Helper";

/// Object path of the helper.
pub const OBJECT_PATH: &str = "/org/linuxvault/Helper";

/// Polkit action checked before every method.
pub const POLKIT_ACTION: &str = "org.linuxvault.manage";

/// Connect the way `lve` does.
///
/// The methods stay synchronous. The reply is completion; there is no
/// completion signal. This connection sets no method timeout, so a call waits
/// while a passphrase is typed and while extraction runs. Many other D-Bus
/// clients give up after 25 seconds, which would abandon those calls.
pub async fn connect_client() -> zbus::Result<zbus::Connection> {
    zbus::connection::Builder::system()?.build().await
}

/// One vault, as `List` will return it once the helper is connected to the core.
///
/// `state` is `unlocked`, `locked`, `locked (not immutable)`, `needs_recovery`,
/// `locking`, or `unlocking`. `locked (not immutable)` is a locked archive
/// whose filesystem rejected the immutable flag, so it can still be deleted.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, zbus::zvariant::Type,
)]
pub struct VaultStatus {
    pub name: String,
    pub path: String,
    pub state: String,
}

/// Synchronous helper methods. Call them on a connection from [`connect_client`],
/// which does not impose a method timeout.
#[proxy(
    interface = "org.linuxvault.Helper",
    default_service = "org.linuxvault.Helper",
    default_path = "/org/linuxvault/Helper"
)]
pub trait Helper {
    /// Register a folder. The passphrase is entered in pinentry, not on the bus.
    fn create(&self, path: &str) -> zbus::Result<()>;

    /// Pack the vault. Does not ask for the passphrase.
    fn lock(&self, name: &str) -> zbus::Result<()>;

    /// Extract the vault. The passphrase is entered in pinentry, not on the bus.
    fn unlock(&self, name: &str) -> zbus::Result<()>;

    /// Vaults owned by the calling user.
    fn list(&self) -> zbus::Result<Vec<VaultStatus>>;

    /// Drop the registry entry. The folder stays.
    fn remove(&self, name: &str) -> zbus::Result<()>;

    /// Delete the vault. The passphrase is entered in pinentry, not on the bus.
    fn terminate(&self, name: &str) -> zbus::Result<()>;
}
