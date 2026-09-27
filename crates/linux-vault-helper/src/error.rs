use zbus::DBusError;

/// Errors a caller can receive. None of them include a passphrase.
#[derive(Debug, DBusError)]
#[zbus(prefix = "org.linuxvault.Error", impl_display = true)]
pub enum HelperError {
    #[zbus(error)]
    Zbus(zbus::Error),
    /// Polkit denied the call, or the caller's credentials could not be read.
    NotAuthorized(String),
    /// No vault of this name is registered for the caller. A name that belongs
    /// to someone else is this same error.
    NotFound(String),
    /// The checks passed. This method is not connected yet.
    NotImplemented(String),
    /// The user dismissed the prompt.
    Cancelled(String),
    /// The caller's user manager is not running.
    NotLoggedIn(String),
    /// The passphrase did not match. The message is only `wrong passphrase`.
    WrongPassphrase(String),
    /// The disk filled up. The message is only `not enough disk space`.
    NoSpace(String),
    /// The folder has no regular files. The message names the vault.
    Empty(String),
    /// The folder is inside another vault, or contains one.
    Nested(String),
    /// `registry.json` was moved aside. No method runs until the helper is restarted.
    RegistryBroken(String),
    /// Pinentry or the vault operation failed. The message has no passphrase.
    Failed(String),
}
