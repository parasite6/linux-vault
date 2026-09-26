use zbus::DBusError;

/// Errors a caller can receive. None of them include a passphrase.
#[derive(Debug, DBusError)]
#[zbus(prefix = "org.linuxvault.Error", impl_display = true)]
pub enum HelperError {
    #[zbus(error)]
    Zbus(zbus::Error),
    /// Polkit denied the call, or the caller's credentials could not be read.
    NotAuthorized(String),
    /// The checks passed. This method is not connected yet.
    NotImplemented(String),
    /// The user dismissed the prompt.
    Cancelled(String),
    /// The caller's user manager is not running.
    NotLoggedIn(String),
    /// Pinentry or the vault operation failed. The message has no passphrase.
    Failed(String),
}
