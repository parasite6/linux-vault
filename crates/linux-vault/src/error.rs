use std::fmt;
use std::io;

use crate::State;

/// Failure from a vault operation.
///
/// The passphrase is never included in an error.
#[derive(Debug)]
pub enum Error {
    /// Empty, or contains a NUL, CR, or LF byte.
    InvalidPassphrase(&'static str),
    /// 7z rejected the passphrase. The vault was not changed.
    WrongPassphrase {
        message: String,
    },
    /// No vault is registered under this name.
    NotFound,
    /// A vault with this name or path is already registered, or the archive already exists.
    AlreadyExists,
    /// The folder is inside another vault, or contains one.
    Nested {
        name: String,
        other: String,
        nesting: crate::Nesting,
    },
    /// The folder is not inside the allowed root.
    OutsideRoot,
    /// A symlink inside the vault points outside the vault.
    EscapingSymlink,
    /// The archive is not a regular file owned by the caller, so its immutable
    /// flag was left alone.
    UnexpectedFile,
    /// `7z l` with no password succeeded, so the archive is not encrypted.
    /// Lock keeps the plaintext. Terminate deletes nothing.
    NotEncrypted,
    /// The vault is not in a state this operation allows.
    InvalidState {
        state: State,
        operation: &'static str,
    },
    /// Another operation holds the registry lock.
    Busy,
    /// `7z` was not found on `PATH`.
    SevenZipMissing,
    /// `7z` exited with a failure other than a wrong passphrase.
    SevenZip {
        status: Option<i32>,
        message: String,
    },
    /// The registry file could not be parsed.
    Registry(String),
    /// `registry.json` was moved aside. Nothing may be written until it is resolved.
    RegistryDamaged(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPassphrase(reason) => write!(f, "invalid passphrase: {reason}"),
            Error::WrongPassphrase { message } => write!(f, "wrong passphrase: {message}"),
            Error::NotFound => write!(f, "vault not found"),
            Error::AlreadyExists => write!(f, "vault already exists"),
            Error::Nested {
                name,
                other,
                nesting,
            } => match nesting {
                crate::Nesting::Inside => {
                    write!(f, "Cannot create {name}: it is inside vault {other}.")
                }
                crate::Nesting::Contains => {
                    write!(f, "Cannot create {name}: it contains vault {other}.")
                }
            },
            Error::OutsideRoot => write!(f, "vault path is outside the allowed root"),
            Error::EscapingSymlink => {
                write!(f, "symlink inside the vault points outside it")
            }
            Error::UnexpectedFile => {
                write!(f, "archive is not a regular file owned by the caller")
            }
            Error::NotEncrypted => write!(f, "archive is not encrypted"),
            Error::InvalidState { state, operation } => {
                write!(f, "cannot {operation} a vault that is {state}")
            }
            Error::Busy => write!(f, "vault registry is busy"),
            Error::SevenZipMissing => write!(f, "7z was not found"),
            Error::SevenZip { status, message } => {
                write!(f, "7z failed (status {status:?}): {message}")
            }
            Error::Registry(message) => write!(f, "registry: {message}"),
            Error::RegistryDamaged(message) => write!(f, "{message}"),
            Error::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
