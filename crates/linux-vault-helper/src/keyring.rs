//! The helper's process keyring.
//!
//! One ring for the whole process. [`create_process_keyring`] runs on the main
//! thread before the async runtime starts any worker. A later
//! `KEYCTL_GET_KEYRING_ID(KEY_SPEC_PROCESS_KEYRING)` on a thread whose
//! credentials were copied before that call creates a second ring, and a
//! passphrase stored there is invisible to the thread that handles `SIGTERM`.
//!
//! The thread keyring is not used. Each key is possessor-only and is not
//! linked into the user keyring or the login session keyring.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use linux_keyutils::{KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use zeroize::Zeroize;

use crate::error::HelperError;
use crate::pinentry::Passphrase;

const PAYLOAD_CAP: usize = 4096;

static INSERT_THREAD: AtomicU64 = AtomicU64::new(0);
static READ_THREAD: AtomicU64 = AtomicU64::new(0);

/// Create the process keyring on this thread.
///
/// Call it from `main` before the runtime is built. Threads started afterwards
/// inherit the ring. Calling it again on a thread that already has the ring
/// returns that same ring.
pub fn create_process_keyring() -> Result<(), HelperError> {
    process_ring().map(|_| ())
}

/// Thread ids of the last passphrase store and the last passphrase read.
///
/// `0` means that operation has not run in this process. Tests use this to
/// show the store and the `SIGTERM` read were different threads.
pub fn passphrase_threads() -> (u64, u64) {
    (
        INSERT_THREAD.load(Ordering::SeqCst),
        READ_THREAD.load(Ordering::SeqCst),
    )
}

fn this_thread() -> u64 {
    unsafe { nix::libc::pthread_self() as u64 }
}

/// Passphrases for unlocked vaults, stored in the process keyring.
///
/// Cloning shares the same keys. This type cannot hand the bytes to a caller
/// except [`Self::read`], which Lock uses and then [`Self::forget`] wipes.
#[derive(Clone)]
pub struct ProcessKeys {
    prefix: Arc<str>,
}

impl ProcessKeys {
    pub fn new() -> Result<Self, HelperError> {
        // The service already created the ring on the main thread. Tests that
        // have not started other threads yet create it here, on their own
        // main thread. This does not paper over a ring created too late: a
        // thread that missed the first create still gets an empty ring of its
        // own, and a later read fails.
        process_ring()?;
        static IDS: AtomicU64 = AtomicU64::new(0);
        let prefix = format!(
            "lve-{}-{}-",
            std::process::id(),
            IDS.fetch_add(1, Ordering::Relaxed)
        );
        Ok(Self {
            prefix: Arc::from(prefix),
        })
    }

    pub fn contains(&self, uid: u32, name: &str) -> bool {
        self.lookup(uid, name).is_ok()
    }

    /// Copy the passphrase into the process keyring, then drop the userspace bytes.
    pub fn insert(&self, uid: u32, name: &str, passphrase: Passphrase) -> Result<(), HelperError> {
        let ring = process_ring()?;
        let key = ring
            .add_key(&self.description(uid, name), passphrase.as_bytes())
            .map_err(|error| named("storing passphrase", name, &error))?;
        let perms = KeyPermissionsBuilder::builder()
            .posessor(Permission::ALL)
            .build();
        if let Err(error) = key.set_perms(perms) {
            let _ = key.invalidate();
            return Err(named("storing passphrase", name, &error));
        }
        INSERT_THREAD.store(this_thread(), Ordering::SeqCst);
        Ok(())
    }

    /// Read the passphrase back. The kernel copy stays until [`Self::forget`].
    ///
    /// Lock is the caller. Nothing on the bus reads this.
    pub fn read(&self, uid: u32, name: &str) -> Result<Passphrase, HelperError> {
        let key = self.lookup(uid, name)?;
        let mut buffer = [0u8; PAYLOAD_CAP];
        let len = key
            .read(&mut buffer)
            .map_err(|error| named("reading passphrase", name, &error))?;
        if len > buffer.len() {
            buffer.zeroize();
            return Err(HelperError::Failed(format!(
                "reading passphrase for {name}: passphrase key is too long"
            )));
        }
        let passphrase = Passphrase::from_bytes(&buffer[..len]);
        buffer.zeroize();
        READ_THREAD.store(this_thread(), Ordering::SeqCst);
        Ok(passphrase)
    }

    /// Remove the key and let the kernel discard its payload.
    ///
    /// A key that is already gone or revoked is a success: its payload is wiped.
    pub fn forget(&self, uid: u32, name: &str) -> Result<(), HelperError> {
        let key = match self.lookup(uid, name) {
            Ok(key) => key,
            Err(HelperError::Failed(message)) if already_gone(&message) => return Ok(()),
            Err(error) => return Err(error),
        };
        match key.invalidate() {
            Ok(()) => Ok(()),
            Err(error) if already_gone(&error.to_string()) => Ok(()),
            Err(error) => Err(named("forgetting passphrase", name, &error)),
        }
    }

    fn lookup(&self, uid: u32, name: &str) -> Result<linux_keyutils::Key, HelperError> {
        process_ring()?
            .search(&self.description(uid, name))
            .map_err(|error| named("finding passphrase", name, &error))
    }

    fn description(&self, uid: u32, name: &str) -> String {
        format!("{}{uid}-{name}", self.prefix)
    }

    #[cfg(test)]
    fn absent_from_other_keyrings(&self, uid: u32, name: &str) -> bool {
        let description = self.description(uid, name);
        [
            KeyRingIdentifier::Thread,
            KeyRingIdentifier::Session,
            KeyRingIdentifier::User,
            KeyRingIdentifier::UserSession,
        ]
        .into_iter()
        .all(|id| match KeyRing::from_special_id(id, false) {
            Ok(ring) => ring.search(&description).is_err(),
            Err(_) => true,
        })
    }
}

fn process_ring() -> Result<KeyRing, HelperError> {
    KeyRing::from_special_id(KeyRingIdentifier::Process, true)
        .map_err(|error| named("creating the process keyring", "helper", &error))
}

fn named(step: &str, target: &str, error: &dyn std::fmt::Display) -> HelperError {
    HelperError::Failed(format!("{step} for {target}: {error}"))
}

fn already_gone(message: &str) -> bool {
    message.contains("KeyDoesNotExist") || message.contains("KeyRevoked")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_passphrase_stays_on_the_process_keyring_and_is_wiped_at_lock() {
        create_process_keyring().unwrap();
        let keys = ProcessKeys::new().unwrap();
        keys.insert(0, "Forge", Passphrase::from_bytes(b"secret"))
            .unwrap();
        assert!(keys.contains(0, "Forge"));
        assert!(keys.absent_from_other_keyrings(0, "Forge"));

        let key = keys.lookup(0, "Forge").unwrap();
        let bits = key.metadata().unwrap().get_perms().bits();
        assert_eq!(bits >> 24, u32::from(Permission::ALL.bits()));
        assert_eq!(bits & 0x00ff_ffff, 0);

        let keys_for_thread = keys.clone();
        std::thread::spawn(move || {
            let read = keys_for_thread.read(0, "Forge").unwrap();
            assert_eq!(read.as_bytes(), b"secret");
        })
        .join()
        .unwrap();

        assert_eq!(keys.read(0, "Forge").unwrap().as_bytes(), b"secret");
        keys.forget(0, "Forge").unwrap();
        assert!(!keys.contains(0, "Forge"));
        assert!(keys.read(0, "Forge").is_err());
        keys.forget(0, "Forge").unwrap();
    }

    #[test]
    fn a_fresh_process_creates_the_process_keyring() {
        if std::env::var_os("LVE_FRESH_KEYRING").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "keyring::tests::a_fresh_process_creates_the_process_keyring",
                    "--test-threads=1",
                ])
                .env("LVE_FRESH_KEYRING", "1")
                .env("LVE_LIMITED_CAPS", "1")
                .status()
                .unwrap();
            assert!(status.success(), "fresh keyring process failed: {status}");
            return;
        }
        crate::limit_to_unit_capabilities();
        create_process_keyring().unwrap();
        let keys = ProcessKeys::new().unwrap();
        keys.insert(0, "lve-trial", Passphrase::from_bytes(b"secret"))
            .unwrap();
        assert_eq!(keys.read(0, "lve-trial").unwrap().as_bytes(), b"secret");
        keys.forget(0, "lve-trial").unwrap();
        let missing = keys.read(0, "lve-trial").unwrap_err().to_string();
        assert!(missing.contains("passphrase for lve-trial"), "{missing}");
    }
}
