//! One in-memory lock per vault name.
//!
//! Held for the whole operation, including pinentry and 7z. A different vault
//! does not wait. The registry file lock is separate and is not held here.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

/// Per-vault exclusion for the helper process.
#[derive(Default)]
pub struct VaultLocks {
    vaults: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

/// Held until the operation on this vault finishes.
pub struct VaultGuard {
    _guard: OwnedMutexGuard<()>,
}

impl VaultLocks {
    pub fn new() -> Self {
        Self {
            vaults: Mutex::new(HashMap::new()),
        }
    }

    /// Wait until no other operation holds `name`, then hold it.
    pub async fn acquire(&self, uid: u32, name: &str) -> VaultGuard {
        let key = format!("{uid}\0{name}");
        let vault = {
            let mut vaults = self.vaults.lock().await;
            vaults
                .entry(key)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        VaultGuard {
            _guard: vault.lock_owned().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::VaultLocks;

    #[tokio::test]
    async fn one_vault_is_exclusive_and_two_vaults_overlap() {
        let locks = Arc::new(VaultLocks::new());
        let first = locks.acquire(1, "Forge").await;
        let other = Arc::clone(&locks);
        let overlapped = tokio::spawn(async move {
            let _guard = other.acquire(1, "Anvil").await;
        });
        tokio::time::timeout(Duration::from_secs(1), overlapped)
            .await
            .expect("a different vault waited")
            .unwrap();

        let waiting = Arc::clone(&locks);
        let blocked = tokio::spawn(async move {
            let _guard = waiting.acquire(1, "Forge").await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!blocked.is_finished());
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("the same vault never ran")
            .unwrap();
    }

    #[tokio::test]
    async fn two_users_hold_the_same_name_at_once() {
        let locks = Arc::new(VaultLocks::new());
        let first = locks.acquire(1, "Forge").await;
        let other = Arc::clone(&locks);
        let overlapped = tokio::spawn(async move {
            let _guard = other.acquire(2, "Forge").await;
        });
        tokio::time::timeout(Duration::from_secs(1), overlapped)
            .await
            .expect("uid 2 waited for uid 1's Forge")
            .unwrap();
        drop(first);
    }
}
