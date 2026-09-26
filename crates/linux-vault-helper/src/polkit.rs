//! Polkit check for an active local session. No authentication dialog.

use std::collections::HashMap;

use linux_vault_dbus::POLKIT_ACTION;
use zbus::proxy;
use zbus::Connection;
use zvariant::OwnedValue;

use crate::caller::Caller;
use crate::error::HelperError;

/// How a call is authorized.
#[derive(Clone, Copy)]
pub enum Authorizer {
    /// `org.linuxvault.manage` on the system bus.
    Polkit,
    /// Test double that accepts the caller.
    Allow,
    /// Test double that rejects the caller.
    Deny,
}

pub async fn authorize(
    authorizer: Authorizer,
    connection: &Connection,
    caller: &Caller,
) -> Result<(), HelperError> {
    match authorizer {
        Authorizer::Allow => Ok(()),
        Authorizer::Deny => Err(HelperError::NotAuthorized("polkit denied the call".into())),
        Authorizer::Polkit => check_polkit(connection, caller).await,
    }
}

async fn check_polkit(connection: &Connection, caller: &Caller) -> Result<(), HelperError> {
    let name = caller
        .bus_name
        .as_ref()
        .ok_or_else(|| HelperError::NotAuthorized("polkit needs the caller's bus name".into()))?;
    let authority = AuthorityProxy::new(connection)
        .await
        .map_err(|error| HelperError::NotAuthorized(format!("polkit is unavailable: {error}")))?;
    let subject = bus_name_subject(name.as_str())?;
    let (authorized, _challenge, _details) = authority
        .check_authorization(&subject, POLKIT_ACTION, HashMap::new(), 0, "")
        .await
        .map_err(|error| HelperError::NotAuthorized(format!("polkit check failed: {error}")))?;
    if authorized {
        Ok(())
    } else {
        Err(HelperError::NotAuthorized(
            "active local session required".into(),
        ))
    }
}

/// Subject `("system-bus-name", { "name": unique_name })`.
pub fn bus_name_subject(
    unique_name: &str,
) -> Result<(String, HashMap<String, OwnedValue>), HelperError> {
    let name = zvariant::Value::from(unique_name)
        .try_to_owned()
        .map_err(|_| HelperError::NotAuthorized("bus name is not a valid polkit subject".into()))?;
    let mut details = HashMap::new();
    details.insert("name".to_string(), name);
    Ok(("system-bus-name".to_string(), details))
}

#[proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait Authority {
    fn check_authorization(
        &self,
        subject: &(String, HashMap<String, OwnedValue>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}
