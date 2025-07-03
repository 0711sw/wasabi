use crate::status_bail;
use crate::web::auth::{
    CLAIM_ACT, CLAIM_EMAIL, CLAIM_LOCALE, CLAIM_NAME, CLAIM_PERMISSIONS, CLAIM_SUB, CLAIM_TENANT,
};
use crate::web::error::ResultExt;
use crate::web::validation::{is_valid_id, is_valid_str};
use anyhow::Context;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use warp::http::StatusCode;

#[derive(Clone)]
pub struct User {
    pub(crate) claims: BTreeMap<String, Value>,
}

impl User {
    pub fn tenant_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_TENANT)
            .and_then(Value::as_str)
            .filter(|id| is_valid_id(id))
            .context("No or invalid  tenant id ('tenant') in JWT token present!")
            .mark_client_error()
    }

    pub fn user_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_SUB)
            .and_then(Value::as_str)
            .filter(|id| is_valid_id(id))
            .context("No or invalid auth id ('sub') in JWT token present!")
            .mark_client_error()
    }

    pub fn full_name(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_NAME)
            .and_then(Value::as_str)
            .filter(|name| is_valid_str(name, 1, 512))
            .context("No or invalid auth name ('name') in JWT token present!")
            .mark_client_error()
    }

    pub fn email(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_EMAIL)
            .and_then(Value::as_str)
            .filter(|email| is_valid_str(email, 1, 512))
            .context("No or invalid email ('email') in JWT token present!")
            .mark_client_error()
    }

    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        if let Some(granted_permission) = self
            .claims
            .get(CLAIM_PERMISSIONS)
            .and_then(|permissions| permissions.as_array())
        {
            let granted_permissions = granted_permission
                .iter()
                .filter_map(|permission| permission.as_str().map(str::to_owned))
                .collect::<HashSet<String>>();
            permissions
                .iter()
                .any(|expected_permission| granted_permissions.contains(*expected_permission))
        } else {
            false
        }
    }

    pub fn enforce_any_permission(self, permissions: &[&str]) -> anyhow::Result<Self> {
        if self.has_any_permission(permissions) {
            Ok(self)
        } else if permissions.len() == 1 {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "The permission '{}' is required for this action",
                permissions[0]
            );
        } else {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "One of the permissions '{}' is required for this action",
                permissions.join(", ")
            );
        }
    }

    /// Returns the end-auth's locale, represented as a BCP47 (RFC5646) language tag.
    ///
    /// This is typically an ISO 639 Alpha-2 (ISO639) language code in lowercase and an ISO 3166-1
    /// Alpha-2 (ISO3166‑1) country code in uppercase, separated by a dash. For example, en-US or
    /// fr-CA.
    ///
    /// This uses the claim [CLAIM_LOCALE] ("locale") as defined by OpenID Connect Core 1.0,
    /// Section 5.1.
    pub fn locale(&self) -> &str {
        self.claims
            .get(CLAIM_LOCALE)
            .and_then(Value::as_str)
            .unwrap_or("en-US")
    }
}

impl Debug for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn fmt_act(act: &Value, mut buffer: String) -> String {
            if let Some(sub) = act.get(CLAIM_SUB).and_then(Value::as_str) {
                if !buffer.is_empty() {
                    buffer.push_str(", ")
                }
                buffer.push_str(sub);
            }

            if let Some(act) = act.get(CLAIM_ACT) {
                fmt_act(act, buffer)
            } else {
                buffer
            }
        }

        if let Some(act) = self.claims.get(CLAIM_ACT) {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"auth\": \"{}\", \"act\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
                fmt_act(act, String::new())
            )
        } else {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"auth\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
            )
        }
    }
}
