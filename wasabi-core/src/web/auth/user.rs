//! Authenticated user representation with claim accessors.
//!
//! The [`User`] struct wraps validated JWT claims and provides typed access
//! to standard fields like tenant, user ID, name, email, and permissions.

use crate::status_bail;
use crate::web::auth::{
    CLAIM_ACT, CLAIM_EMAIL, CLAIM_LOCALE, CLAIM_NAME, CLAIM_PERMISSIONS, CLAIM_SUB, CLAIM_TENANT,
    DEFAULT_LOCALE,
};
use crate::web::error::ResultExt;
use crate::web::validation::{is_valid_id, is_valid_str};
use anyhow::Context;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use warp::http::StatusCode;

pub(crate) type ClaimsSet = BTreeMap<String, Value>;

/// An authenticated user extracted from a validated JWT.
#[derive(Clone)]
pub struct User {
    /// The original JWT token string.
    pub jwt_token: String,
    pub(crate) claims: ClaimsSet,
}

impl User {
    /// Returns the tenant ID from the `tenant` claim.
    pub fn tenant_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_TENANT)
            .and_then(Value::as_str)
            .filter(|id| is_valid_id(id))
            .context("No or invalid  tenant id ('tenant') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the user ID from the `sub` claim.
    pub fn user_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_SUB)
            .and_then(Value::as_str)
            .filter(|id| is_valid_id(id))
            .context("No or invalid auth id ('sub') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the user's full name from the `name` claim.
    pub fn full_name(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_NAME)
            .and_then(Value::as_str)
            .filter(|name| is_valid_str(name, 1, 512))
            .context("No or invalid auth name ('name') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the user's email from the `email` claim.
    pub fn email(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_EMAIL)
            .and_then(Value::as_str)
            .filter(|email| is_valid_str(email, 1, 512))
            .context("No or invalid email ('email') in JWT token present!")
            .mark_client_error()
    }

    /// Returns `true` if the user has at least one of the given permissions.
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

    /// Returns the user if they have at least one of the given permissions, otherwise 401.
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
            .unwrap_or(DEFAULT_LOCALE)
    }
}

impl Debug for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn fmt_act(act: &Value, mut buffer: String) -> String {
            if act.is_object() {
                if let Some(sub) = act.get(CLAIM_SUB).and_then(Value::as_str) {
                    if !buffer.is_empty() {
                        buffer.push_str(", ")
                    }
                    buffer.push_str(sub);

                    if let Some(tenant) = act.get(CLAIM_TENANT).and_then(Value::as_str) {
                        buffer.push_str(" (tenant: ");
                        buffer.push_str(tenant);
                        buffer.push(')');
                    }
                }

                if let Some(act) = act.get(CLAIM_ACT) {
                    buffer = fmt_act(act, buffer);
                }
            } else if act.is_string() {
                buffer.push_str(act.as_str().unwrap_or_default());
            } else {
                buffer.push_str(&act.to_string());
            }

            buffer
        }

        if let Some(act) = self.claims.get(CLAIM_ACT) {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"sub\": \"{}\", \"act\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
                fmt_act(act, String::new())
            )
        } else {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"sub\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
            )
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::web::auth::user::ClaimsSet;
    use crate::web::auth::*;
    use anyhow::Context;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    pub struct Builder {
        jwt_token: String,
        claims: ClaimsSet,
    }

    impl Builder {
        pub fn new() -> Self {
            Builder {
                jwt_token: String::new(),
                claims: ClaimsSet::new(),
            }
        }

        pub fn with_string(mut self, key: &str, value: &str) -> Self {
            self.claims.insert(key.to_owned(), Value::from(value));
            self
        }

        pub fn with_value(mut self, key: &str, value: Value) -> Self {
            self.claims.insert(key.to_owned(), value);
            self
        }

        pub fn with_jwt_token(mut self, token: impl ToString) -> Self {
            self.jwt_token = token.to_string();
            self
        }

        pub fn build_user(self) -> User {
            User {
                jwt_token: self.jwt_token,
                claims: self.claims,
            }
        }

        pub fn into_token(self, secret: &str) -> Result<String, anyhow::Error> {
            encode(
                &Header::new(Algorithm::HS256),
                &self.claims,
                &EncodingKey::from_secret(secret.as_bytes()),
            )
            .context("Signing failed")
        }
    }
    #[test]
    fn simple_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .build_user();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\" }"
        );
    }

    #[test]
    fn simple_delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_ACT, "sub1")
            .build_user();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"sub1\" }"
        );

        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!(42))
            .build_user();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"42\" }"
        );
    }

    #[test]
    fn complex_delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!({"sub": "sub1", "tenant": "tenant2"}))
            .build_user();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"sub1 (tenant: tenant2)\" }"
        );
    }

    #[test]
    fn chained_delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!({"sub": "sub1", "act": {"sub": "sub2"}}))
            .build_user();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"sub1, sub2\" }"
        );
    }

    #[test]
    fn user_tenant_id_returns_valid_tenant_id() {
        let user = Builder::new()
            .with_string(CLAIM_TENANT, "0815")
            .build_user();

        assert_eq!(user.tenant_id().unwrap(), "0815");
    }

    #[test]
    fn user_tenant_id_fails_for_missing_tenant_id() {
        let user = Builder::new().build_user();
        assert!(user.tenant_id().is_err());
    }

    #[test]
    fn user_tenant_id_fails_for_empty_tenant_id() {
        let user = Builder::new().with_string(CLAIM_TENANT, "").build_user();
        assert!(user.tenant_id().is_err());
    }

    #[test]
    fn user_tenant_id_fails_for_tenant_id_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_TENANT, "a".repeat(65).as_str())
            .build_user();
        assert!(user.tenant_id().is_err());
    }

    #[test]
    fn user_user_id_returns_valid_user_id() {
        let user = Builder::new().with_string(CLAIM_SUB, "1234").build_user();

        assert_eq!(user.user_id().unwrap(), "1234");
    }

    #[test]
    fn user_user_id_fails_for_missing_user_id() {
        let user = Builder::new().build_user();
        assert!(user.user_id().is_err());
    }

    #[test]
    fn user_user_id_fails_for_empty_user_id() {
        let user = Builder::new().with_string(CLAIM_SUB, "").build_user();
        assert!(user.user_id().is_err());
    }

    #[test]
    fn user_user_id_fails_for_user_id_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "a".repeat(65).as_str())
            .build_user();
        assert!(user.user_id().is_err());
    }

    #[test]
    fn user_full_name_returns_valid_name() {
        let user = Builder::new()
            .with_string(CLAIM_NAME, "John Doe")
            .build_user();

        assert_eq!(user.full_name().unwrap(), "John Doe");
    }

    #[test]
    fn user_full_name_fails_for_missing_name() {
        let user = Builder::new().build_user();
        assert!(user.full_name().is_err());
    }

    #[test]
    fn user_full_name_fails_for_empty_name() {
        let user = Builder::new().with_string(CLAIM_NAME, "").build_user();
        assert!(user.full_name().is_err());
    }

    #[test]
    fn user_full_name_fails_for_name_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_NAME, "a".repeat(513).as_str())
            .build_user();
        assert!(user.full_name().is_err());
    }

    #[test]
    fn user_email_returns_valid_email() {
        let user = Builder::new()
            .with_string(CLAIM_EMAIL, "auth@example.com")
            .build_user();

        assert_eq!(user.email().unwrap(), "auth@example.com");
    }

    #[test]
    fn user_email_fails_for_missing_email() {
        let user = Builder::new().build_user();
        assert!(user.email().is_err());
    }

    #[test]
    fn user_email_fails_for_empty_email() {
        let user = Builder::new().with_string(CLAIM_EMAIL, "").build_user();
        assert!(user.email().is_err());
    }

    #[test]
    fn user_email_fails_for_email_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_EMAIL, "a".repeat(513).as_str())
            .build_user();
        assert!(user.email().is_err());
    }

    #[test]
    fn user_has_permission_returns_true_if_user_has_permission() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build_user();

        assert!(user.has_any_permission(&[&"permission1"]));
        assert!(user.has_any_permission(&[&"permission2"]));
        assert!(user.has_any_permission(&[&"permission1", &"permission2"]));
    }

    #[test]
    fn user_has_permission_returns_false_if_user_does_not_have_permission() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build_user();

        assert!(!user.has_any_permission(&[&"permission3"]));
        assert!(!user.has_any_permission(&[&"permission4"]));
        assert!(!user.has_any_permission(&[&"permission3", &"permission4"]));
    }

    #[test]
    fn user_has_permission_returns_false_if_no_permissions_claim_present() {
        let user = Builder::new().build_user();

        assert!(!user.has_any_permission(&[&"permission1"]));
    }

    #[test]
    fn user_has_permission_returns_false_if_permissions_claim_is_not_an_array() {
        let user = Builder::new()
            .with_string(CLAIM_PERMISSIONS, "permission1")
            .build_user();

        assert!(!user.has_any_permission(&[&"permission1"]));
    }

    #[test]
    fn user_enforce_permission_with_permission_succeeds() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build_user();

        assert!(
            user.clone()
                .enforce_any_permission(&[&"permission1"])
                .is_ok()
        );
        assert!(
            user.clone()
                .enforce_any_permission(&[&"permission2"])
                .is_ok()
        );
        assert!(
            user.enforce_any_permission(&[&"permissionX", &"permission1"])
                .is_ok()
        );
    }

    #[test]
    fn user_enforce_permission_fails_if_permission_is_missing() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build_user();

        assert_eq!(
            user.clone()
                .enforce_any_permission(&[&"permissionA"])
                .unwrap_err()
                .to_string(),
            "The permission 'permissionA' is required for this action"
        );

        assert_eq!(
            user.enforce_any_permission(&[&"permissionA", &"permissionB"])
                .unwrap_err()
                .to_string(),
            "One of the permissions 'permissionA, permissionB' is required for this action"
        );
    }
}
