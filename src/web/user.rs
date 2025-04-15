use crate::status_bail;
use crate::web::error::ResultExt;
use crate::web::warp::{into_rejection, with_cloneable};
use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;
use warp::http::StatusCode;
use warp::{Filter, Rejection, http};

const CLAIM_AUD: &str = "aud";
const CLAIM_ISS: &str = "iss";
const CLAIM_SUB: &str = "sub";
const CLAIM_ACT: &str = "act";
const CLAIM_EXP: &str = "exp";
const CLAIM_NBF: &str = "nbf";
const CLAIM_TENANT: &str = "tenant";
const CLAIM_NAME: &str = "name";
const CLAIM_EMAIL: &str = "email";
const CLAIM_ROLES: &str = "roles";

const PREFIX_BEARER_TOKEN: &str = "Bearer ";

#[derive(Clone)]
pub struct Authenticator {
    expected_audience: Option<String>,
    expected_issuer: Option<String>,
    key: Arc<Hmac<Sha256>>,
}

#[derive(Clone)]
pub struct User {
    claims: BTreeMap<String, Value>,
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
                "{{\"tenant\": \"{}\", \"user\": \"{}\", \"act\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
                fmt_act(act, String::new())
            )
        } else {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"user\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
            )
        }
    }
}

pub trait Role: Display + Send + Sync {
    fn name(&self) -> &'static str;
}

impl User {
    pub fn tenant_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_TENANT)
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 32)
            .context("No or invalid  tenant id ('tenant') in JWT token present!")
            .with_status(StatusCode::BAD_REQUEST)
    }

    pub fn user_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_SUB)
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 32)
            .context("No or invalid user id ('sub') in JWT token present!")
            .with_status(StatusCode::BAD_REQUEST)
    }

    pub fn full_name(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_NAME)
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 512)
            .context("No or invalid user name ('name') in JWT token present!")
            .with_status(StatusCode::BAD_REQUEST)
    }

    pub fn email(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_EMAIL)
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty() && email.len() <= 512)
            .context("No or invalid email ('email') in JWT token present!")
            .with_status(StatusCode::BAD_REQUEST)
    }

    pub fn has_role(&self, roles: &[&'static dyn Role]) -> bool {
        if let Some(granted_roles) = self
            .claims
            .get(CLAIM_ROLES)
            .and_then(|roles| roles.as_array())
        {
            let granted_roles = granted_roles
                .iter()
                .filter_map(|role| role.as_str().map(str::to_owned))
                .collect::<HashSet<String>>();
            roles
                .iter()
                .any(|expected_role| granted_roles.contains(expected_role.name()))
        } else {
            false
        }
    }

    pub fn enforce_role(self, roles: &[&'static dyn Role]) -> anyhow::Result<Self> {
        if self.has_role(roles) {
            Ok(self)
        } else if roles.len() == 1 {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "The role '{}' is required for this action",
                roles[0]
            );
        } else {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "One of the roles '{}' is required for this action",
                roles
                    .iter()
                    .map(|role| role.name())
                    .collect::<Vec<&str>>()
                    .join(", ")
            );
        }
    }
}

impl Authenticator {
    pub fn new(
        secret: &str,
        expected_audience: Option<String>,
        expected_issuer: Option<String>,
    ) -> Self {
        Authenticator {
            key: Arc::new(Hmac::new_from_slice(secret.as_bytes()).unwrap()),
            expected_issuer,
            expected_audience,
        }
    }
}

pub fn with_user(
    authenticator: Authenticator,
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>(
            http::header::AUTHORIZATION.as_str(),
        ))
        .and(with_cloneable(authenticator))
        .and_then(|authorization, authenticator| async {
            parse_headers(authorization, authenticator).map_err(into_rejection)
        })
}

pub fn with_user_with_role(
    authenticator: Authenticator,
    roles: &'static [&'static dyn Role],
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    with_user(authenticator)
        .and_then(move |user: User| async move { user.enforce_role(roles).map_err(into_rejection) })
}

#[tracing::instrument(level = "trace", skip(auth), ret(Debug), err(Display))]
fn parse_headers(authentication: Option<String>, auth: Authenticator) -> anyhow::Result<User> {
    let jwt_token = if let Some(jwt_token) = authentication {
        jwt_token
            .strip_prefix(PREFIX_BEARER_TOKEN)
            .map(str::to_string)
            .unwrap_or(jwt_token)
    } else {
        status_bail!(StatusCode::UNAUTHORIZED, "No JWT present.");
    };

    let claims: BTreeMap<String, Value> = match jwt_token.verify_with_key(auth.key.as_ref()) {
        Ok(claims) => claims,
        Err(err) => {
            status_bail!(StatusCode::UNAUTHORIZED, "Invalid JWT present: {}", err);
        }
    };

    check_validity(&claims, &auth.expected_audience, &auth.expected_issuer)?;
    Ok(User { claims })
}

fn check_validity(
    claims: &BTreeMap<String, Value>,
    expected_audience: &Option<String>,
    expected_issuer: &Option<String>,
) -> anyhow::Result<()> {
    if let Some(expected_audience) = expected_audience {
        if expected_audience != claims.get(CLAIM_AUD).and_then(Value::as_str).unwrap_or("") {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "The given JWT token has an invalid audience"
            );
        }
    }
    if let Some(expected_issuer) = expected_issuer {
        if expected_issuer != claims.get(CLAIM_ISS).and_then(Value::as_str).unwrap_or("") {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "The given JWT token has an invalid issuer"
            );
        }
    }
    if let Some(expires) = parse_timestamp(CLAIM_EXP, claims)? {
        if expires <= Utc::now() {
            status_bail!(StatusCode::UNAUTHORIZED, "The given JWT token is expired");
        }
    }

    if let Some(nbf) = parse_timestamp(CLAIM_NBF, claims)? {
        if nbf >= Utc::now() {
            status_bail!(StatusCode::UNAUTHORIZED, "The given JWT is not yet valid.");
        }
    }

    Ok(())
}

fn parse_timestamp(
    claim: &str,
    claims: &BTreeMap<String, Value>,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    if let Some(value) = claims.get(claim) {
        match value
            .as_i64()
            .and_then(|value| DateTime::from_timestamp(value, 0))
        {
            Some(timestamp) => Ok(Some(timestamp)),
            None => Err(anyhow!(
                "The value '{}' in '{}' cannot be parsed as UNIX timestamp",
                value,
                claim
            )),
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::web::error::ApiError;
    use crate::web::user::*;
    use anyhow::Context;
    use chrono::{DateTime, TimeDelta, Utc};
    use hmac::digest::core_api::CoreWrapper;
    use hmac::{Hmac, HmacCore};
    use jwt::SignWithKey;
    use serde_json::{Value, json};
    use sha2::Sha256;
    use sha2::digest::KeyInit;
    use std::collections::BTreeMap;
    use std::ops::{Add, Sub};
    use warp::http::StatusCode;

    impl Role for &'static str {
        fn name(&self) -> &'static str {
            self
        }
    }

    struct Builder {
        claims: BTreeMap<String, Value>,
    }

    impl Builder {
        fn new() -> Self {
            Builder {
                claims: BTreeMap::new(),
            }
        }

        fn with_string(mut self, key: &str, value: &str) -> Self {
            self.claims.insert(key.to_owned(), Value::from(value));
            self
        }

        fn with_date(mut self, key: &str, date_time: DateTime<Utc>) -> Self {
            self.claims
                .insert(key.to_owned(), Value::from(date_time.timestamp()));
            self
        }

        fn with_value(mut self, key: &str, value: Value) -> Self {
            self.claims.insert(key.to_owned(), value);
            self
        }

        fn build(self) -> BTreeMap<String, Value> {
            self.claims
        }

        fn build_user(self) -> User {
            User {
                claims: self.claims,
            }
        }

        fn into_token(self, secret: &str) -> Result<String, anyhow::Error> {
            let key: Hmac<Sha256> =
                <CoreWrapper<HmacCore<_>> as KeyInit>::new_from_slice(secret.as_bytes())
                    .context("Invalid Secret Key")?;
            self.claims.sign_with_key(&key).context("Signing failed")
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
            "{\"tenant\": \"0815\", \"user\": \"1234\" }"
        );
    }

    #[test]
    fn delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!({"sub": "sub1"}))
            .build_user();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"user\": \"1234\", \"act\": \"sub1\" }"
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
            "{\"tenant\": \"0815\", \"user\": \"1234\", \"act\": \"sub1, sub2\" }"
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
            .with_string(CLAIM_TENANT, "a".repeat(33).as_str())
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
            .with_string(CLAIM_SUB, "a".repeat(33).as_str())
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
            .with_string(CLAIM_EMAIL, "user@example.com")
            .build_user();

        assert_eq!(user.email().unwrap(), "user@example.com");
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
    fn user_has_role_returns_true_if_user_has_role() {
        let user = Builder::new()
            .with_value(CLAIM_ROLES, json!(["role1", "role2"]))
            .build_user();

        assert!(user.has_role(&[&"role1"]));
        assert!(user.has_role(&[&"role2"]));
        assert!(user.has_role(&[&"role1", &"role2"]));
    }

    #[test]
    fn user_has_role_returns_false_if_user_does_not_have_role() {
        let user = Builder::new()
            .with_value(CLAIM_ROLES, json!(["role1", "role2"]))
            .build_user();

        assert!(!user.has_role(&[&"role3"]));
        assert!(!user.has_role(&[&"role4"]));
        assert!(!user.has_role(&[&"role3", &"role4"]));
    }

    #[test]
    fn user_has_role_returns_false_if_no_roles_claim_present() {
        let user = Builder::new().build_user();

        assert!(!user.has_role(&[&"role1"]));
    }

    #[test]
    fn user_has_role_returns_false_if_roles_claim_is_not_an_array() {
        let user = Builder::new()
            .with_string(CLAIM_ROLES, "role1")
            .build_user();

        assert!(!user.has_role(&[&"role1"]));
    }

    #[test]
    fn user_enforce_role_with_role_succeeds() {
        let user = Builder::new()
            .with_value(CLAIM_ROLES, json!(["role1", "role2"]))
            .build_user();

        assert!(user.clone().enforce_role(&[&"role1"]).is_ok());
        assert!(user.clone().enforce_role(&[&"role2"]).is_ok());
        assert!(user.enforce_role(&[&"roleX", &"role1"]).is_ok());
    }

    #[test]
    fn user_enforce_role_fails_if_role_is_missing() {
        let user = Builder::new()
            .with_value(CLAIM_ROLES, json!(["role1", "role2"]))
            .build_user();

        assert_eq!(
            user.clone()
                .enforce_role(&[&"roleA"])
                .unwrap_err()
                .to_string(),
            "The role 'roleA' is required for this action"
        );

        assert_eq!(
            user.enforce_role(&[&"roleA", &"roleB"])
                .unwrap_err()
                .to_string(),
            "One of the roles 'roleA, roleB' is required for this action"
        );
    }

    #[tokio::test]
    async fn with_user_succeeds_with_valid_token() {
        let token = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Authenticator::new("some-secret", None, None);
        let filter = with_user(authenticator);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        let user = res.unwrap();
        assert_eq!(user.tenant_id().unwrap(), "0815");
        assert_eq!(user.user_id().unwrap(), "1234");
        assert_eq!(user.full_name().unwrap(), "test");
    }

    #[tokio::test]
    async fn with_user_with_role_succeeds_with_valid_token() {
        let token = Builder::new()
            .with_value(CLAIM_ROLES, json!(["role1", "role2"]))
            .into_token("some-secret")
            .unwrap();

        let authenticator = Authenticator::new("some-secret", None, None);
        let filter = with_user_with_role(authenticator, &[&"role1"]);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn with_user_with_role_succeeds_fails_for_token_with_missing_role() {
        let token = Builder::new()
            .with_value(CLAIM_ROLES, json!(["role1", "role2"]))
            .into_token("some-secret")
            .unwrap();

        let authenticator = Authenticator::new("some-secret", None, None);
        let filter = with_user_with_role(authenticator, &[&"missing-role"]);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn with_user_fails_without_token() {
        let authenticator = Authenticator::new("some-secret", None, None);
        let filter = with_user(authenticator);

        let res = warp::test::request().filter(&filter).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn with_user_fails_with_invalid_token() {
        let authenticator = Authenticator::new("some-secret", None, None);
        let filter = with_user(authenticator);

        let res = warp::test::request()
            .header("authorization", "Bearer invalid.jwt.token")
            .filter(&filter)
            .await;

        assert!(res.is_err());
    }

    #[test]
    fn parse_headers_without_token_fails() {
        let authenticator = Authenticator::new("some-secret", None, None);
        assert!(parse_headers(None, authenticator).is_err());
    }

    #[test]
    fn parse_headers_with_valid_token_succeeds() {
        let token = Builder::new()
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Authenticator::new("some-secret", None, None);
        let user = parse_headers(Some(token), authenticator).unwrap();
        assert_eq!(user.tenant_id().unwrap(), "0815");
        assert_eq!(user.user_id().unwrap(), "1234");
        assert_eq!(user.full_name().unwrap(), "test");
    }

    #[test]
    fn parse_headers_with_external_jwt_succeeds() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Authenticator::new("external-secret", None, None);
        let user = parse_headers(Some(jwt.to_owned()), authenticator).unwrap();
        assert_eq!(user.tenant_id().unwrap(), "21516239022");
        assert_eq!(user.user_id().unwrap(), "1234567890");
        assert_eq!(user.full_name().unwrap(), "John Doe");
    }

    #[test]
    fn parse_headers_with_bearer_token_succeeds() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Authenticator::new("external-secret", None, None);
        assert!(parse_headers(Some(format!("Bearer {}", jwt)), authenticator).is_ok());
    }

    #[test]
    fn parse_headers_with_invalid_secret_fails() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Authenticator::new("wrong-secret", None, None);
        let err = parse_headers(Some(jwt.to_owned()), authenticator).unwrap_err();
        let api_error = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api_error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn check_validity_succeeds_if_nothing_is_expected() {
        let claims = Builder::new().build();
        assert!(check_validity(&claims, &None, &None).is_ok());
    }

    #[test]
    fn check_validity_properly_enforces_exp() {
        let in_one_hour = Utc::now().add(TimeDelta::hours(1));
        let one_hour_ago = Utc::now().sub(TimeDelta::hours(1));

        assert!(
            check_validity(
                &Builder::new().with_date(CLAIM_EXP, in_one_hour).build(),
                &None,
                &None
            )
            .is_ok()
        );
        assert!(
            check_validity(
                &Builder::new().with_date(CLAIM_EXP, one_hour_ago).build(),
                &None,
                &None
            )
            .is_err()
        );
    }

    #[test]
    fn check_validity_properly_enforces_nbf() {
        let in_one_hour = Utc::now().add(TimeDelta::hours(1));
        let one_hour_ago = Utc::now().sub(TimeDelta::hours(1));

        assert!(
            check_validity(
                &Builder::new().with_date(CLAIM_NBF, one_hour_ago).build(),
                &None,
                &None
            )
            .is_ok()
        );
        assert!(
            check_validity(
                &Builder::new().with_date(CLAIM_NBF, in_one_hour).build(),
                &None,
                &None
            )
            .is_err()
        );
    }

    #[test]
    fn check_validity_properly_enforces_audience() {
        let audience = "an audience".to_owned();
        let other_audience = "other audience".to_owned();
        let claims_with_audience = Builder::new().with_string(CLAIM_AUD, &audience).build();

        assert!(check_validity(&claims_with_audience, &None, &None).is_ok());
        assert!(check_validity(&claims_with_audience, &Some(audience.clone()), &None).is_ok());

        assert!(check_validity(&claims_with_audience, &Some(other_audience), &None).is_err());
    }

    #[test]
    fn check_validity_properly_enforces_issuer() {
        let issuer = "an issuer".to_owned();
        let other_issuer = "other issuer".to_owned();
        let claims_with_issuer = Builder::new().with_string(CLAIM_ISS, &issuer).build();

        assert!(check_validity(&claims_with_issuer, &None, &None).is_ok());
        assert!(check_validity(&claims_with_issuer, &None, &Some(issuer)).is_ok());

        assert!(check_validity(&claims_with_issuer, &None, &Some(other_issuer)).is_err());
    }

    #[test]
    fn parse_timestamp_succeeds_for_valid_unix_timestamp() {
        assert!(
            parse_timestamp(
                "x",
                &BTreeMap::from([("x".to_owned(), json!(Utc::now().timestamp()))])
            )
            .is_ok()
        );
    }

    #[test]
    fn parse_timestamp_succeeds_for_empty_claim() {
        assert!(parse_timestamp("x", &BTreeMap::default()).is_ok());
    }

    #[test]
    fn parse_timestamp_fails_for_iso_date_times() {
        assert!(
            parse_timestamp(
                "x",
                &BTreeMap::from([("x".to_owned(), Value::from("2000-01-01T00:00:00"))])
            )
            .is_err()
        );
    }

    #[test]
    fn parse_timestamp_fails_for_timestamps_given_as_string() {
        assert!(
            parse_timestamp(
                "x",
                &BTreeMap::from([("x".to_owned(), Value::from("4875634234"))])
            )
            .is_err()
        );
    }
}
