use crate::status_bail;
use crate::web::auth::authenticator::Authenticator;
use crate::web::auth::user::User;
use crate::web::warp::{into_rejection, with_cloneable};
use std::sync::Arc;
use warp::http::StatusCode;
use warp::{Filter, Rejection};

pub mod authenticator;
pub mod user;

mod jwks;

const PREFIX_BEARER_TOKEN: &str = "Bearer ";

pub const CLAIM_AUD: &str = "aud";
pub const CLAIM_ISS: &str = "iss";
pub const CLAIM_SUB: &str = "sub";
pub const CLAIM_ACT: &str = "act";
pub const CLAIM_LOCALE: &str = "locale";
pub const CLAIM_TENANT: &str = "tenant";
pub const CLAIM_NAME: &str = "name";
pub const CLAIM_EMAIL: &str = "email";
pub const CLAIM_PERMISSIONS: &str = "permissions";

pub fn with_user(
    authenticator: Arc<dyn Authenticator>,
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>(
            warp::http::header::AUTHORIZATION.as_str(),
        ))
        .and(with_cloneable(authenticator))
        .and_then(|authorization, authenticator| async {
            parse_headers(authorization, authenticator)
                .await
                .map_err(into_rejection)
        })
}

pub fn with_user_with_any_permission(
    authenticator: Arc<dyn Authenticator>,
    permissions: &[&str],
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    with_user(authenticator).and_then(move |user: User| async move {
        user.enforce_any_permission(permissions)
            .map_err(into_rejection)
    })
}

pub fn enforce_user_with_any_permission(
    authenticator: Arc<dyn Authenticator>,
    permissions: &'static [&'static str],
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    with_user(authenticator)
        .and_then(move |user: User| async move {
            user.enforce_any_permission(permissions)
                .map(|_| ())
                .map_err(into_rejection)
        })
        .untuple_one()
}

#[tracing::instrument(level = "trace", skip(auth), ret(Debug), err(Display))]
async fn parse_headers(
    authentication: Option<String>,
    auth: Arc<dyn Authenticator>,
) -> anyhow::Result<User> {
    let jwt_token = if let Some(jwt_token) = authentication {
        jwt_token
            .strip_prefix(PREFIX_BEARER_TOKEN)
            .map(str::to_string)
            .unwrap_or(jwt_token)
    } else {
        status_bail!(StatusCode::UNAUTHORIZED, "No JWT present.");
    };

    let claims = auth.parse_jwt(&jwt_token).await?;

    // let mut claims = match &auth {
    //     Authenticator::Simple(key) =>  verify_with_simple_key(&jwt_token, key.as_ref())?,
    //     Authenticator::Jwks(jwks_settings) => {
    //         verify_with_jwks(&jwt_token, jwks_settings.as_ref()).await?
    //     }
    // };
    //
    // if !claims.contains_key(CLAIM_LOCALE) {
    //     claims.insert(CLAIM_LOCALE.to_string(), Value::from(auth.default_locale()));
    // }

    Ok(User { claims })
}
#[cfg(test)]
mod tests {
    use crate::web::auth::authenticator::SimpleAuthenticator;
    use crate::web::auth::*;
    use crate::web::error::ApiError;
    use anyhow::Context;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use warp::http::StatusCode;

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

        fn with_value(mut self, key: &str, value: Value) -> Self {
            self.claims.insert(key.to_owned(), value);
            self
        }

        fn build_user(self) -> User {
            User {
                claims: self.claims,
            }
        }

        fn into_token(self, secret: &str) -> Result<String, anyhow::Error> {
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
            "{\"tenant\": \"0815\", \"auth\": \"1234\" }"
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
            "{\"tenant\": \"0815\", \"auth\": \"1234\", \"act\": \"sub1\" }"
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
            "{\"tenant\": \"0815\", \"auth\": \"1234\", \"act\": \"sub1, sub2\" }"
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

    #[tokio::test]
    async fn with_user_succeeds_with_valid_token() {
        let token = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
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
    async fn with_user_with_permission_succeeds_with_valid_token() {
        let token = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
        let filter = with_user_with_any_permission(authenticator, &["permission1"]);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn with_user_with_permission_succeeds_fails_for_token_with_missing_permission() {
        let token = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
        let filter = with_user_with_any_permission(authenticator, &["missing-permission"]);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn with_user_fails_without_token() {
        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
        let filter = with_user(authenticator);

        let res = warp::test::request().filter(&filter).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn with_user_fails_with_invalid_token() {
        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
        let filter = with_user(authenticator);

        let res = warp::test::request()
            .header("authorization", "Bearer invalid.jwt.token")
            .filter(&filter)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn parse_headers_without_token_fails() {
        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
        assert!(parse_headers(None, authenticator).await.is_err());
    }

    #[tokio::test]
    async fn parse_headers_with_valid_token_succeeds() {
        let token = Builder::new()
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(SimpleAuthenticator::new("some-secret"));
        let user = parse_headers(Some(token), authenticator).await.unwrap();
        assert_eq!(user.tenant_id().unwrap(), "0815");
        assert_eq!(user.user_id().unwrap(), "1234");
        assert_eq!(user.full_name().unwrap(), "test");
    }

    #[tokio::test]
    async fn parse_headers_with_external_jwt_succeeds() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Arc::new(SimpleAuthenticator::new("external-secret"));
        let user = parse_headers(Some(jwt.to_owned()), authenticator)
            .await
            .unwrap();
        assert_eq!(user.tenant_id().unwrap(), "21516239022");
        assert_eq!(user.user_id().unwrap(), "1234567890");
        assert_eq!(user.full_name().unwrap(), "John Doe");
    }

    #[tokio::test]
    async fn parse_headers_with_bearer_token_succeeds() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Arc::new(SimpleAuthenticator::new("external-secret"));
        assert!(
            parse_headers(Some(format!("Bearer {}", jwt)), authenticator)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn parse_headers_with_invalid_secret_fails() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Arc::new(SimpleAuthenticator::new("wrong-secret"));
        let err = parse_headers(Some(jwt.to_owned()), authenticator)
            .await
            .unwrap_err();
        let api_error = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api_error.status, StatusCode::UNAUTHORIZED);
    }
}
