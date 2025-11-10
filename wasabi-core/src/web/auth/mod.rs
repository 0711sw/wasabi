use crate::status_bail;
use crate::web::auth::authenticator::Authenticator;
use crate::web::auth::user::User;
use crate::web::warp::{into_rejection, with_cloneable};
use std::sync::Arc;
use serde::Deserialize;
use warp::http::StatusCode;
use warp::{Filter, Rejection};

pub mod authenticator;
pub mod user;

mod jwks;

const PREFIX_BEARER_TOKEN: &str = "Bearer ";

pub(crate) const DEFAULT_LOCALE: &str = "en-US";

pub const CLAIM_AUD: &str = "aud";
pub const CLAIM_ISS: &str = "iss";
pub const CLAIM_SUB: &str = "sub";
pub const CLAIM_ACT: &str = "act";
pub const CLAIM_LOCALE: &str = "locale";
pub const CLAIM_TENANT: &str = "tenant";
pub const CLAIM_NAME: &str = "name";
pub const CLAIM_EMAIL: &str = "email";
pub const CLAIM_PERMISSIONS: &str = "permissions";

#[derive(Deserialize)]
struct TokenInQueryString {
    jwt: Option<String>,
}

pub fn with_user(
    authenticator: Arc<Authenticator>,
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>(
            warp::http::header::AUTHORIZATION.as_str(),
        ))
        .and(warp::query::<TokenInQueryString>())
        .and(with_cloneable(authenticator))
        .and_then(|authorization : Option<String>, query_string: TokenInQueryString, authenticator| async {
            parse_jwt_token(authorization.or(query_string.jwt), authenticator)
                .await
                .map_err(into_rejection)
        })
}

pub fn with_user_with_any_permission(
    authenticator: Arc<Authenticator>,
    permissions: &[&str],
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    with_user(authenticator).and_then(move |user: User| async move {
        user.enforce_any_permission(permissions)
            .map_err(into_rejection)
    })
}

pub fn enforce_user_with_any_permission(
    authenticator: Arc<Authenticator>,
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
async fn parse_jwt_token(
    bearer_token: Option<String>,
    auth: Arc<Authenticator>,
) -> anyhow::Result<User> {
    let jwt_token = if let Some(jwt_token) = bearer_token {
        jwt_token
            .strip_prefix(PREFIX_BEARER_TOKEN)
            .map(str::to_string)
            .unwrap_or(jwt_token)
    } else {
        status_bail!(StatusCode::UNAUTHORIZED, "No JWT present.");
    };

    let claims = auth.parse_jwt(&jwt_token).await?;
    Ok(User { claims })
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use hyper::StatusCode;
    use serde_json::json;
    use crate::web::auth::{parse_jwt_token, with_user, with_user_with_any_permission, CLAIM_NAME, CLAIM_PERMISSIONS, CLAIM_SUB, CLAIM_TENANT};
    use crate::web::auth::authenticator::Authenticator;
    use crate::web::auth::user::tests::Builder;
    use crate::web::error::ApiError;

    #[tokio::test]
    async fn with_user_succeeds_with_valid_token() {
        let token = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
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
    async fn with_user_succeeds_with_valid_token_as_query_param() {
        let token = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        let filter = with_user(authenticator);

        let res = warp::test::request().path(&format!("/?jwt={token}"))
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

        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        let filter = with_user_with_any_permission(authenticator, &["permission1"]);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn with_user_with_permission_fails_for_token_with_missing_permission() {
        let token = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        let filter = with_user_with_any_permission(authenticator, &["missing-permission"]);

        let res = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn with_user_fails_without_token() {
        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        let filter = with_user(authenticator);

        let res = warp::test::request().filter(&filter).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn with_user_fails_with_invalid_token() {
        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        let filter = with_user(authenticator);

        let res = warp::test::request()
            .header("authorization", "Bearer invalid.jwt.token")
            .filter(&filter)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn parse_headers_without_token_fails() {
        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        assert!(parse_jwt_token(None, authenticator).await.is_err());
    }

    #[tokio::test]
    async fn parse_headers_with_valid_token_succeeds() {
        let token = Builder::new()
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_NAME, "test")
            .into_token("some-secret")
            .unwrap();

        let authenticator = Arc::new(Authenticator::with_simple_secret("some-secret"));
        let user = parse_jwt_token(Some(token), authenticator).await.unwrap();
        assert_eq!(user.tenant_id().unwrap(), "0815");
        assert_eq!(user.user_id().unwrap(), "1234");
        assert_eq!(user.full_name().unwrap(), "test");
    }

    #[tokio::test]
    async fn parse_headers_with_external_jwt_succeeds() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Arc::new(Authenticator::with_simple_secret("external-secret"));
        let user = parse_jwt_token(Some(jwt.to_owned()), authenticator)
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

        let authenticator = Arc::new(Authenticator::with_simple_secret("external-secret"));
        assert!(
            parse_jwt_token(Some(format!("Bearer {}", jwt)), authenticator)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn parse_headers_with_invalid_secret_fails() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50IjoiMjE1MTYyMzkwMjIifQ.\
                         JWvhLyGHKP4cF7jFpxpRmnWmanVay1gNzwkLF9dE5YE";

        let authenticator = Arc::new(Authenticator::with_simple_secret("wrong-secret"));
        let err = parse_jwt_token(Some(jwt.to_owned()), authenticator)
            .await
            .unwrap_err();
        let api_error = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api_error.status, StatusCode::UNAUTHORIZED);
    }
}
