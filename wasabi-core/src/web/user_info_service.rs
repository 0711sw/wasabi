//! User info endpoint.
//!
//! Exposes `/user-info/v1` returning all JWT claims of the authenticated user.
//! Useful for debugging authentication and inspecting token contents.

use crate::web::auth::authenticator::Authenticator;
use crate::web::auth::user::User;
use crate::web::auth::with_user;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;

/// Creates the `/user-info/v1` route returning all user claims as JSON.
pub fn get_user_info_route(authenticator: Arc<Authenticator>) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("user-info" / "v1")
        .and(warp::get())
        .and(with_user(authenticator))
        .and_then(handle_get_user_info)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /user-info/v1", skip_all)]
async fn handle_get_user_info(user: User) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&user.claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::user::tests::Builder;
    use crate::web::auth::{CLAIM_EMAIL, CLAIM_NAME, CLAIM_SUB, CLAIM_TENANT};

    #[tokio::test]
    async fn get_user_info_returns_all_claims() {
        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .with_string(CLAIM_TENANT, "tenant-456")
            .with_string(CLAIM_NAME, "John Doe")
            .with_string(CLAIM_EMAIL, "john@example.com")
            .into_token("test-secret")
            .unwrap();

        let authenticator = Arc::new(Authenticator::with_simple_secret("test-secret"));
        let filter = get_user_info_route(authenticator);

        let res = warp::test::request()
            .path("/user-info/v1")
            .header("authorization", format!("Bearer {}", token))
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 200);

        let body: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        assert_eq!(body["sub"], "user-123");
        assert_eq!(body["tenant"], "tenant-456");
        assert_eq!(body["name"], "John Doe");
        assert_eq!(body["email"], "john@example.com");
    }

    #[tokio::test]
    async fn get_user_info_fails_without_token() {
        let authenticator = Arc::new(Authenticator::with_simple_secret("test-secret"));
        let filter = with_user(authenticator);

        let res = warp::test::request().filter(&filter).await;

        assert!(res.is_err());
    }
}
