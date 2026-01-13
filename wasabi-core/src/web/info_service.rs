//! Application info endpoint.
//!
//! Exposes `/info/v1` returning app name, version, cluster ID, and task ID.
//! Useful for health checks and deployment verification.

use serde_json::json;
use warp::Filter;
use warp::filters::BoxedFilter;

/// Creates the `/info/v1` route returning application metadata as JSON.
pub fn get_info_route() -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("info" / "v1")
        .and(warp::get())
        .and_then(handle_get_info)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /info/v1", skip_all)]
async fn handle_get_info() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&json!({
            "app": crate::APP_NAME.clone(),
            "version": crate::APP_VERSION.clone(),
            "clusterId": crate::CLUSTER_ID.clone(),
            "taskId": crate::TASK_ID.clone(),
    })))
}
