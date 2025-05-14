use serde_json::json;
use warp::Filter;
use warp::filters::BoxedFilter;

pub fn get_info_route() -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("info" / "v1")
        .and(warp::get())
        .and_then(handle_get_info)
        .boxed()
}

#[tracing::instrument(level = "debug",
    target = "/info/v1",
    name = "GET /info/v1",
    skip_all,
    fields(http.request.method = "GET",
           url.path = "/info/v1",
           http.response.status_code = 200,
           http.response.content_length = 0)
)]
async fn handle_get_info() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&json!({
            "app": crate::APP_NAME.clone(),
            "version": crate::APP_VERSION.clone(),
            "clusterId": crate::CLUSTER_ID.clone(),
            "taskId": crate::TASK_ID.clone(),
    })))
}
