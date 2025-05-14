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
    name = "GET /info/v1",
    skip_all,
    fields(http.request.method = "GET",
           http.url = "1",
           http.method = "2",
           http.status_code = 404,
           http.content_length = 5,
              http.route = "/info/v112",
              http.response.status_code = 405,
           http.response.content_length = 8,
           span.kind = "server",
              url.path = "/info/v1")
)]
async fn handle_get_info() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&json!({
            "app": crate::APP_NAME.clone(),
            "version": crate::APP_VERSION.clone(),
            "clusterId": crate::CLUSTER_ID.clone(),
            "taskId": crate::TASK_ID.clone(),
    })))
}
