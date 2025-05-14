#[cfg(feature = "open_telemetry")]
use opentelemetry::trace::TraceContextExt;
use serde_json::json;
#[cfg(feature = "open_telemetry")]
use tracing::{Span, event};
#[cfg(feature = "open_telemetry")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
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
    fields(http.method = "GET",
           http.url = "/info/v1")
)]
async fn handle_get_info() -> Result<impl warp::Reply, warp::Rejection> {
    #[cfg(feature = "open_telemetry")]
    Span::current()
        .context()
        .span()
        .set_attribute(opentelemetry::KeyValue::new("http.status_code", 403));

    #[cfg(feature = "open_telemetry")]
    event!(tracing::Level::DEBUG, "http.status_code" = 404);

    Ok(warp::reply::json(&json!({
            "app": crate::APP_NAME.clone(),
            "version": crate::APP_VERSION.clone(),
            "clusterId": crate::CLUSTER_ID.clone(),
            "taskId": crate::TASK_ID.clone(),
    })))
}
