use crate::web::warp::with_cloneable;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::Uri;

pub fn get_favicon_route(effective_favicon_uri: &'static str) -> BoxedFilter<(impl warp::Reply,)> {
    let uri = Arc::new(Uri::from_static(effective_favicon_uri));
    warp::path!("favicon.ico")
        .and(warp::get())
        .and(with_cloneable(uri))
        .and_then(handle_get_favicon)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /favicon.ico", skip_all)]
async fn handle_get_favicon(uri: Arc<Uri>) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::redirect::temporary(uri.as_ref().clone()))
}
