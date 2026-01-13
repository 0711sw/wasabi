//! Favicon redirect route.
//!
//! Redirects `/favicon.ico` requests to a configurable URI, avoiding the need
//! to serve static files from the application.

use crate::web::warp::with_cloneable;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::Uri;

/// Creates a route that redirects `/favicon.ico` to the given URI.
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
