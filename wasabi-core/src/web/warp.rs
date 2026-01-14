//! Warp framework utilities and HTTP server setup.
//!
//! Provides filters for parsing request bodies (JSON, form, raw bytes/streams),
//! response helpers, error handling, and the main [`run_webserver`] function
//! that sets up tracing and graceful shutdown.

use crate::client_bail;
use crate::web::error::{ApiError, ResultExt};
use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
use http::Request;
use hyper::{Body, Server};
use percent_encoding::percent_decode_str;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::task::Poll;
use std::time::Duration;
use tokio_util::bytes::Buf;
use tokio_util::bytes::BufMut;
use tracing::{Instrument, Span, debug_span};
use warp::http::header::CONTENT_TYPE;
use warp::http::{HeaderValue, StatusCode};
use warp::reply::Response;
use warp::{Filter, Rejection, Reply, http, reply};

use crate::tools::{PinnedBytesStream, system};
use tower::{Service, ServiceBuilder};

/// Filter that extracts the Content-Length header as u64.
pub fn content_length_header() -> impl Filter<Extract = (u64,), Error = Rejection> + Clone {
    warp::header::header::<u64>(http::header::CONTENT_LENGTH.as_str())
}

/// Filter that injects a cloneable value into the filter chain.
pub fn with_cloneable<C: Clone + Send>(
    value: C,
) -> impl Filter<Extract = (C,), Error = Infallible> + Clone {
    warp::any().map(move || value.clone())
}

/// Filter that reads the request body into a `Vec<u8>`, enforcing size limits.
pub fn with_body_as_buffer(
    max_body_size: u64,
) -> impl Filter<Extract = (Vec<u8>,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async move |stream, content_length, max_body_size| {
            body_as_buffer(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn body_as_buffer(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<Vec<u8>> {
    if content_length == 0 {
        client_bail!("Empty input data");
    }
    if content_length > max_body_size {
        client_bail!("The given request data is too large");
    }

    let stream = as_size_limited_stream(stream, content_length).await;
    read_into_buffer(stream, content_length).await
}

async fn as_size_limited_stream<E: Error + Send + Sync + 'static>(
    stream: impl Stream<Item = Result<impl Buf, E>> + Unpin + Send,
    content_length: u64,
) -> impl Stream<Item = Result<impl Buf, std::io::Error>> {
    let mut remaining_bytes = content_length as i64;

    stream.map(move |result| match result {
        Ok(bytes) => {
            remaining_bytes -= bytes.remaining() as i64;
            if remaining_bytes < 0 {
                Err(std::io::Error::other(anyhow!("Input data too large")))
            } else {
                Ok(bytes)
            }
        }
        Err(err) => Err(std::io::Error::other(err)),
    })
}

fn buf_to_bytes(mut buf: impl Buf) -> Bytes {
    let len = buf.remaining();
    let mut vec = vec![0u8; len];
    buf.copy_to_slice(&mut vec);
    Bytes::from(vec)
}

/// Filter that provides the request body as a streaming `PinnedBytesStream`.
pub fn with_body_as_stream(
    max_content_size: u64,
) -> impl Filter<Extract = (PinnedBytesStream,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_content_size))
        .and_then(async move |stream, content_length, max_content_size| {
            as_stream(
                as_size_limited_stream(stream, content_length).await,
                content_length,
                max_content_size,
            )
            .await
            .map_err(into_rejection)
        })
}

async fn as_stream(
    stream: impl Stream<Item = Result<impl Buf + 'static, std::io::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<PinnedBytesStream> {
    if content_length == 0 {
        client_bail!("Empty input data");
    }
    if content_length > max_body_size {
        client_bail!("The given request data is too large");
    }

    Ok(Box::pin(stream.map_ok(buf_to_bytes)) as PinnedBytesStream)
}

/// Reads a byte stream into a pre-allocated buffer.
pub async fn read_into_buffer(
    mut stream: impl Stream<Item = Result<impl Buf, std::io::Error>> + Unpin,
    content_length: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(content_length as usize);
    while let Some(chunk) = stream
        .try_next()
        .await
        .context("Failed to read body")
        .mark_client_error()?
    {
        data.put(chunk);
    }

    Ok(data)
}

/// Filter that parses the request body as JSON into type `T`.
pub fn with_body_as_json<T: DeserializeOwned + Send>(
    max_body_size: u64,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async |stream, content_length, max_body_size| {
            decode_json(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn decode_json<T: DeserializeOwned + Send>(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<T> {
    let data = body_as_buffer(stream, content_length, max_body_size).await?;
    let decoded = serde_json::from_slice(&data)
        .context("Invalid JSON input")
        .mark_client_error()?;

    Ok(decoded)
}

/// Filter that parses URL-encoded form data into type `T`.
pub fn with_body_as_form<T: DeserializeOwned + Send>(
    max_body_size: u64,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone {
    warp::header::exact_ignore_case("content-type", "application/x-www-form-urlencoded")
        .and(warp::body::stream())
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async |stream, content_length, max_body_size| {
            decode_form(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn decode_form<T: DeserializeOwned + Send>(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<T> {
    let data = body_as_string(stream, content_length, max_body_size).await?;
    let decoded = serde_urlencoded::from_str(&data)
        .context("Invalid url-encoded data input")
        .mark_client_error()?;

    Ok(decoded)
}

/// Filter that reads the request body as a UTF-8 string.
pub fn with_body_as_string(
    max_body_size: u64,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async |stream, content_length, max_body_size| {
            body_as_string(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn body_as_string(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<String> {
    let data = body_as_buffer(stream, content_length, max_body_size).await?;
    let data_as_string = String::from_utf8(data)
        .context("Received invalid UTF-8 data")
        .mark_client_error()?;

    Ok(data_as_string)
}
/// Converts a result into a JSON response with status 200 OK.
pub fn into_response<S: Serialize>(result: anyhow::Result<S>) -> Result<impl Reply, Rejection> {
    into_response_with_status(result.map(|data| (StatusCode::OK, data)))
}

/// Converts a result into a JSON response with a custom status code.
pub fn into_response_with_status<S: Serialize>(
    response: anyhow::Result<(StatusCode, S)>,
) -> Result<impl Reply, Rejection> {
    let response = response.and_then(|(status_code, data)| {
        match serde_json::to_vec(&data).context("Failed to serialize data") {
            Ok(data) => Ok((status_code, data)),
            Err(err) => Err(err),
        }
    });

    match response {
        Ok((status, data)) => {
            let mut res = Response::new(data.into());
            *res.status_mut() = status;
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            Ok(res)
        }
        Err(err) => Err(into_rejection(err)),
    }
}

/// Converts an anyhow error into a warp Rejection, preserving ApiError status if present.
pub fn into_rejection(err: anyhow::Error) -> Rejection {
    match err.downcast_ref::<ApiError>() {
        Some(api_error) => api_error.clone().into(),
        None => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{:#}", err)).into(),
    }
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(err) = err.find::<ApiError>() {
        Ok(reply::with_status(reply::json(&err), err.status))
    } else {
        Err(err)
    }
}

/// Combines multiple routes using `or`. Usage: `routes![route1, route2, route3]`
#[macro_export]
macro_rules! routes {
    [$route:expr] => {
        $route
    };
    [$route:expr, $($rest:expr),+] => {
        warp::Filter::or($route, routes![$($rest),+])
    };
}

/// Starts an HTTP server with tracing and graceful shutdown.
///
/// Reads `BIND_ADDRESS` from environment. Waits for shutdown signal,
/// then allows 3 seconds for in-flight requests to complete.
pub async fn run_webserver<F>(routes: F) -> anyhow::Result<()>
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: Reply,
    F::Error: Into<Rejection> + 'static,
{
    let bind_address = env::var("BIND_ADDRESS")
        .context("Failed to read bind address. Please provide BIND_ADDRESS in the environment")?;
    let bind_address =
        SocketAddr::from_str(&bind_address).context("Failed to parse bind address.")?;

    tracing::info!("Starting server at {}", bind_address.clone());

    let filter = routes.boxed().recover(handle_rejection);

    let svc = warp::service(filter);
    let traced_svc = ServiceBuilder::new()
        .layer_fn(|inner| TracingMiddleware { inner })
        .service(svc);

    let server = Server::bind(&bind_address).serve(hyper::service::make_service_fn(|_| {
        let svc = traced_svc.clone();
        async move { Ok::<_, Infallible>(svc) }
    }));

    tracing::info!(
        "Running HTTP server at effective address {}",
        server.local_addr()
    );
    server
        .with_graceful_shutdown(system::await_shutdown())
        .await
        .with_context(|| format!("Failed to bind HTTP server to {}", bind_address))?;

    tracing::info!("HTTP Server has been stopped...");
    // Wait a bit to ensure all requests are processed and also permit background tasks to finish
    // (as most probably the web server will run in the main thread which will cause the process
    // to terminate once it completes).
    tokio::time::sleep(Duration::from_secs(3)).await;
    tracing::info!("HTTP Server has been terminated.");

    Ok(())
}

#[derive(Clone)]
struct TracingMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for TracingMiddleware<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        #[cfg_attr(not(feature = "open_telemetry"), allow(unused_mut))]
        let mut span = debug_span!(
            "http_request",
            aws.service = crate::CLUSTER_ID.clone(),
            http.method = %method,
            http.url = %path,
            http.status_code = tracing::field::Empty,
        );

        #[cfg(feature = "open_telemetry")]
        open_telemetry::extract_parent_context(req.headers(), &mut span);

        let mut inner = self.inner.clone();

        let fut = async move {
            let response = inner.call(req).await?;
            let status = response.status().as_u16();
            Span::current().record("http.status_code", status as i64);
            Ok(response)
        }
        .instrument(span);

        Box::pin(fut)
    }
}

/// A URL path segment that has been percent-decoded.
///
/// Use in route patterns to automatically decode path segments like `%20` → ` `.
#[derive(Debug, Clone)]
pub struct DecodedSegment(pub String);

impl FromStr for DecodedSegment {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "%20" -> " "
        let decoded = percent_decode_str(s).decode_utf8_lossy().into_owned();
        Ok(DecodedSegment(decoded))
    }
}

impl From<DecodedSegment> for String {
    fn from(value: DecodedSegment) -> Self {
        value.0
    }
}

#[cfg(feature = "open_telemetry")]
mod open_telemetry {
    use hyper::http::HeaderMap;

    use opentelemetry::propagation::Extractor;
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    struct HeaderExtractor<'a> {
        headers: &'a HeaderMap,
    }

    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.headers.get(key).and_then(|value| value.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.headers.keys().map(|header| header.as_str()).collect()
        }
    }

    pub fn extract_parent_context(headers: &HeaderMap, span: &mut Span) {
        let extractor = HeaderExtractor { headers };
        let parent_cx =
            opentelemetry::global::get_text_map_propagator(|prop| prop.extract(&extractor));
        let _ = span.set_parent(parent_cx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::error::ApiError;
    use bytes::Bytes;
    use futures_util::stream;
    use futures_util::StreamExt;
    use std::str::FromStr;

    // as_size_limited_stream tests

    #[tokio::test]
    async fn as_size_limited_stream_allows_valid_size() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from("hello"))]);
        let result: Vec<_> = as_size_limited_stream(stream, 5).await.collect().await;

        assert!(result.iter().all(Result::is_ok));
    }

    #[tokio::test]
    async fn as_size_limited_stream_rejects_oversize_input() {
        let stream = stream::iter(vec![
            Ok::<Bytes, warp::Error>(Bytes::from("hello")),
            Ok::<Bytes, warp::Error>(Bytes::from("world")),
            Ok::<Bytes, warp::Error>(Bytes::from("foobar")),
        ]);
        let result: Vec<_> = as_size_limited_stream(stream, 5).await.collect().await;

        assert_eq!(result.iter().filter(|res| res.is_ok()).count(), 1);
        assert_eq!(result.iter().filter(|res| res.is_err()).count(), 2);
    }

    #[tokio::test]
    async fn as_size_limited_stream_handles_empty_input() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from(""))]);
        let result: Vec<_> = as_size_limited_stream(stream, 0).await.collect().await;

        assert!(result.iter().all(|res| res.is_ok()));
    }

    #[tokio::test]
    async fn as_size_limited_stream_propagates_stream_errors() {
        let stream = stream::iter(vec![Err::<Bytes, std::io::Error>(std::io::Error::other(
            "Test error",
        ))]);
        let result: Vec<_> = as_size_limited_stream(stream, 5).await.collect().await;

        assert!(result.iter().any(|res| res.is_err()));
    }

    // into_rejection tests

    #[test]
    fn into_rejection_preserves_api_error_status() {
        use crate::web::error::ResultExt;

        // Create an error with ApiError context
        let err: anyhow::Error = anyhow::anyhow!("root cause")
            .context(ApiError::new(StatusCode::NOT_FOUND, "Not found"));

        let rejection = into_rejection(err);

        let found = rejection.find::<ApiError>().unwrap();
        assert_eq!(found.status, StatusCode::NOT_FOUND);
        assert_eq!(found.message, "Not found");
    }

    #[test]
    fn into_rejection_defaults_to_500_for_plain_errors() {
        let err = anyhow::anyhow!("Something went wrong");

        let rejection = into_rejection(err);

        let found = rejection.find::<ApiError>().unwrap();
        assert_eq!(found.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(found.message.contains("Something went wrong"));
    }

    // DecodedSegment tests

    #[test]
    fn decoded_segment_decodes_percent_encoding() {
        let segment = DecodedSegment::from_str("hello%20world").unwrap();
        assert_eq!(segment.0, "hello world");
    }

    #[test]
    fn decoded_segment_decodes_special_chars() {
        let segment = DecodedSegment::from_str("foo%2Fbar").unwrap();
        assert_eq!(segment.0, "foo/bar");

        let segment = DecodedSegment::from_str("a%3Db").unwrap();
        assert_eq!(segment.0, "a=b");
    }

    #[test]
    fn decoded_segment_passes_through_plain_text() {
        let segment = DecodedSegment::from_str("hello").unwrap();
        assert_eq!(segment.0, "hello");
    }

    #[test]
    fn decoded_segment_converts_to_string() {
        let segment = DecodedSegment::from_str("test").unwrap();
        let s: String = segment.into();
        assert_eq!(s, "test");
    }

    // read_into_buffer tests

    #[tokio::test]
    async fn read_into_buffer_collects_chunks() {
        let stream = stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::from("hel")),
            Ok(Bytes::from("lo")),
        ]);
        let result = read_into_buffer(stream, 5).await.unwrap();
        assert_eq!(result, b"hello");
    }

    #[tokio::test]
    async fn read_into_buffer_handles_empty_stream() {
        let stream = stream::iter(Vec::<Result<Bytes, std::io::Error>>::new());
        let result = read_into_buffer(stream, 0).await.unwrap();
        assert!(result.is_empty());
    }
}
