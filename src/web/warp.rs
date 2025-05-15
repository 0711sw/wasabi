use crate::client_bail;
use crate::web::error::{ApiError, ResultExt};
use anyhow::{Context, anyhow};
use futures_util::{Stream, StreamExt, TryStreamExt};
use http::Request;
use hyper::Server;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::task::Poll;
use tokio_util::bytes::Buf;
use tokio_util::bytes::BufMut;
use tracing::debug_span;
use warp::http::header::CONTENT_TYPE;
use warp::http::{HeaderValue, StatusCode};
use warp::reply::Response;
use warp::{Filter, Rejection, Reply, http, reply};

use tower::{Service, ServiceBuilder};
use warp::hyper::Body;

pub fn content_length_header() -> impl Filter<Extract = (i64,), Error = Rejection> + Clone {
    warp::header::header::<i64>(http::header::CONTENT_LENGTH.as_str())
}

pub fn with_cloneable<C: Clone + Send>(
    value: C,
) -> impl Filter<Extract = (C,), Error = Infallible> + Clone {
    warp::any().map(move || value.clone())
}

pub async fn body_as_buffer(
    stream: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin + Send,
    content_length: i64,
    max_body_size: i64,
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

pub async fn as_size_limited_stream<E: Error + Send + Sync + 'static>(
    stream: impl Stream<Item = Result<impl Buf, E>> + Unpin + Send,
    content_length: i64,
) -> impl Stream<Item = Result<impl Buf, std::io::Error>> {
    let mut remaining_bytes = content_length;

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

pub async fn read_into_buffer(
    mut stream: impl Stream<Item = Result<impl Buf, std::io::Error>> + Unpin,
    content_length: i64,
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

pub async fn decode_json<T: DeserializeOwned + Send>(
    stream: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin + Send,
    content_length: i64,
    max_body_size: i64,
) -> anyhow::Result<T> {
    let data = body_as_buffer(stream, content_length, max_body_size).await?;
    let decoded = serde_json::from_slice(&data)
        .context("Invalid JSON input")
        .mark_client_error()?;

    Ok(decoded)
}

pub async fn body_as_string(
    stream: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin + Send,
    content_length: i64,
    max_body_size: i64,
) -> anyhow::Result<String> {
    let data = body_as_buffer(stream, content_length, max_body_size).await?;
    let data_as_string = String::from_utf8(data)
        .context("Received invalid UTF-8 data")
        .mark_client_error()?;

    Ok(data_as_string)
}
pub fn into_response<S: Serialize>(result: anyhow::Result<S>) -> Result<impl Reply, Rejection> {
    into_response_with_status(result.map(|data| (StatusCode::OK, data)))
}

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

#[macro_export]
macro_rules! routes {
    [$route:expr] => {
        $route
    };
    [$route:expr, $($rest:expr),+] => {
        warp::Filter::or($route, routes![$($rest),+])
    };
}

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
        .await
        .with_context(|| format!("Failed to bind HTTP server to {}", bind_address))?;
    tracing::info!("HTTP Server has terminated...");

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

        let span = debug_span!(
            "http_request",
            aws.service = crate::CLUSTER_ID.clone(),
            http.method = %method,
            http.url = %path,
            http.status_code = tracing::field::Empty,
        );

        let mut inner = self.inner.clone();

        let fut = async move {
            let _enter = span.enter();
            let response = inner.call(req).await?;
            let status = response.status();
            span.record("http.status_code", &status.as_u16());
            Ok(response)
        };

        Box::pin(fut)
    }
}

#[cfg(test)]
mod tests {
    use crate::web::warp::as_size_limited_stream;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use futures_util::stream;

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
}
