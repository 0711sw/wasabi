use crate::APP_NAME;
use anyhow::Context;
use std::env;
use tracing::{Level, Subscriber};
use tracing_subscriber::filter::{FilterExt, filter_fn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

#[cfg(feature = "pretty_logs")]
mod console;

#[cfg(feature = "open_telemetry")]
mod otel;

#[cfg(feature = "open_telemetry")]
pub fn setup_tracing() {
    let console_layer = setup_console_layer();

    match otel::setup_open_telemetry_layer() {
        Ok(otlp_layer) => {
            Registry::default()
                .with(console_layer)
                .with(otlp_layer)
                .init();

            tracing::info!(
                "Tracing initialized successfully [reporting to console as well as OpenTelemetry]"
            );
        }
        Err(err) => {
            Registry::default().with(console_layer).init();
            tracing::info!("Tracing initialized successfully [reporting to console only]");
            tracing::info!("Skipping OpenTelemetry setup: {:#}", err);
        }
    }
}

#[cfg(not(feature = "open_telemetry"))]
pub fn setup_tracing() {
    let console_layer = setup_console_layer();
    Registry::default().with(console_layer).init();
    tracing::info!("Tracing initialized successfully [reporting to console only]");
}

#[cfg(feature = "pretty_logs")]
fn setup_console_layer() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW)
        .event_format(crate::logging::console::ConsoleDebugFormat)
        .with_filter(filter)
        .boxed()
}

#[cfg(not(feature = "pretty_logs"))]
fn setup_console_layer() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = tracing_subscriber::fmt::format()
        .with_ansi(false)
        .without_time();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let layer = tracing_subscriber::fmt::layer()
        .event_format(format)
        .with_filter(filter);

    layer.boxed()
}