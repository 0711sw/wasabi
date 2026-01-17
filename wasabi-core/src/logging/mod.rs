//! Tracing and logging infrastructure.
//!
//! Provides a unified [`setup_tracing`] function that configures the `tracing` subscriber
//! with console output and optional OpenTelemetry export.
//!
//! # Usage
//!
//! Call [`setup_tracing`] once at application startup:
//!
//! ```rust,ignore
//! fn main() {
//!     wasabi_core::logging::setup_tracing();
//!     // ... rest of application
//! }
//! ```
//!
//! # Features
//!
//! - **Console logging** - Always enabled, respects `RUST_LOG` env var for filtering
//! - **Pretty logs** (`pretty_logs` feature) - Colorful, human-friendly console output
//! - **OpenTelemetry** (`open_telemetry` feature) - Export traces to OTLP endpoint
//!
//! # Environment Variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `RUST_LOG` | Console log filter (e.g., `info`, `myapp=debug`) | `info` |
//! | `RUST_TRACE` | OpenTelemetry trace filter | `debug` |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint URL | (required for OTel) |
//!
//! # Output Modes
//!
//! Without `pretty_logs`, output is plain text suitable for log aggregation:
//! ```text
//! INFO myapp::server: Starting server on port 8080
//! ```
//!
//! With `pretty_logs`, output is colorized with timestamps and span nesting:
//! ```text
//! 14:32:01.234 INFO  | myapp::server: Starting server on port 8080
//! ```

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

#[cfg(feature = "pretty_logs")]
use tracing_subscriber::fmt::format::FmtSpan;

#[cfg(not(feature = "pretty_logs"))]
mod production;

#[cfg(feature = "pretty_logs")]
mod pretty;

#[cfg(feature = "open_telemetry")]
mod otel;

/// Initializes the tracing subscriber with console output and optional OpenTelemetry.
///
/// This function should be called once at application startup. It configures:
///
/// - **Console layer**: Outputs to stdout, filtered by `RUST_LOG` env var
/// - **OpenTelemetry layer** (if `open_telemetry` feature enabled): Exports to OTLP endpoint
///
/// If OpenTelemetry setup fails (e.g., missing endpoint), it falls back to console-only
/// logging and logs a warning.
///
/// # Panics
///
/// Panics if called more than once (tracing subscriber can only be set once).
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

/// Initializes the tracing subscriber with console output only.
///
/// This version is used when the `open_telemetry` feature is not enabled.
/// See the feature-enabled version for full documentation.
#[cfg(not(feature = "open_telemetry"))]
pub fn setup_tracing() {
    let console_layer = setup_console_layer();
    Registry::default().with(console_layer).init();
    tracing::info!("Tracing initialized successfully [reporting to console only]");
}

/// Creates the console output layer with appropriate formatting.
///
/// Uses `RUST_LOG` environment variable for filtering, defaulting to `info`.
/// Format depends on whether `pretty_logs` feature is enabled.
#[cfg(feature = "pretty_logs")]
fn setup_console_layer() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW)
        .event_format(setup_console_format())
        .with_filter(filter)
        .boxed()
}

/// Creates the console output layer for production (no ANSI, with span context).
#[cfg(not(feature = "pretty_logs"))]
fn setup_console_layer() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .event_format(setup_console_format())
        .with_filter(filter)
        .boxed()
}

#[cfg(feature = "pretty_logs")]
fn setup_console_format() -> pretty::PrettyConsoleLogFormat {
    pretty::PrettyConsoleLogFormat {}
}

#[cfg(not(feature = "pretty_logs"))]
fn setup_console_format() -> production::ProductionLogFormat {
    production::ProductionLogFormat
}
