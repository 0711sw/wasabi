use crate::{APP_VERSION, CLUSTER_ID, TASK_ID};
use anyhow::Context;
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use std::env;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer};

pub fn setup_open_telemetry_layer<S>() -> anyhow::Result<impl Layer<S>>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .context("No OpenTelemetry endpoint present in OTEL_EXPORTER_OTLP_ENDPOINT")?;

    let provider = setup_open_telemetry(endpoint)?;
    let tracer = provider.tracer(crate::APP_NAME.clone());
    let filter = EnvFilter::try_from_env("RUST_TRACE").unwrap_or_else(|_| EnvFilter::new("debug"));
    let layer = OpenTelemetryLayer::new(tracer).with_filter(filter);

    Ok(layer)
}

fn setup_open_telemetry(endpoint: String) -> anyhow::Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()
        .context(format!(
            "Failed to build OpenTelemetry exporter for: {}",
            endpoint
        ))?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_max_events_per_span(64)
        .with_max_attributes_per_span(16)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([
                    KeyValue::new(
                        opentelemetry_semantic_conventions::resource::CLOUD_PROVIDER,
                        "aws",
                    ),
                    KeyValue::new(
                        opentelemetry_semantic_conventions::resource::CLOUD_PLATFORM,
                        "aws_ecs",
                    ),
                    KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                        CLUSTER_ID.clone(),
                    ),
                    KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_INSTANCE_ID,
                        TASK_ID.clone(),
                    ),
                    KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                        APP_VERSION.clone(),
                    ),
                ])
                .build(),
        )
        .build();

    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    Ok(tracer_provider)
}
