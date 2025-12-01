use crate::events::{Event, EventRecorder};
use crate::tools::system;
use crate::{APP_NAME, CLUSTER_ID};
use async_trait::async_trait;
use aws_sdk_firehose::Client;
use aws_sdk_firehose::config::http::HttpResponse;
use aws_sdk_firehose::error::SdkError;
use aws_sdk_firehose::operation::put_record_batch::{PutRecordBatchError, PutRecordBatchOutput};
use aws_sdk_firehose::types::Record;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;
use std::env;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::mpsc;

const NON_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").unwrap());
const ENV_FIREHOSE_STREAM_NAME: &str = "FIREHOSE_STREAM_NAME";
const ENV_FIREHOSE_SYSTEM_NAME: &str = "FIREHOSE_SYSTEM_NAME";
const EVENT_BUFFER_SIZE: usize = 8192;
const EVENT_FLUSH_INTERVAL_SECONDS: u64 = 15;
const AUTOMATIC_FLUSH_SIZE: usize = 64;
const MAX_EVENTS_PER_UPLOAD: usize = 256;

#[derive(Serialize)]
struct EventWrapper<'a, T: Event + Serialize> {
    #[serde(flatten)]
    pub payload: &'a T,

    #[serde(serialize_with = "ts_no_tz")]
    pub timestamp: DateTime<Utc>,
    pub event: &'static str,
    pub system: &'a str,
}

fn ts_no_tz<S>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
    s.serialize_str(&formatted)
}

pub struct FirehoseEventRecorder {
    system: String,
    tx: mpsc::Sender<String>,
}

impl FirehoseEventRecorder {}

impl FirehoseEventRecorder {
    #[tracing::instrument(err(Display))]
    pub async fn from_env() -> anyhow::Result<Self> {
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        let stream = env::var(ENV_FIREHOSE_STREAM_NAME).unwrap_or_else(|_| {
            NON_CHARS
                .replace_all(&APP_NAME.to_lowercase(), "_")
                .into_owned()
        });
        let system = env::var(ENV_FIREHOSE_SYSTEM_NAME).unwrap_or_else(|_| {
            NON_CHARS
                .replace_all(&CLUSTER_ID.to_lowercase(), "_")
                .into_owned()
        });

        tracing::info!(
            "Sending events to Firehose as system: {} into stream: {}",
            system,
            stream
        );

        let (tx, rx) = mpsc::channel::<String>(EVENT_BUFFER_SIZE);
        tokio::spawn(async move {
            run_background_loop(&client, &stream, rx).await;
        });

        Ok(Self { system, tx })
    }

    async fn record_event<'a, E: Event>(&self, event: EventWrapper<'a, E>) -> anyhow::Result<()> {
        let json = serde_json::to_string(&event)?;
        self.tx.send(json).await?;

        Ok(())
    }
}

async fn run_background_loop(client: &Client, stream: &str, mut rx: mpsc::Receiver<String>) {
    let mut buffer = Vec::new();
    let mut interval = tokio::time::interval(Duration::from_secs(EVENT_FLUSH_INTERVAL_SECONDS));

    while system::is_running() {
        tokio::select! {
            Some(event) = rx.recv() => {
                buffer.push(event);
                if buffer.len() >= AUTOMATIC_FLUSH_SIZE {
                    flush_batch(&client, &stream, &mut buffer).await;
                }
            },
            _ = interval.tick() => {
                    flush_batch(&client,&stream, &mut buffer).await;
            }
        }
    }

    // Channel closed, flush remaining events...
    flush_batch(&client, &stream, &mut buffer).await;
}

#[tracing::instrument(level = "debug", skip(client, buffer))]
async fn flush_batch(client: &Client, stream: &str, buffer: &mut Vec<String>) {
    let records = buffer
        .drain(..)
        .map(|json| Record::builder().data(json.into_bytes().into()).build())
        .flatten()
        .collect::<Vec<_>>();

    for chunk in records.chunks(MAX_EVENTS_PER_UPLOAD) {
        if let Err(err) = flush_chunk(client, stream, chunk).await {
            tracing::error!(?err, "Failed to send batch of events to Firehose");
        }
    }
}

#[tracing::instrument(level = "debug", skip(client, chunk))]
async fn flush_chunk(
    client: &Client,
    stream: &str,
    chunk: &[Record],
) -> Result<PutRecordBatchOutput, SdkError<PutRecordBatchError, HttpResponse>> {
    client
        .put_record_batch()
        .delivery_stream_name(stream)
        .set_records(Some(chunk.into()))
        .send()
        .await
}

#[async_trait]
impl EventRecorder for FirehoseEventRecorder {
    async fn record<E: Event>(&self, event: E) {
        self.record_at(event, Utc::now()).await;
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn record_at<E: Event>(&self, event: E, timestamp: DateTime<Utc>) {
        let wrapper = EventWrapper {
            payload: &event,
            timestamp,
            event: event.event_type(),
            system: &self.system,
        };

        if let Err(err) = self.record_event(wrapper).await {
            tracing::error ! ( ? event, % timestamp, ? err, "Failed to record event");
        }
    }
}
