use crate::events::{Event, EventRecorder};
use crate::{APP_NAME, CLUSTER_ID};
use async_trait::async_trait;
use aws_sdk_firehose::Client;
use aws_sdk_firehose::types::Record;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;
use std::env;
use std::sync::LazyLock;

#[derive(Serialize)]
struct EventWrapper<'a, T: Event + Serialize> {
    #[serde(flatten)]
    pub payload: &'a T,

    pub timestamp: DateTime<Utc>,
    pub event: &'static str,
    pub system: &'a str,
}

pub struct FirehoseEventRecorder {
    client: Client,
    stream: String,
    system: String,
}


impl FirehoseEventRecorder {}

const NON_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z]+").unwrap());
impl FirehoseEventRecorder {

    #[tracing::instrument(err(Display))]
    pub async fn from_env() -> anyhow::Result<Self> {
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        let stream = env::var("FIREHOSE_STREAM_NAME").unwrap_or_else(|_| {
            NON_CHARS
                .replace_all(&APP_NAME.to_lowercase(), "_")
                .into_owned()
        });
        let system = env::var("FIREHOSE_SYSTEM_NAME").unwrap_or_else(|_| {
            NON_CHARS
                .replace_all(&CLUSTER_ID.to_lowercase(), "_")
                .into_owned()
        });

        Ok(Self {
            client,
            stream,
            system,
        })
    }

    async fn record_event<'a, E: Event>(&self, event: EventWrapper<'a, E>) -> anyhow::Result<()> {
        let json = serde_json::to_string(&event)?;

        let record = Record::builder().data(json.into_bytes().into()).build()?;

        let _ = self
            .client
            .put_record()
            .delivery_stream_name(&self.stream)
            .record(record)
            .send()
            .await?;

        Ok(())
    }
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
            tracing::error!(?event, %timestamp, ?err, "Failed to record event");
        }
    }
}
