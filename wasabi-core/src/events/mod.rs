#[cfg(feature = "aws_firehose")]
pub mod firehose;

use async_trait::async_trait;
use serde::Serialize;
use std::fmt::Debug;

pub trait Event: Serialize + Debug + Send + Sync {
    fn event_type(&self) -> &'static str;
}

#[async_trait]
pub trait EventRecorder: Send + Sync {
    async fn record<E: Event>(&self, event: E);
    async fn record_at<E: Event>(&self, event: E, timestamp: chrono::DateTime<chrono::Utc>);
}

pub struct NoopEventRecorder;

#[async_trait]
impl EventRecorder for NoopEventRecorder {
    async fn record<E: Event>(&self, event: E) {
        self.record_at(event, chrono::Utc::now()).await;
    }
    async fn record_at<E: Event>(&self, event: E, timestamp: chrono::DateTime<chrono::Utc>) {
        match serde_json::to_string(&event) {
            Ok(json) => {
                tracing::debug!(
                    "Received an event of type {} at {}: {}",
                    event.event_type(),
                    timestamp,
                    json
                );
            }
            Err(err) => {
                tracing::error!(
                    "Failed to serialize event of type {} at {}: {:#}",
                    event.event_type(),
                    timestamp,
                    err
                );
            }
        }
    }
}
