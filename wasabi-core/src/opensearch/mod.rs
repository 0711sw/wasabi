//! OpenSearch/Elasticsearch client for index management.
//!
//! # Environment Variables
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `OPENSEARCH_URL` | OpenSearch cluster URL (required) |
//! | `OPENSEARCH_USER` | Username for basic auth (optional) |
//! | `OPENSEARCH_PASS` | Password for basic auth (optional) |

use anyhow::Context;
use opensearch::OpenSearch;
use opensearch::auth::Credentials;
use opensearch::http::transport::{SingleNodeConnectionPool, TransportBuilder};
use serde::Serialize;
use std::collections::HashMap;
use std::env;

/// Index creation settings and mappings.
#[derive(Serialize)]
pub struct IndexDescription {
    /// Index settings (shards, replicas).
    pub settings: IndexSettings,
    /// Field mappings for the index.
    pub mappings: Mapping,
}

/// Index configuration settings.
#[derive(Serialize)]
pub struct IndexSettings {
    /// Number of primary shards.
    pub number_of_shards: u32,
    /// Number of replica shards.
    pub number_of_replicas: u32,
}

/// Index field mappings container.
#[derive(Serialize)]
pub struct Mapping {
    /// Field name to mapping definition.
    pub properties: HashMap<String, FieldMapping>,
}

/// OpenSearch field type definitions.
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum FieldMapping {
    /// Full-text searchable field.
    #[serde(rename = "text")]
    Text,
    /// Exact-match field for filtering and aggregations.
    #[serde(rename = "keyword")]
    Keyword,
    /// 32-bit integer.
    #[serde(rename = "integer")]
    Integer,
    /// Single-precision floating point.
    #[serde(rename = "float")]
    Float,
    /// Date/time field.
    #[serde(rename = "date")]
    Date,
    /// Boolean field.
    #[serde(rename = "boolean")]
    Boolean,
    /// Nested object (fields accessible but not independently searchable).
    #[serde(rename = "object")]
    Object {
        /// Nested field mappings.
        properties: HashMap<String, FieldMapping>,
    },
    /// Nested document (independently searchable).
    #[serde(rename = "nested")]
    Nested {
        /// Nested field mappings.
        properties: HashMap<String, FieldMapping>,
    },
}

/// OpenSearch client wrapper.
pub struct OpenSearchClient {
    /// The underlying OpenSearch client.
    pub client: OpenSearch,
}

impl OpenSearchClient {
    /// Creates a client from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        let url = env::var("OPENSEARCH_URL").context("Missing OPENSEARCH_URL")?;
        let user = std::env::var("OPENSEARCH_USER").unwrap_or_default();
        let pass = std::env::var("OPENSEARCH_PASS").unwrap_or_default();

        let conn_pool =
            SingleNodeConnectionPool::new(url.parse().context("Invalid OpenSearch URL")?);

        let mut builder = TransportBuilder::new(conn_pool);

        if !user.is_empty() {
            builder = builder.auth(Credentials::Basic(user, pass));
        }

        let transport = builder.build()?;
        Ok(Self {
            client: OpenSearch::new(transport),
        })
    }

    /// Creates an index if it doesn't exist, using the provided mapping function.
    pub async fn ensure_index_exists<F>(
        &self,
        index_name: &str,
        mapping_fn: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> IndexDescription,
    {
        let exists_response = self
            .client
            .indices()
            .exists(opensearch::indices::IndicesExistsParts::Index(&[
                index_name,
            ]))
            .send()
            .await?;

        if exists_response.status_code().is_success() {
            return Ok(());
        }

        let description = mapping_fn();

        let response = self
            .client
            .indices()
            .create(opensearch::indices::IndicesCreateParts::Index(index_name))
            .body(description)
            .send()
            .await?;

        if !response.status_code().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to create index {}: {}",
                index_name,
                response.status_code()
            ));
        }

        Ok(())
    }
}
