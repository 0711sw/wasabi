use anyhow::Context;
use opensearch::OpenSearch;
use opensearch::auth::Credentials;
use opensearch::http::transport::{SingleNodeConnectionPool, TransportBuilder};
use serde::Serialize;
use std::collections::HashMap;
use std::env;

#[derive(Serialize)]
pub struct IndexDescription {
    pub settings: IndexSettings,
    pub mappings: Mapping,
}

#[derive(Serialize)]
pub struct IndexSettings {
    pub number_of_shards: u32,
    pub number_of_replicas: u32,
}

#[derive(Serialize)]
pub struct Mapping {
    pub properties: HashMap<String, FieldMapping>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum FieldMapping {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "keyword")]
    Keyword,
    #[serde(rename = "integer")]
    Integer,
    #[serde(rename = "float")]
    Float,
    #[serde(rename = "date")]
    Date,
    #[serde(rename = "boolean")]
    Boolean,
    #[serde(rename = "object")]
    Object {
        properties: HashMap<String, FieldMapping>,
    },
    #[serde(rename = "nested")]
    Nested {
        properties: HashMap<String, FieldMapping>,
    },
}

pub struct OpenSearchClient {
    pub client: OpenSearch,
}

impl OpenSearchClient {
    pub fn from_env() -> anyhow::Result<Self> {
        let url = env::var("OPENSEARCH_URL").context("Missing OPENSEARCH_URL")?;
        let user = std::env::var("OPENSEARCH_USER").unwrap_or_default();
        let pass = std::env::var("OPENSEARCH_PASS").unwrap_or_default();

        let conn_pool =
            SingleNodeConnectionPool::new(url.parse().context("Invalid OpenSearch URL")?);

        let mut builder = TransportBuilder::new(conn_pool);

        if user.len() > 0 {
            builder = builder.auth(Credentials::Basic(user, pass));
        }

        let transport = builder.build()?;
        Ok(Self {
            client: OpenSearch::new(transport),
        })
    }

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
