use anyhow::Context;
use aws_sdk_dynamodb::operation::query::QueryOutput;
use aws_sdk_dynamodb::operation::query::builders::QueryFluentBuilder;
use aws_sdk_dynamodb::types::AttributeValue;
use futures_util::{Stream, StreamExt, TryStreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::pin::Pin;

pub mod client;
pub mod schema;

pub fn extract_entity<T: Serialize + DeserializeOwned>(
    output: QueryOutput,
) -> anyhow::Result<Option<T>> {
    if let Some(result) = output.items.and_then(|items| items.into_iter().next()) {
        serde_dynamo::aws_sdk_dynamodb_1::from_item(result)
            .context("Failed to deserialize DynamoDB item")
            .map(Some)
    } else {
        Ok(None)
    }
}

pub async fn find_first<E: Serialize + DeserializeOwned>(
    query_fluent_builder: QueryFluentBuilder,
) -> anyhow::Result<Option<E>> {
    let block_size = query_fluent_builder
        .get_limit()
        .context("Invalid query: No limit is given")?;

    let mut last_key = None;

    loop {
        let mut query = query_fluent_builder.clone();
        query = query.set_exclusive_start_key(last_key);
        let result = query
            .send()
            .await
            .context("Error searching table 'blocks'")?;

        if result.count() > 0 {
            return extract_entity(result).context("Failed to deserialize an entity");
        } else if result.scanned_count() < block_size || result.last_evaluated_key().is_none() {
            return Ok(None);
        } else {
            last_key = result.last_evaluated_key;
        }
    }
}

pub fn stream_all<E>(
    query_fluent_builder: QueryFluentBuilder,
) -> anyhow::Result<Pin<Box<dyn Stream<Item = anyhow::Result<E>> + Send>>>
where
    E: Serialize + DeserializeOwned + Send + 'static,
{
    enum PaginationState {
        Start,
        LastKey(HashMap<String, AttributeValue>),
        End,
    }

    let _ = query_fluent_builder
        .get_limit()
        .context("Invalid query: No limit is given")?;

    let stream = futures_util::stream::try_unfold(
        (query_fluent_builder, PaginationState::Start),
        |(query_fluent_builder, state)| async move {
            let mut query = query_fluent_builder.clone();
            match state {
                PaginationState::Start => {}
                PaginationState::LastKey(last_key) => {
                    query = query.set_exclusive_start_key(Some(last_key));
                }
                PaginationState::End => return Ok::<_, anyhow::Error>(None),
            }

            let result = query
                .send()
                .await
                .context("Error executing paginated query")?;

            let entities = result
                .items
                .unwrap_or_default()
                .into_iter()
                .map(serde_dynamo::aws_sdk_dynamodb_1::from_item)
                .collect::<Result<Vec<E>, _>>()
                .context("Failed to deserialize items")?;

            if entities.is_empty() {
                Ok(None)
            } else {
                let next_state = if let Some(next_key) = result.last_evaluated_key {
                    PaginationState::LastKey(next_key)
                } else {
                    PaginationState::End
                };

                Ok(Some((entities, (query_fluent_builder, next_state))))
            }
        },
    );

    let stream = stream
        .map_ok(|items| futures_util::stream::iter(items.into_iter().map(Ok)))
        .try_flatten()
        .boxed();

    Ok(stream)
}

pub async fn find_all<E>(query_fluent_builder: QueryFluentBuilder) -> anyhow::Result<Vec<E>>
where
    E: Serialize + DeserializeOwned + Send + 'static,
{
    stream_all(query_fluent_builder)?.try_collect().await
}

pub fn generate_id() -> String {
    crate::tools::id_generator::generate_id(32)
}

pub fn str(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}
