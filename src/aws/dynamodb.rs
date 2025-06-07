use anyhow::Context;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::BuildError;
use aws_sdk_dynamodb::operation::create_table::builders::CreateTableFluentBuilder;
use aws_sdk_dynamodb::operation::delete_item::builders::DeleteItemFluentBuilder;
use aws_sdk_dynamodb::operation::get_item::builders::GetItemFluentBuilder;
use aws_sdk_dynamodb::operation::put_item::builders::PutItemFluentBuilder;
use aws_sdk_dynamodb::operation::query::QueryOutput;
use aws_sdk_dynamodb::operation::query::builders::QueryFluentBuilder;
use aws_sdk_dynamodb::operation::update_item::builders::UpdateItemFluentBuilder;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, GlobalSecondaryIndex, KeySchemaElement, KeyType,
    Projection, ProjectionType, ScalarAttributeType, TableStatus,
};
use futures_util::{Stream, StreamExt, TryStreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::env;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct DynamoClient {
    pub client: Client,
    table_prefix: String,
}

impl DynamoClient {
    pub async fn from_env() -> anyhow::Result<DynamoClient> {
        tracing::info!("Setting up DynamoDB....");
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        let table_prefix = env::var("DYNAMO_TABLE_PREFIX")
            .context("No DYNAMO_TABLE_PREFIX provided in environment")?;

        Ok(DynamoClient {
            client,
            table_prefix,
        })
    }

    pub fn effective_name(&self, table: &str) -> String {
        format!("{}-{}", self.table_prefix, table)
    }

    pub async fn does_table_exist(&self, name: &str) -> anyhow::Result<bool> {
        let effective_name = self.effective_name(name);

        match self
            .client
            .describe_table()
            .table_name(&effective_name)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err)
            if err
                .as_service_error()
                .map(|e| e.is_resource_not_found_exception())
                .unwrap_or(false) =>
                {
                    Ok(false)
                }
            Err(e) => Err(e).context(format!("Cannot access DynamoDB table '{}'", effective_name)),
        }
    }

    pub async fn create_table<F>(&self, name: &str, callback: F) -> anyhow::Result<()>
    where
        F: FnOnce(CreateTableFluentBuilder) -> Result<CreateTableFluentBuilder, BuildError>,
    {
        let effective_name = self.effective_name(name);

        if self.does_table_exist(name).await? {
            tracing::info!("Table '{}' already exists.", effective_name);
            Ok(())
        } else {
            tracing::info!("Table '{}' does not exist. Creating...", effective_name);
            callback(self.client.create_table().table_name(&effective_name))
                .with_context(|| {
                    format!(
                        "Faild to build proper create table request for: {}",
                        &effective_name
                    )
                })?
                .send()
                .await
                .with_context(|| {
                    format!("Failed to create DynamoDB table '{}'", &effective_name)
                })?;

            tracing::info!(
                "Create Table '{}' was submitted to DynamoDB",
                effective_name
            );
            self.wait_until_table_becomes_active(&effective_name)
                .await?;
            tracing::info!("Table '{}' was successfully created", effective_name);

            Ok(())
        }
    }

    pub fn str_attribute(name: &str) -> Result<AttributeDefinition, BuildError> {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(ScalarAttributeType::S)
            .build()
    }

    pub fn with_hash_index(
        builder: CreateTableFluentBuilder,
        hash_attribute: &str,
    ) -> Result<CreateTableFluentBuilder, BuildError> {
        Ok(builder.key_schema(
            KeySchemaElement::builder()
                .attribute_name(hash_attribute)
                .key_type(KeyType::Hash)
                .build()?,
        ))
    }

    pub fn with_range_index(
        builder: CreateTableFluentBuilder,
        hash_attribute: &str,
        range_attribute: &str,
    ) -> Result<CreateTableFluentBuilder, BuildError> {
        Ok(builder
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(hash_attribute)
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(range_attribute)
                    .key_type(KeyType::Range)
                    .build()?,
            ))
    }

    pub fn replicated_range_index(
        index_name: &str,
        hash_attribute: &str,
        range_attribute: &str,
    ) -> Result<GlobalSecondaryIndex, BuildError> {
        GlobalSecondaryIndex::builder()
            .index_name(index_name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(hash_attribute)
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(range_attribute)
                    .key_type(KeyType::Range)
                    .build()?,
            )
            .projection(
                Projection::builder()
                    .projection_type(ProjectionType::All)
                    .build(),
            )
            .build()
    }

    async fn wait_until_table_becomes_active(&self, table_name: &str) -> anyhow::Result<()> {
        let effective_name = self.effective_name(table_name);
        for _ in 0..15 {
            let resp = self
                .client
                .describe_table()
                .table_name(table_name)
                .send()
                .await
                .with_context(|| {
                    format!("Failed to check table status of '{}'", &effective_name)
                })?;

            let status = resp
                .table()
                .and_then(|t| t.table_status())
                .unwrap_or(&TableStatus::Creating);

            if status == &TableStatus::Active {
                return Ok(());
            }

            sleep(Duration::from_secs(10)).await;
        }

        anyhow::bail!("Table '{}' did not become ACTIVE in time", effective_name);
    }

    pub fn put_item(&self, table_name: &str) -> PutItemFluentBuilder {
        self.client
            .put_item()
            .table_name(self.effective_name(table_name))
    }

    pub fn get_item(&self, table_name: &str) -> GetItemFluentBuilder {
        self.client
            .get_item()
            .table_name(self.effective_name(table_name))
    }

    pub fn query(&self, table_name: &str) -> QueryFluentBuilder {
        self.client
            .query()
            .table_name(self.effective_name(table_name))
    }

    pub fn update_item(&self, table_name: &str) -> UpdateItemFluentBuilder {
        self.client
            .update_item()
            .table_name(self.effective_name(table_name))
    }

    pub fn delete_item(&self, table_name: &str) -> DeleteItemFluentBuilder {
        self.client
            .delete_item()
            .table_name(self.effective_name(table_name))
    }

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
                return Self::extract_entity(result).context("Failed to deserialize an entity");
            } else if result.scanned_count() < block_size || result.last_evaluated_key().is_none() {
                return Ok(None);
            } else {
                last_key = result.last_evaluated_key;
            }
        }
    }

    pub fn stream_all<E>(
        query_fluent_builder: QueryFluentBuilder,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item=anyhow::Result<E>> + Send>>>
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
                    .map(serde_dynamo::from_item)
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
        Self::stream_all(query_fluent_builder)?.try_collect().await
    }
}

#[cfg(test)]
mod tests {
    use crate::aws::dynamodb::DynamoClient;
    use crate::aws::test::test_run_id;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
    };
    use std::env;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    #[ignore]
    async fn does_table_exists_detects_nonexistent_table() {
        unsafe {
            env::set_var("DYNAMO_TABLE_PREFIX", "wasabi-test");
        }

        let dbd_client = DynamoClient::from_env().await.unwrap();
        let table_name = "non-existent-table";

        assert!(!dbd_client.does_table_exist(table_name).await.unwrap());
    }

    #[tokio::test]
    #[ignore]
    async fn create_table_actually_creates_a_table() {
        unsafe {
            env::set_var("DYNAMO_TABLE_PREFIX", "wasabi-test");
        }

        let dbd_client = DynamoClient::from_env().await.unwrap();
        let table_name = format!("test-table-{}", test_run_id());

        // Ensure the table does not exist before creating it...
        if dbd_client.does_table_exist(&table_name).await.unwrap() {
            dbd_client
                .client
                .delete_table()
                .table_name(dbd_client.effective_name(&table_name))
                .send()
                .await
                .unwrap();

            // Wait for the table to be deleted...
            for _ in 1..5 {
                if dbd_client.does_table_exist(&table_name).await.unwrap() {
                    tracing::info!("Waiting for table '{}' to be deleted...", table_name);
                    sleep(Duration::from_secs(2)).await;
                } else {
                    break;
                }
            }
        }

        // Check again to ensure the table is deleted...
        assert!(!dbd_client.does_table_exist(&table_name).await.unwrap());

        // Create the table...
        dbd_client
            .create_table(&table_name, |builder| {
                Ok(builder
                    .attribute_definitions(
                        AttributeDefinition::builder()
                            .attribute_name("PK")
                            .attribute_type(ScalarAttributeType::S)
                            .build()
                            .unwrap(),
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name("PK")
                            .key_type(KeyType::Hash)
                            .build()
                            .unwrap(),
                    )
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await
            .unwrap();

        // Ensure the table is created...
        assert!(dbd_client.does_table_exist(&table_name).await.unwrap());

        // Ensure that the table is not created twice...
        dbd_client
            .create_table(&table_name, |_| {
                panic!("This should not be called again");
            })
            .await
            .unwrap();

        // Be a good citizen and delete the table...
        dbd_client
            .client
            .delete_table()
            .table_name(dbd_client.effective_name(&table_name))
            .send()
            .await
            .unwrap();
    }
}
