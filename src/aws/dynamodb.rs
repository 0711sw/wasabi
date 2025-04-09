use anyhow::Context;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::operation::create_table::builders::CreateTableFluentBuilder;
use aws_sdk_dynamodb::types::TableStatus;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct DynamoClient {
    client: Client,
    table_prefix: Option<String>,
}

impl DynamoClient {
    pub async fn from_env() -> anyhow::Result<DynamoClient> {
        tracing::info!("Setting up DynamoDB....");
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        Ok(DynamoClient {
            client,
            table_prefix: env::var("DYNAMO_TABLE_PREFIX").ok(),
        })
    }

    pub fn effective_name(&self, table: &str) -> String {
        match &self.table_prefix {
            Some(prefix) => format!("{}.{}", prefix, table),
            None => table.to_owned(),
        }
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
        F: FnOnce(CreateTableFluentBuilder) -> CreateTableFluentBuilder,
    {
        let effective_name = self.effective_name(name);

        if self.does_table_exist(name).await? {
            tracing::info!("Table '{}' already exists.", effective_name);
            Ok(())
        } else {
            tracing::info!("Table '{}' does not exist. Creating...", effective_name);
            callback(self.client.create_table().table_name(&effective_name))
                .send()
                .await
                .with_context(|| {
                    format!("Failed to create DynamoDB table '{}'", &effective_name)
                })?;

            tracing::info!(
                "Create Table '{}' was submitted to DynamoDB",
                effective_name
            );
            self.wait_until_table_active(&effective_name).await?;
            tracing::info!("Table '{}' was successfully created", effective_name);

            Ok(())
        }
    }
    async fn wait_until_table_active(&self, table_name: &str) -> anyhow::Result<()> {
        let effective_name = self.effective_name(table_name);
        for _ in 0..5 {
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

            sleep(Duration::from_secs(2)).await;
        }

        anyhow::bail!("Table '{}' did not become ACTIVE in time", effective_name);
    }
}

#[cfg(test)]
mod tests {
    use crate::aws::dynamodb::DynamoClient;
    use crate::aws::test::test_run_id;
    use crate::aws_rdy;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
    };
    use std::env;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn does_table_exists_detects_nonexistent_table() {
        aws_rdy!();

        unsafe {
            env::set_var("DYNAMO_TABLE_PREFIX", "wasabi-test");
        }

        let dbd_client = DynamoClient::from_env().await.unwrap();
        let table_name = "non-existent-table";

        assert!(!dbd_client.does_table_exist(table_name).await.unwrap());
    }

    #[tokio::test]
    async fn create_table_actually_creates_a_table() {
        aws_rdy!();

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
                builder
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
                    .billing_mode(BillingMode::PayPerRequest)
            })
            .await
            .unwrap();

        // Ensure the table is created...
        assert!(dbd_client.does_table_exist(&table_name).await.unwrap());

        // Ensure that the table is not created twice...
        dbd_client
            .create_table(&table_name, |builder| {
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
