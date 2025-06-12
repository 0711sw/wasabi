use crate::aws::dynamodb::DynamoClient;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, BillingMode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigEntity {
    #[serde(rename = "type")]
    pub config_type: String,
    pub id: String,
    pub priority: i32,
    pub required_feature: Option<String>,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SystemConfigEntity {
    #[serde(flatten)]
    pub config: ConfigEntity,
    pub module: String,
    pub txn: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TenantSettingsEntity {
    pub tenant_id: String,
    pub granted_features: Vec<String>,
    pub enabled_features: Vec<String>,
    pub suppressed_elements: Vec<String>,
}

#[async_trait]
pub trait ConfigRepository: Send + Sync {

    async fn fetch_tenant_settings(&self, tenant_id: &str) -> anyhow::Result<TenantSettingsEntity>;

    async fn store_tenant_settings(&self, settings: TenantSettingsEntity) -> anyhow::Result<()>;

    async fn find_all_for_tenant(
        &self,
        type_name: &str,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<ConfigEntity>>;

    async fn find_for_tenant(
        &self,
        type_name: &str,
        tenant_id: &str,
        id: &str,
    ) -> anyhow::Result<Option<ConfigEntity>>;

    async fn find_all_for_system(&self, type_name: &str) -> anyhow::Result<Vec<ConfigEntity>>;

    async fn find_for_system(
        &self,
        type_name: &str,
        id: &str,
    ) -> anyhow::Result<Option<ConfigEntity>>;

    async fn store_system_element(
        &self,
        module: &str,
        txn: &str,
        config_type: String,
        id: String,
        priority: i32,
        required_feature: Option<String>,
        data: String,
    ) -> anyhow::Result<()>;

    async fn remove_outdated_system_elements(&self, module: &str, txn: &str) -> anyhow::Result<()>;
}

pub struct DynamoConfigRepository {
    client: DynamoClient,
}

impl DynamoConfigRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table("config-system-elements", |table| {
                let table = table
                    .attribute_definitions(DynamoClient::str_attribute("type")?)
                    .attribute_definitions(DynamoClient::str_attribute("typeAndId")?)
                    .attribute_definitions(DynamoClient::int_attribute("priority")?)
                    .attribute_definitions(DynamoClient::str_attribute("module")?)
                    .attribute_definitions(DynamoClient::str_attribute("txn")?);

                let table = DynamoClient::with_hash_index(table, "typeAndId")?;

                let table = table
                    .global_secondary_indexes(DynamoClient::replicated_range_index(
                        "TypePriorityIndex",
                        "type",
                        "priority",
                    )?)
                    .global_secondary_indexes(DynamoClient::replicated_range_index(
                        "ModuleTxnIndex",
                        "module",
                        "txn",
                    )?);

                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table("config-tenant-elements", |table| {
                let table = table
                    .attribute_definitions(DynamoClient::str_attribute("tenantAndTypeAndId")?)
                    .attribute_definitions(DynamoClient::str_attribute("tenantAndType")?)
                    .attribute_definitions(DynamoClient::int_attribute("priority")?);

                let table = DynamoClient::with_hash_index(table, "tenantAndTypeAndId")?;

                let table = table.global_secondary_indexes(DynamoClient::replicated_range_index(
                    "TenantAndTypePriorityIndex",
                    "tenantAndType",
                    "priority",
                )?);

                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table("config-tenant-settings", |table| {
                let table = table.attribute_definitions(DynamoClient::str_attribute("tenantId")?);
                let table = DynamoClient::with_hash_index(table, "tenantId")?;

                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl ConfigRepository for DynamoConfigRepository {

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn fetch_tenant_settings(&self, tenant_id: &str) -> anyhow::Result<TenantSettingsEntity> {
        Ok(DynamoClient::extract_entity::<TenantSettingsEntity>(
            self.client
                .query("config-tenant-settings")
                .key_condition_expression("#tenantId = :tenant_id")
                .expression_attribute_names("#tenantId", "tenantId")
                .expression_attribute_values(":tenant_id", AttributeValue::S(tenant_id.to_string()))
                .send()
                .await
                .context("Failed to read config-tenant-settings")?,
        )?
        .unwrap_or_else(|| {
            TenantSettingsEntity {
                tenant_id: tenant_id.to_string(),
                granted_features: Vec::new(),
                enabled_features: Vec::new(),
                suppressed_elements: Vec::new(),
            }
        }))
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn store_tenant_settings(&self, settings: TenantSettingsEntity) -> anyhow::Result<()> {
        self.client
            .put_entity("config-tenant-settings", &settings)?
            .send()
            .await
            .context("Error inserting entity into 'config-tenant-settings' table")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn find_all_for_tenant(
        &self,
        type_name: &str,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<ConfigEntity>> {
        DynamoClient::find_all::<ConfigEntity>(
            self.client
                .query("config-tenant-elements")
                .index_name("TenantAndTypePriorityIndex")
                .limit(32)
                .key_condition_expression("#tenantAndType = :tenantAndType")
                .expression_attribute_names("#tenantAndType", "tenantAndType")
                .expression_attribute_values(
                    ":tenantAndType",
                    AttributeValue::S(Self::compute_tenant_and_type(tenant_id, type_name)),
                ),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn find_for_tenant(
        &self,
        type_name: &str,
        tenant_id: &str,
        id: &str,
    ) -> anyhow::Result<Option<ConfigEntity>> {
        let entity = DynamoClient::extract_entity::<ConfigEntity>(
            self.client
                .query("config-tenant-elements")
                .key_condition_expression("#tenantAndTypeAndId = :tenantAndTypeAndId")
                .expression_attribute_names("#tenantAndTypeAndId", "tenantAndTypeAndId")
                .expression_attribute_values(
                    ":tenantAndTypeAndId",
                    AttributeValue::S(Self::compute_teant_and_type_and_id(
                        tenant_id, type_name, id,
                    )),
                )
                .send()
                .await
                .context("Failed to search in config-system-elements")?,
        )?;

        Ok(entity)
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn find_all_for_system(&self, type_name: &str) -> anyhow::Result<Vec<ConfigEntity>> {
        DynamoClient::find_all::<ConfigEntity>(
            self.client
                .query("config-system-elements")
                .index_name("TypePriorityIndex")
                .limit(32)
                .key_condition_expression("#type = :type")
                .expression_attribute_names("#type", "type")
                .expression_attribute_values(":type", AttributeValue::S(type_name.to_string())),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn find_for_system(
        &self,
        type_name: &str,
        id: &str,
    ) -> anyhow::Result<Option<ConfigEntity>> {
        let entity = DynamoClient::extract_entity::<ConfigEntity>(
            self.client
                .query("config-system-elements")
                .key_condition_expression("#typeAndId = :typeAndId")
                .expression_attribute_names("#typeAndId", "typeAndId")
                .expression_attribute_values(
                    ":typeAndId",
                    AttributeValue::S(Self::compute_type_and_id(type_name, id)),
                )
                .send()
                .await
                .context("Failed to search in config-system-elements")?,
        )?;

        Ok(entity)
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn store_system_element(
        &self,
        module: &str,
        txn: &str,
        config_type: String,
        id: String,
        priority: i32,
        required_feature: Option<String>,
        data: String,
    ) -> anyhow::Result<()> {
        let entity = SystemConfigEntity {
            config: ConfigEntity {
                config_type,
                id,
                priority,
                required_feature,
                data,
            },
            module: module.to_string(),
            txn: txn.to_string(),
        };

        let mut item = serde_dynamo::aws_sdk_dynamodb_1::to_item(&entity)
            .context("Error serializing entity into DynamoDB item")?;
        item.insert(
            "typeAndId".to_string(),
            AttributeValue::S(Self::compute_type_and_id(
                &entity.config.config_type,
                &entity.config.id,
            )),
        );

        self.client
            .put_item("config-system-elements")
            .set_item(Some(item))
            .send()
            .await
            .context("Error inserting entity into 'config-system-elements' table")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn remove_outdated_system_elements(&self, module: &str, txn: &str) -> anyhow::Result<()> {
        // DynamoDN does not support txn <> txn - therefore, we need to first delete everything that
        // is less than our txn to retain...
        let items = DynamoClient::find_all::<ConfigEntity>(
            self.client
                .query("config-system-elements")
                .index_name("ModuleTxnIndex")
                .limit(32)
                .key_condition_expression("#module = :module AND #txn < :txn")
                .expression_attribute_names("#module", "module")
                .expression_attribute_names("#txn", "txn")
                .expression_attribute_values(":module", AttributeValue::S(module.to_string()))
                .expression_attribute_values(":txn", AttributeValue::S(txn.to_string())),
        )
        .await?;

        for item in items {
            self.delete_system_element(&item.config_type, &item.id)
                .await?;
        }

        // ...and then delete everything that is greater than our txn to retain.
        let items = DynamoClient::find_all::<ConfigEntity>(
            self.client
                .query("config-system-elements")
                .index_name("ModuleTxnIndex")
                .limit(32)
                .key_condition_expression("#module = :module AND #txn > :txn")
                .expression_attribute_names("#module", "module")
                .expression_attribute_names("#txn", "txn")
                .expression_attribute_values(":module", AttributeValue::S(module.to_string()))
                .expression_attribute_values(":txn", AttributeValue::S(txn.to_string())),
        )
        .await?;

        for item in items {
            self.delete_system_element(&item.config_type, &item.id)
                .await?;
        }

        Ok(())
    }
}

impl DynamoConfigRepository {
    fn compute_tenant_and_type(tenant_id: &str, type_name: &str) -> String {
        format!("{}#{}", tenant_id, type_name)
    }
    fn compute_type_and_id(type_name: &str, id: &str) -> String {
        format!("{}#{}", type_name, id)
    }
    fn compute_teant_and_type_and_id(tenant_id: &str, type_name: &str, id: &str) -> String {
        format!("{}#{}#{}", tenant_id, type_name, id)
    }

    async fn delete_system_element(&self, type_name: &str, id: &str) -> anyhow::Result<()> {
        self.client
            .delete_item("config-system-elements")
            .key(
                "typeAndId",
                AttributeValue::S(Self::compute_type_and_id(type_name, id)),
            )
            .send()
            .await
            .context("Error deleting entity from 'config-system-elements' table")?;

        Ok(())
    }
}
