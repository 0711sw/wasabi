use crate::aws::dynamodb::DynamoClient;
use crate::config::repository::{
    ConfigEntity, ConfigRepository, SystemConfigEntity, TenantSettingsEntity,
};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, BillingMode};

pub struct DynamoConfigRepository {
    client: DynamoClient,
}

const TABLE_CONFIG_SYSTEM_ELEMENTS: &str = "config-system-elements";
const FIELD_TYPE: &'static str = "type";
const FIELD_TYPE_AND_ID: &'static str = "typeAndId";
const FIELD_PRIORITY: &'static str = "priority";
const FIELD_MODULE: &'static str = "module";
const FIELD_TXN: &'static str = "txn";
const INDEX_TYPE_BY_PRIORITY: &'static str = "TypePriorityIndex";
const INDEX_MODULE_BY_TXN: &'static str = "ModuleTxnIndex";

const TABLE_CONFIG_TENANT_ELEMENTS: &'static str = "config-tenant-elements";
const FIELD_TENANT_AND_TYPE_AND_ID: &'static str = "tenantAndTypeAndId";
const FIELD_TENANT_AND_TYPE: &'static str = "tenantAndType";

const TABLE_CONFIG_TENANT_SETTINGS: &'static str = "config-tenant-settings";
const FIELD_TENANT_ID: &'static str = "tenantId";
const INDEX_TENANT_AND_TYPE_BY_PRIORITY: &'static str = "TenantAndTypePriorityIndex";

impl DynamoConfigRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_CONFIG_SYSTEM_ELEMENTS, |table| {
                let table = table
                    .attribute_definitions(DynamoClient::str_attribute(FIELD_TYPE)?)
                    .attribute_definitions(DynamoClient::str_attribute(FIELD_TYPE_AND_ID)?)
                    .attribute_definitions(DynamoClient::int_attribute(FIELD_PRIORITY)?)
                    .attribute_definitions(DynamoClient::str_attribute(FIELD_MODULE)?)
                    .attribute_definitions(DynamoClient::str_attribute(FIELD_TXN)?);

                let table = DynamoClient::with_hash_index(table, FIELD_TYPE_AND_ID)?;

                let table = table
                    .global_secondary_indexes(DynamoClient::replicated_range_index(
                        INDEX_TYPE_BY_PRIORITY,
                        FIELD_TYPE,
                        FIELD_PRIORITY,
                    )?)
                    .global_secondary_indexes(DynamoClient::replicated_range_index(
                        INDEX_MODULE_BY_TXN,
                        FIELD_MODULE,
                        FIELD_TXN,
                    )?);

                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table(TABLE_CONFIG_TENANT_ELEMENTS, |table| {
                let table = table
                    .attribute_definitions(DynamoClient::str_attribute(
                        FIELD_TENANT_AND_TYPE_AND_ID,
                    )?)
                    .attribute_definitions(DynamoClient::str_attribute(FIELD_TENANT_AND_TYPE)?)
                    .attribute_definitions(DynamoClient::int_attribute(FIELD_PRIORITY)?);

                let table = DynamoClient::with_hash_index(table, FIELD_TENANT_AND_TYPE_AND_ID)?;

                let table = table.global_secondary_indexes(DynamoClient::replicated_range_index(
                    INDEX_TENANT_AND_TYPE_BY_PRIORITY,
                    FIELD_TENANT_AND_TYPE,
                    FIELD_PRIORITY,
                )?);

                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table(TABLE_CONFIG_TENANT_SETTINGS, |table| {
                let table =
                    table.attribute_definitions(DynamoClient::str_attribute(FIELD_TENANT_ID)?);
                let table = DynamoClient::with_hash_index(table, FIELD_TENANT_ID)?;

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
                .query(TABLE_CONFIG_TENANT_SETTINGS)
                .key_condition_expression("#tenantId = :tenant_id")
                .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
                .expression_attribute_values(":tenant_id", AttributeValue::S(tenant_id.to_string()))
                .send()
                .await
                .context("Failed to read config-tenant-settings")?,
        )?
        .unwrap_or_else(|| TenantSettingsEntity {
            tenant_id: tenant_id.to_string(),
            granted_features: Vec::new(),
            enabled_features: Vec::new(),
            suppressed_elements: Vec::new(),
        }))
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn store_tenant_settings(&self, settings: TenantSettingsEntity) -> anyhow::Result<()> {
        self.client
            .put_entity(TABLE_CONFIG_TENANT_SETTINGS, &settings)?
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
                    AttributeValue::S(Self::compute_tenant_and_type_and_id(
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
                module: Some(module.to_string()),
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
        // DynamoDB does not support txn <> txn - therefore, we need to first delete everything that
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

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn store_tenant_element(
        &self,
        tenant_id: String,
        config_type: String,
        id: String,
        priority: i32,
        data: String,
    ) -> anyhow::Result<()> {
        let entity = ConfigEntity {
            config_type,
            id,
            priority,
            required_feature: None,
            module: None,
            data,
        };

        let mut item = serde_dynamo::aws_sdk_dynamodb_1::to_item(&entity)
            .context("Error serializing entity into DynamoDB item")?;
        item.insert(
            "tenantAndTypeAndId".to_string(),
            AttributeValue::S(Self::compute_tenant_and_type_and_id(
                &tenant_id,
                &entity.config_type,
                &entity.id,
            )),
        );
        item.insert(
            "tenantAndType".to_string(),
            AttributeValue::S(Self::compute_tenant_and_type(
                &tenant_id,
                &entity.config_type,
            )),
        );

        self.client
            .put_item("config-tenant-elements")
            .set_item(Some(item))
            .send()
            .await
            .context("Error inserting entity into 'config-system-elements' table")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    async fn delete_tenant_element(
        &self,
        tenant_id: &str,
        type_name: &str,
        id: &str,
    ) -> anyhow::Result<()> {
        self.client
            .delete_item("config-tenant-elements")
            .key(
                "tenantAndTypeAndId",
                AttributeValue::S(Self::compute_tenant_and_type_and_id(
                    tenant_id, type_name, id,
                )),
            )
            .send()
            .await
            .context("Error deleting entity from 'config-tenant#-elements' table")?;

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
    fn compute_tenant_and_type_and_id(tenant_id: &str, type_name: &str, id: &str) -> String {
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
