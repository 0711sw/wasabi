#[cfg(feature = "aws_dynamodb")]
pub mod dynamo;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEntity {
    #[serde(rename = "type")]
    pub config_type: String,
    pub id: String,
    pub priority: i32,
    pub required_feature: Option<String>,
    pub module: Option<String>,
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
pub struct TenantSettingsEntity {
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

    async fn store_tenant_element(
        &self,
        tenant_id: String,
        type_name: String,
        id: String,
        priority: i32,
        data: String,
    ) -> anyhow::Result<()>;

    async fn delete_tenant_element(
        &self,
        tenant_id: &str,
        type_name: &str,
        id: &str,
    ) -> anyhow::Result<()>;
}
