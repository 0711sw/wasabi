use async_trait::async_trait;
use std::collections::HashSet;

pub struct ConfigEntity {
    pub config_type: String,
    pub id: String,
    pub priority: i32,
    pub required_feature: Option<String>,
    pub data: String,
}

#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn fetch_granted_features(&self, tenant_id: &str) -> anyhow::Result<HashSet<String>>;

    async fn store_granted_features(
        &self,
        tenant_id: &str,
        features: Vec<String>,
    ) -> anyhow::Result<()>;

    async fn fetch_enabled_features(&self, tenant_id: &str) -> anyhow::Result<HashSet<String>>;
    async fn store_enabled_features(
        &self,
        tenant_id: &str,
        features: Vec<String>,
    ) -> anyhow::Result<()>;

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
