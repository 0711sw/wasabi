use crate::config::descriptor::{ConfigDescriptor, ConfigHandler, Registry};
use crate::config::repository::{ConfigEntity, ConfigRepository};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;

/**
Rules for docs
Rules for assets
Singleton for dpp tenant data

Fields for docs

**/
#[derive(Clone)]
pub struct ConfigClient {
    pub(crate) registry: Arc<Registry>,
    pub(crate) repository: Arc<dyn ConfigRepository>,
}

impl ConfigClient {
    pub async fn find_all<D: ConfigDescriptor>(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<D::Item>> {
        let type_name = D::type_name();
        let enabled_features = self.repository.fetch_enabled_features(tenant_id).await?;
        let granted_features = self.repository.fetch_granted_features(tenant_id).await?;

        let mut entities: Vec<ConfigEntity> = self
            .repository
            .find_all_for_system(&type_name)
            .await?
            .into_iter()
            .filter(|entity| Self::check_access(entity, &enabled_features, &granted_features))
            .collect();
        entities.append(
            &mut self
                .repository
                .find_all_for_tenant(&type_name, tenant_id)
                .await?,
        );
        entities.sort_by(|a, b| a.priority.cmp(&b.priority));

        let handler = self.registry.find_handler(&type_name)?;
        let result: Vec<D::Item> = entities
            .into_iter()
            .map(|entity| Self::parse::<D::Item>(&entity.data, &handler))
            .flatten()
            .collect();

        Ok(result)
    }

    fn check_access(
        entity: &ConfigEntity,
        enabled_features: &HashSet<String>,
        granted_features: &HashSet<String>,
    ) -> bool {
        if let Some(required_feature) = &entity.required_feature {
            enabled_features.contains(required_feature)
                && granted_features.contains(required_feature)
        } else {
            true
        }
    }

    fn parse<T: 'static>(data: &str, handler: &ConfigHandler) -> Option<T> {
        serde_json::from_str::<Value>(data)
            .ok()
            .and_then(|value| (handler.parse)(value).ok())
            .and_then(|element| element.downcast::<T>().ok())
            .map(|element| *element)
    }

    pub async fn find_by_id<D: ConfigDescriptor>(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> anyhow::Result<Option<D::Item>> {
        let handler = self.registry.find_handler(D::type_name())?;

        if let Some(entity) = self
            .repository
            .find_for_tenant(D::type_name(), tenant_id, id)
            .await?
            .and_then(|entity| Self::parse::<D::Item>(&entity.data, &handler))
        {
            Ok(Some(entity))
        } else {
            let enabled_features = self.repository.fetch_enabled_features(tenant_id).await?;
            let granted_features = self.repository.fetch_granted_features(tenant_id).await?;

            Ok(self
                .repository
                .find_for_system(D::type_name(), id)
                .await?
                .filter(|entity| Self::check_access(entity, &enabled_features, &granted_features))
                .and_then(|entity| Self::parse::<D::Item>(&entity.data, &handler)))
        }
    }

    pub async fn find_singleton<D: ConfigDescriptor>(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<D::Item>> {
        self.find_by_id::<D>(tenant_id, "instance").await
    }
}
