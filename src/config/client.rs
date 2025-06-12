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

pub struct TenantSettings {
    repository: Arc<dyn ConfigRepository>,
    tenant_id: String,
    enabled_features: Option<HashSet<String>>,
    granted_features: Option<HashSet<String>>,
}

impl ConfigClient {
    pub fn new(registry: Arc<Registry>, repository: Arc<dyn ConfigRepository>) -> Self {
        Self {
            registry,
            repository,
        }
    }

    pub fn tenant_settings(&self, tenant_id: &str) -> TenantSettings {
        TenantSettings::new(self.repository.clone(), tenant_id.to_string())
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn find_all<D: ConfigDescriptor>(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<D::Item>> {
        let type_name = D::type_name();
        let mut tenant_settings = self.tenant_settings(tenant_id);

        let mut entities: Vec<ConfigEntity> = Vec::new();

        for entity in self.repository.find_all_for_system(&type_name).await? {
            if tenant_settings.check_access(&entity).await? {
                entities.push(entity);
            }
        }

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

    fn parse<T: 'static>(data: &str, handler: &ConfigHandler) -> Option<T> {
        serde_json::from_str::<Value>(data)
            .ok()
            .and_then(|value| (handler.parse)(value).ok())
            .and_then(|element| element.downcast::<T>().ok())
            .map(|element| *element)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn find_by_id<D: ConfigDescriptor>(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> anyhow::Result<Option<D::Item>> {
        let handler = self.registry.find_handler(D::type_name())?;
        let mut tenant_settings = self.tenant_settings(tenant_id);

        if let Some(entity) = self
            .repository
            .find_for_tenant(D::type_name(), tenant_id, id)
            .await?
            .and_then(|entity| Self::parse::<D::Item>(&entity.data, &handler))
        {
            Ok(Some(entity))
        } else if let Some(entity) = self.repository.find_for_system(D::type_name(), id).await? {
            if tenant_settings.check_access(&entity).await? {
                Ok(Self::parse::<D::Item>(&entity.data, &handler))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn find_singleton<D: ConfigDescriptor>(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<D::Item>> {
        self.find_by_id::<D>(tenant_id, "instance").await
    }
}

impl TenantSettings {
    fn new(repository: Arc<dyn ConfigRepository>, tenant_id: String) -> Self {
        Self {
            repository,
            tenant_id,
            enabled_features: None,
            granted_features: None,
        }
    }

    async fn load(&mut self) -> anyhow::Result<()> {
        let tenant_settings = self
            .repository
            .fetch_tenant_settings(&self.tenant_id)
            .await?;

        self.enabled_features = Some(tenant_settings.enabled_features.into_iter().collect());
        self.granted_features = Some(tenant_settings.granted_features.into_iter().collect());
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn check_access(&mut self, entity: &ConfigEntity) -> anyhow::Result<bool> {
        if let Some(feature) = &entity.required_feature {
            Ok(self.check_if_enabled(feature).await?
                && !self.check_if_suppressed(&entity.id).await?)
        } else {
            Ok(true)
        }
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn check_if_enabled(&mut self, feature: &str) -> anyhow::Result<bool> {
        if self.enabled_features.is_none() {
            self.load().await?;
        }

        Ok(self
            .enabled_features
            .as_ref()
            .map(|features| features.contains(feature))
            .unwrap_or(false)
            && self
                .granted_features
                .as_ref()
                .map(|features| features.contains(feature))
                .unwrap_or(false))
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn check_if_suppressed(&mut self, id: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}
