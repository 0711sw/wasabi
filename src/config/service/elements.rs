use std::sync::Arc;
use crate::config::client::ConfigClient;
use crate::config::descriptor::{ValidationMessage, Validator};
use crate::config::repository::{ConfigEntity, TenantSettingsEntity};
use crate::config::service::features::{FeatureDescriptor, FeatureInfo, from_config};
use crate::config::service::system::ModuleDescriptor;
use crate::web::DEFAULT_MAX_JSON_BODY_SIZE;
use crate::web::auth::{with_user_with_any_permission};
use crate::web::warp::{into_response, with_body_as_json, with_cloneable};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use warp::Filter;
use warp::filters::BoxedFilter;
use crate::web::auth::authenticator::Authenticator;
use crate::web::auth::user::User;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ElementInfo {
    pub id: String,
    pub priority: i32,
    pub state: ElementState,
    pub required_feature: Option<FeatureInfo>,
    pub module: Option<ModuleInfo>,
    pub data: Value,
}

#[derive(Debug, Serialize, Deserialize)]
enum ElementState {
    Enabled,
    FeatureDisabled,
    ElementSuppressed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleInfo {
    pub id: String,
    pub label: String,
    pub description: Option<String>,
}

pub fn get_elements_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "elements" / "v1" / String)
        .and(warp::get())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(authenticator, required_permissions))
        .and_then(handle_get_elements_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /config/elements/v1", skip_all)]
async fn handle_get_elements_route(
    type_name: String,
    config_client: ConfigClient,
    user: User,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_get_elements(type_name, config_client, user).await)
}

async fn handle_get_elements(
    type_name: String,
    config_client: ConfigClient,
    user: User,
) -> anyhow::Result<Vec<ElementInfo>> {
    let tenant_id = user.tenant_id()?;
    let mut entities: Vec<ElementInfo> = config_client
        .repository
        .find_all_for_tenant(&type_name, tenant_id)
        .await?
        .iter()
        .map(|entity| {
            if let Ok(data) = serde_json::from_str::<Value>(&entity.data) {
                Some(ElementInfo {
                    id: entity.id.clone(),
                    priority: entity.priority,
                    state: ElementState::Enabled,
                    required_feature: None,
                    module: None,
                    data,
                })
            } else {
                None
            }
        })
        .flatten()
        .collect();

    let settings = config_client
        .repository
        .fetch_tenant_settings(tenant_id)
        .await?;

    for entity in config_client
        .repository
        .find_all_for_system(&type_name)
        .await?
    {
        if is_accessible(&entity, &settings) {
            if let Ok(data) = serde_json::from_str::<Value>(&entity.data) {
                entities.push(ElementInfo {
                    id: entity.id.clone(),
                    priority: entity.priority,
                    state: determine_state(&entity, &settings),
                    required_feature: fetch_feature_info(
                        &entity.required_feature,
                        &settings,
                        &config_client,
                    )
                    .await?,
                    module: fetch_module_info(&entity.module, &settings, &config_client).await?,
                    data,
                });
            }
        }
    }

    entities.sort_by(|a, b| a.priority.cmp(&b.priority));

    Ok(entities)
}

fn is_accessible(entity: &ConfigEntity, settings: &TenantSettingsEntity) -> bool {
    if let Some(required_feature) = &entity.required_feature {
        settings.granted_features.contains(&required_feature)
    } else {
        true
    }
}

fn determine_state(entity: &ConfigEntity, settings: &TenantSettingsEntity) -> ElementState {
    if settings.suppressed_elements.contains(&entity.id) {
        ElementState::ElementSuppressed
    } else if let Some(required_feature) = &entity.required_feature {
        if settings.enabled_features.contains(required_feature) {
            ElementState::Enabled
        } else {
            ElementState::FeatureDisabled
        }
    } else {
        ElementState::Enabled
    }
}

async fn fetch_feature_info(
    feature: &Option<String>,
    settings: &TenantSettingsEntity,
    config: &ConfigClient,
) -> anyhow::Result<Option<FeatureInfo>> {
    if let Some(feature_name) = feature {
        if let Some(feature_element) = config
            .find_by_id::<FeatureDescriptor>(&settings.tenant_id, feature_name)
            .await?
        {
            Ok(Some(from_config(
                &feature_element,
                "xx",
                settings.enabled_features.contains(&feature_name),
            )))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

async fn fetch_module_info(
    module: &Option<String>,
    settings: &TenantSettingsEntity,
    config: &ConfigClient,
) -> anyhow::Result<Option<ModuleInfo>> {
    if let Some(module_name) = module {
        if let Some(module_info) = config
            .find_by_id::<ModuleDescriptor>(&settings.tenant_id, module_name)
            .await?
        {
            Ok(Some(ModuleInfo {
                id: module_info.name.clone(),
                label: module_info
                    .label
                    .get("xx")
                    .unwrap_or(&module_info.name)
                    .to_string(),
                description: module_info.description.get("xx").map(str::to_owned),
            }))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub fn put_element_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "element" / "v1")
        .and(warp::put())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(authenticator, required_permissions))
        .and(with_body_as_json::<Value>(DEFAULT_MAX_JSON_BODY_SIZE))
        .and_then(handle_put_element_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /config/elements/v1", skip_all)]
async fn handle_put_element_route(
    config_client: ConfigClient,
    user: User,
    element: Value,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_put_element(config_client, user, element).await)
}

async fn handle_put_element(
    config_client: ConfigClient,
    user: User,
    mut element_data: Value,
) -> anyhow::Result<Vec<ValidationMessage>> {
    let type_name = element_data
        .get("@type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Element type is required"))?
        .to_string();
    let priority = element_data
        .get("@priority")
        .and_then(Value::as_i64)
        .unwrap_or(100) as i32;

    let handler = config_client.registry.find_handler(&type_name)?;
    let element = (handler.parse)(element_data.clone())?;
    let id = (handler.derive_id)(&element)?;

    let mut validator = Validator::new();
    (handler.validate)(&element, &mut validator)?;

    if !validator.has_errors() {
        if let Value::Object(ref mut data) = element_data {
            data.retain(|data, _| !data.starts_with('@'));
        }

        config_client
            .repository
            .store_tenant_element(
                user.tenant_id()?.to_owned(),
                type_name,
                id,
                priority,
                serde_json::to_string(&element_data)?,
            )
            .await?;
    }
    Ok(validator.messages())
}

pub fn delete_element_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "element" / "v1" / String / String)
        .and(warp::delete())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(authenticator, required_permissions))
        .and_then(handle_delete_element_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "DELETE /config/element/v1", skip_all)]
async fn handle_delete_element_route(
    type_name: String,
    id: String,
    config_client: ConfigClient,
    user: User,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_delete_element(type_name, id, config_client, user).await)
}

async fn handle_delete_element(
    type_name: String,
    id: String,
    config_client: ConfigClient,
    user: User,
) -> anyhow::Result<()> {
    config_client
        .repository
        .delete_tenant_element(user.tenant_id()?, &type_name, &id)
        .await?;
    Ok(())
}
