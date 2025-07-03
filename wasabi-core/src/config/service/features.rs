use crate::config::client::ConfigClient;
use crate::config::descriptor::{ConfigDescriptor, Validator};
use crate::tools::i18n_string::I18nString;
use crate::web::DEFAULT_MAX_JSON_BODY_SIZE;
use crate::web::auth::authenticator::Authenticator;
use crate::web::auth::user::User;
use crate::web::auth::with_user_with_any_permission;
use crate::web::warp::{into_response, with_body_as_json, with_cloneable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FeatureElement {
    pub name: String,
    pub label: I18nString,
    #[serde(default)]
    pub description: I18nString,
    pub auto_granted: bool,
}

pub(crate) struct FeatureDescriptor;

impl ConfigDescriptor for FeatureDescriptor {
    type Item = FeatureElement;

    fn type_name() -> &'static str {
        "sys::Feature"
    }

    fn validate(_item: &FeatureElement, _validator: &mut Validator) -> anyhow::Result<()> {
        Ok(())
    }

    fn derive_id(item: &FeatureElement) -> anyhow::Result<String> {
        Ok(item.name.clone())
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FeatureInfo {
    pub id: String,
    pub label: String,
    pub description: Option<String>,
    pub enabled: bool,
}

pub(crate) fn from_config(feature: &FeatureElement, lang: &str, enabled: bool) -> FeatureInfo {
    FeatureInfo {
        id: feature.name.clone(),
        label: feature.label.get(lang).unwrap_or(&feature.name).to_owned(),
        description: feature.description.get(lang).map(str::to_owned),
        enabled,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FeatureUpdate {
    features: Vec<String>,
}

pub fn get_granted_features_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "granted-features" / "v1")
        .and(warp::get())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(
            authenticator,
            required_permissions,
        ))
        .and_then(handle_get_granted_features_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /config/granted-features/v1", skip_all)]
async fn handle_get_granted_features_route(
    config_client: ConfigClient,
    user: User,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_get_granted_features(config_client, user).await)
}

async fn handle_get_granted_features(
    config_client: ConfigClient,
    user: User,
) -> anyhow::Result<Vec<FeatureInfo>> {
    let granted_features = config_client
        .repository
        .fetch_tenant_settings(&user.tenant_id()?)
        .await?
        .granted_features;

    Ok(config_client
        .find_all::<FeatureDescriptor>(&user.tenant_id()?)
        .await?
        .iter()
        .filter(|feature| !feature.auto_granted)
        .map(|feature| from_config(&feature, "xx", granted_features.contains(&feature.name)))
        .collect())
}

pub fn post_granted_features_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "granted-features" / "v1")
        .and(warp::post())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(
            authenticator,
            required_permissions,
        ))
        .and(with_body_as_json::<FeatureUpdate>(
            DEFAULT_MAX_JSON_BODY_SIZE,
        ))
        .and_then(handle_post_granted_features_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /config/granted-features/v1", skip_all)]
async fn handle_post_granted_features_route(
    config_client: ConfigClient,
    user: User,
    feature_update: FeatureUpdate,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_post_granted_features(config_client, user, feature_update).await)
}

async fn handle_post_granted_features(
    config_client: ConfigClient,
    user: User,
    feature_update: FeatureUpdate,
) -> anyhow::Result<FeatureUpdate> {
    let tenant_id = user.tenant_id()?;
    let mut settings = config_client
        .repository
        .fetch_tenant_settings(tenant_id)
        .await?;

    settings.granted_features = feature_update.features.clone();

    config_client
        .repository
        .store_tenant_settings(settings)
        .await?;

    Ok(feature_update)
}

pub fn get_enabled_features_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "features" / "v1")
        .and(warp::get())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(
            authenticator,
            required_permissions,
        ))
        .and_then(handle_get_enabled_features_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /config/features/v1", skip_all)]
async fn handle_get_enabled_features_route(
    config_client: ConfigClient,
    user: User,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_get_enabled_features(config_client, user).await)
}

async fn handle_get_enabled_features(
    config_client: ConfigClient,
    user: User,
) -> anyhow::Result<Vec<FeatureInfo>> {
    let settings = config_client
        .repository
        .fetch_tenant_settings(&user.tenant_id()?)
        .await?;

    Ok(config_client
        .find_all::<FeatureDescriptor>(&user.tenant_id()?)
        .await?
        .iter()
        .filter(|feature| feature.auto_granted || settings.granted_features.contains(&feature.name))
        .map(|feature| {
            from_config(
                &feature,
                "xx",
                settings.enabled_features.contains(&feature.name),
            )
        })
        .collect())
}

pub fn post_enabled_features_route(
    authenticator: Arc<dyn Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "features" / "v1")
        .and(warp::post())
        .and(with_cloneable(config_client))
        .and(with_user_with_any_permission(
            authenticator,
            required_permissions,
        ))
        .and(with_body_as_json::<FeatureUpdate>(
            DEFAULT_MAX_JSON_BODY_SIZE,
        ))
        .and_then(handle_post_enabled_features_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /config/features/v1", skip_all)]
async fn handle_post_enabled_features_route(
    config_client: ConfigClient,
    user: User,
    feature_update: FeatureUpdate,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_post_enabled_features(config_client, user, feature_update).await)
}

async fn handle_post_enabled_features(
    config_client: ConfigClient,
    user: User,
    feature_update: FeatureUpdate,
) -> anyhow::Result<FeatureUpdate> {
    let tenant_id = user.tenant_id()?;
    let mut settings = config_client
        .repository
        .fetch_tenant_settings(tenant_id)
        .await?;
    let features = config_client
        .find_all::<FeatureDescriptor>(tenant_id)
        .await?;

    settings.enabled_features = feature_update
        .features
        .into_iter()
        .filter(|feature| {
            settings.granted_features.contains(feature)
                || features
                    .iter()
                    .any(|f| f.name == *feature && f.auto_granted)
        })
        .collect();

    config_client
        .repository
        .store_tenant_settings(settings.clone())
        .await?;

    Ok(FeatureUpdate {
        features: settings.enabled_features,
    })
}
