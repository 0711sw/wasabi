use crate::config::client::ConfigClient;
use crate::config::descriptor::{ConfigDescriptor, ValidationMessage, Validator};
use crate::tools::i18n_string::I18nString;
use crate::tools::id_generator::generate_id;
use crate::web::DEFAULT_MAX_JSON_BODY_SIZE;
use crate::web::auth::authenticator::Authenticator;
use crate::web::auth::enforce_user_with_any_permission;
use crate::web::warp::{into_response, with_body_as_json, with_cloneable};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ModuleElement {
    pub name: String,
    pub label: I18nString,
    pub description: I18nString,
}

pub(crate) struct ModuleDescriptor;

impl ConfigDescriptor for ModuleDescriptor {
    type Item = ModuleElement;

    fn type_name() -> &'static str {
        "sys::Module"
    }

    fn validate(_item: &ModuleElement, _validator: &mut Validator) -> anyhow::Result<()> {
        // Perform validation logic here
        Ok(())
    }

    fn derive_id(item: &ModuleElement) -> anyhow::Result<String> {
        Ok(item.name.clone())
    }
}

#[derive(Debug, Deserialize)]
struct SystemModuleBody {
    pub name: String,
    pub label: I18nString,
    pub description: I18nString,

    pub elements: Vec<Value>,
}

pub fn post_validate_system_module_route(
    authenticator: Arc<Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "module" / "validate" / "v1")
        .and(warp::post())
        .and(enforce_user_with_any_permission(
            authenticator,
            required_permissions,
        ))
        .and(with_cloneable(config_client))
        .and(with_body_as_json::<SystemModuleBody>(
            DEFAULT_MAX_JSON_BODY_SIZE,
        ))
        .and_then(handle_post_validate_system_module_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /config/module/validate/v1", skip_all)]
async fn handle_post_validate_system_module_route(
    config_client: ConfigClient,
    module: SystemModuleBody,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_system_module(config_client, module, false).await)
}

pub fn post_system_module_route(
    authenticator: Arc<Authenticator>,
    required_permissions: &'static [&'static str],
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "module" / "v1")
        .and(warp::post())
        .and(enforce_user_with_any_permission(
            authenticator,
            required_permissions,
        ))
        .and(with_cloneable(config_client))
        .and(with_body_as_json::<SystemModuleBody>(
            DEFAULT_MAX_JSON_BODY_SIZE,
        ))
        .and_then(handle_post_system_module_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /config/module/v1", skip_all)]
async fn handle_post_system_module_route(
    config_client: ConfigClient,
    module: SystemModuleBody,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_system_module(config_client, module, true).await)
}

async fn handle_system_module(
    config_client: ConfigClient,
    module: SystemModuleBody,
    perform_save: bool,
) -> anyhow::Result<Vec<ValidationMessage>> {
    let module_name = module.name.clone();
    let mut validator = Validator::new();

    let mut elements = module.elements;
    elements.insert(
        0,
        json!({
            "@type": ModuleDescriptor::type_name(),
            "name": module.name,
            "label": module.label,
            "description": module.description,
        }),
    );

    let mut elements_to_store = Vec::with_capacity(elements.len());
    for (index, element_data) in elements.into_iter().enumerate() {
        let element_type = element_data
            .get("@type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        validator.with_context(format!("{} (Element #{})", element_type, index));
        let _ = (|| -> anyhow::Result<()> {
            let handler = config_client.registry.find_handler(&element_type)?;
            let element = (handler.parse)(element_data.clone())?;
            let id = (handler.derive_id)(&element)?;
            validator.with_context(format!("{} ({})", &element_type, id));
            (handler.validate)(&element, &mut validator)?;
            elements_to_store.push((element_data, element_type, id));
            Ok(())
        })()
        .map_err(|err| {
            validator.add_message(ValidationMessage::error(format!("{:#}", err)));
        });
    }

    if !validator.has_errors() && perform_save {
        let txn = generate_id(16);
        for (mut data, element_type, id) in elements_to_store.into_iter() {
            let priority = data.get("@priority").and_then(Value::as_i64).unwrap_or(100) as i32;
            let required_feature = data
                .get("@requiredFeature")
                .and_then(Value::as_str)
                .map(str::to_string);

            if let Value::Object(ref mut data) = data {
                data.retain(|data, _| !data.starts_with('@'));
            }

            config_client
                .repository
                .store_system_element(
                    &module_name,
                    &txn,
                    element_type,
                    id,
                    priority,
                    required_feature,
                    serde_json::to_string(&data)?,
                )
                .await?;
        }

        config_client
            .repository
            .remove_outdated_system_elements(&module_name, &txn)
            .await?;
    }

    Ok(validator.messages())
}
