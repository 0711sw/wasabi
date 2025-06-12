use crate::config::client::ConfigClient;
use crate::config::descriptor::{ConfigDescriptor, ValidationMessage, Validator};
use crate::tools::i18n_string::I18nString;
use crate::tools::id_generator::generate_id;
use crate::web::user::{Authenticator, User, with_user};
use crate::web::warp::{into_response, with_cloneable};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
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

    fn validate(item: &ModuleElement, validator: &mut Validator) -> anyhow::Result<()> {
        // Perform validation logic here
        Ok(())
    }

    fn derive_id(item: &ModuleElement) -> anyhow::Result<String> {
        Ok(item.name.clone())
    }
}

pub(crate) struct ModuleInfo {
    pub id: String,
    pub label: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct SystemModuleBody {
    pub name: String,
    pub label: I18nString,
    pub description: I18nString,

    pub elements: Vec<Value>,
}

pub fn post_validate_system_module_route(
    authenticator: Authenticator,
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "module" / "validate" / "v1")
        .and(warp::post())
        .and(with_cloneable(config_client))
        .and(with_user(authenticator))
        .and(warp::body::json::<SystemModuleBody>())
        .and_then(handle_post_validate_system_module_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /config/module/validate/v1", skip_all)]
async fn handle_post_validate_system_module_route(
    config_client: ConfigClient,
    user: User,
    module: SystemModuleBody,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_system_module(config_client, user, module, false).await)
}

pub fn post_system_module_route(
    authenticator: Authenticator,
    config_client: ConfigClient,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "module" / "v1")
        .and(warp::post())
        .and(with_cloneable(config_client))
        .and(with_user(authenticator))
        .and(warp::body::json::<SystemModuleBody>())
        .and_then(handle_post_system_module_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /config/module/v1", skip_all)]
async fn handle_post_system_module_route(
    config_client: ConfigClient,
    user: User,
    module: SystemModuleBody,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(handle_system_module(config_client, user, module, true).await)
}

async fn handle_system_module(
    config_client: ConfigClient,
    user: User,
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
        let handler = config_client.registry.find_handler(&element_type)?;
        let element = (handler.parse)(element_data.clone())?;
        let id = (handler.derive_id)(&element)?;
        validator.with_context(format!("{} ({})", &element_type, id));
        (handler.validate)(&element, &mut validator)?;
        elements_to_store.push((element_data, element, element_type, id))
    }

    if !validator.has_errors() && perform_save {
        let txn = generate_id(16);
        for (data, element, element_type, id) in elements_to_store.into_iter() {
            config_client
                .repository
                .store_system_element(
                    &module_name,
                    &txn,
                    element_type,
                    id,
                    data.get("@priority").and_then(Value::as_i64).unwrap_or(100) as i32,
                    data.get("@requiredFeature")
                        .and_then(Value::as_str)
                        .map(str::to_string),
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
