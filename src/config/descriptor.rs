use crate::config::service::features::FeatureDescriptor;
use crate::config::service::system::ModuleDescriptor;
use anyhow::Context;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;

pub trait ConfigDescriptor: Send + Sync
where
    Self::Item: Send + Sync + Serialize + DeserializeOwned + 'static,
{
    type Item;

    fn type_name() -> &'static str;

    fn validate(item: &Self::Item, validator: &mut Validator) -> anyhow::Result<()>;

    fn derive_id(item: &Self::Item) -> anyhow::Result<String>;
}

pub struct ConfigHandler {
    pub(crate) parse: Box<dyn Fn(Value) -> anyhow::Result<Box<dyn Any + Send + Sync>> + Send + Sync>,
    pub(crate) validate: Box<
        dyn Fn(&Box<dyn Any + Send + Sync>, &mut Validator) -> anyhow::Result<()> + Send + Sync,
    >,
    pub(crate) derive_id: Box<dyn Fn(&Box<dyn Any + Send + Sync>) -> anyhow::Result<String> + Send + Sync>,
}

pub struct Validator {
    messages: Vec<ValidationMessage>,
    context: Option<String>,
}

impl Validator {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            context: None,
        }
    }

    pub fn with_context(&mut self, context: String) {
        self.context = Some(context);
    }

    pub fn add_message(&mut self, message: ValidationMessage) {
        if let Some(context) = self.context.as_ref() {
            self.messages.push(ValidationMessage {
                message: format!("{}: {}", context, message.message),
                severity: message.severity,
            });
        } else {
            self.messages.push(message);
        }
    }

    pub fn has_errors(&self) -> bool {
        self.messages.iter().any(|m| m.severity == Severity::Error)
    }

    pub fn messages(self) -> Vec<ValidationMessage> {
        self.messages
    }
}

#[derive(Debug, Serialize)]
pub struct ValidationMessage {
    pub message: String,
    pub severity: Severity,
}

impl ValidationMessage {
    pub fn error(message: String) -> Self {
        Self {
            message,
            severity: Severity::Error,
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

pub struct Registry {
    handlers: HashMap<String, ConfigHandler>,
}

impl Registry {
    pub fn new() -> Self {
        let mut instance = Self {
            handlers: HashMap::new(),
        };

        instance.register::<FeatureDescriptor>();
        instance.register::<ModuleDescriptor>();

        instance
    }

    pub fn register<D: ConfigDescriptor + 'static>(&mut self) {
        self.handlers.insert(
            D::type_name().to_owned(),
            ConfigHandler {
                parse: Box::new(|value| {
                    serde_json::from_value::<D::Item>(value)
                        .with_context(|| format!("Failed to deserialize {}", D::type_name()))
                        .map(|d| Box::new(d) as Box<dyn Any + Send + Sync>)
                }),
                validate: Box::new(|value, validator| {
                    D::validate(
                        value.downcast_ref::<D::Item>().context("Failed to unbox")?,
                        validator,
                    )
                }),
                derive_id: Box::new(|value| {
                    D::derive_id(value.downcast_ref::<D::Item>().context("Failed to unbox")?)
                }),
            },
        );
    }

    pub fn find_handler(&self, type_name: &str) -> anyhow::Result<&ConfigHandler> {
        self.handlers
            .get(type_name)
            .ok_or_else(|| anyhow::anyhow!("Descriptor not found for type: {}", type_name))
    }
}
