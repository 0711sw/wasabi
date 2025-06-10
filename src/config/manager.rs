// use crate::config::descriptor::{
//     ConfigClientDescriptor, ConfigDescriptor, ValidationMessage, Validator, unbox,
// };
// use crate::tools::i18n_string::I18nString;
// use serde::{Deserialize, Serialize};
// use serde_json::Value;
// use std::any::Any;
// 
// pub struct ConfigManager {}
// 
// #[derive(Debug, Serialize, Deserialize)]
// pub struct FeatureConfig {
//     pub name: String,
//     pub label: I18nString,
//     pub description: I18nString,
// }
// 
// impl ConfigClientDescriptor for FeatureConfig {
//     type Item = FeatureConfig;
// 
//     fn type_name() -> String {
//         "sys::Feature".to_owned()
//     }
// }
// 
// impl ConfigDescriptor for FeatureConfig {
//     fn type_name(&self) -> String {
//         <Self as ConfigClientDescriptor>::type_name()
//     }
// 
//     fn validate(&self, item: Value, validator: &mut Validator) -> anyhow::Result<()> {
//         let feature = unbox::<FeatureConfig>(self.deserialize(item)?)?;
// 
//         Ok(())
//     }
// 
//     fn derive_id(&self, item: Value) -> anyhow::Result<String> {
//         let feature = unbox::<FeatureConfig>(self.deserialize(item)?)?;
// 
//         Ok(feature.name)
//     }
// 
//     fn deserialize(&self, value: Value) -> anyhow::Result<Box<dyn Any>> {
//         serde_json::from_value::<FeatureConfig>(value)
//             .map(|config: FeatureConfig| Box::new(config) as Box<dyn Any>)
//             .map_err(|e| anyhow::anyhow!("Failed to deserialize FeatureConfig: {}", e))
//     }
// }
// 
// pub struct ModuleConfig {
//     pub feature: String,
//     pub label: I18nString,
//     pub description: I18nString,
// }
// 
// pub struct FeatureInfo {
//     pub id: String,
//     pub label: String,
//     pub description: String,
//     pub enabled: bool,
// }
// 
// pub struct ModuleInfo {
//     pub id: String,
//     pub label: String,
//     pub description: String,
// }
// 
// pub struct ConfigInfo {
//     pub id: String,
//     pub priority: i32,
//     pub enabled: bool,
//     pub required_feature: Option<FeatureInfo>,
//     pub module: Option<ModuleInfo>,
//     pub data: Value,
// }
// 
// // - Convert all this to ervices
// 
// impl ConfigManager {
//     pub async fn list_granted_features(&self, tenant_id: &str) -> anyhow::Result<Vec<FeatureInfo>> {
//         todo!();
//     }
// 
//     pub async fn store_granted_features(
//         &self,
//         tenant_id: &str,
//         features: Vec<String>,
//     ) -> anyhow::Result<()> {
//         todo!();
//     }
// 
//     pub async fn list_enabled_features(&self, tenant_id: &str) -> anyhow::Result<Vec<FeatureInfo>> {
//         todo!();
//     }
// 
//     pub async fn store_enabled_features(
//         &self,
// 
//         tenant_id: &str,
//         features: Vec<String>,
//     ) -> anyhow::Result<()> {
//         todo!();
//     }
// 
//     pub fn list_configurations(
//         &self,
//         tenant_id: &str,
//         config_type: &str,
//     ) -> anyhow::Result<Vec<ConfigInfo>> {
//         todo!();
//     }
// 
//     pub fn validate_configuration(&self, config_type: &str, data: Value) -> Vec<ValidationMessage> {
//         // This function would typically validate the configuration data.
//         // For now, we return Ok as a placeholder.
//         todo!();
//     }
// 
//     pub fn create_configuration(
//         &self,
//         tenant_id: &str,
//         config_type: &str,
//         data: Value,
//     ) -> anyhow::Result<ConfigInfo> {
//         todo!();
//     }
// 
//     pub fn update_configuration(
//         &self,
//         tenant_id: &str,
//         config_type: &str,
//         id: &str,
//         data: Value,
//     ) -> anyhow::Result<ConfigInfo> {
//         todo!();
//     }
// 
//     pub fn delete_configuration(
//         &self,
//         tenant_id: &str,
//         config_type: &str,
//         id: &str,
//     ) -> anyhow::Result<()> {
//         todo!();
//     }
// 
//     pub fn validate_system_module(
//         &self,
//         module_name: &str,
//         configs: Vec<Value>,
//     ) -> Vec<ValidationMessage> {
//         // This function would typically validate the system module configurations.
//         // For now, we return Ok as a placeholder.
//         todo!();
//     }
// 
//     pub fn import_system_module(
//         &self,
//         module_name: &str,
//         configs: Vec<Value>,
//     ) -> anyhow::Result<()> {
//         todo!();
//     }
// }
