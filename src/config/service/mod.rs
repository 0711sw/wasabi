pub mod elements;
pub mod features;
pub mod system;

use serde_json::Value;

pub struct ElementInfo {
    pub id: String,
    pub priority: i32,
    pub enabled: bool,
    // pub required_feature: Option<crate::config::manager::FeatureInfo>,
    // pub module: Option<crate::config::manager::ModuleInfo>,
    pub data: Value,
}
