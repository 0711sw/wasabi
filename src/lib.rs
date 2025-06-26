use std::env;
use std::sync::LazyLock;

pub mod logging;
pub mod tools;
pub mod web;

pub mod aws;

#[cfg(feature = "open_search")]
pub mod opensearch;

#[cfg(feature = "config")]
pub mod config;

pub static APP_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("APP_NAME").unwrap_or("WASABI".to_string()));

pub static APP_VERSION: LazyLock<String> =
    LazyLock::new(|| env::var("APP_VERSION").unwrap_or("DEVELOPMENT-SNAPSHOT-VERSION".to_string()));

pub static CLUSTER_ID: LazyLock<String> =
    LazyLock::new(|| env::var("CLUSTER_ID").unwrap_or("local".to_string()));

pub static TASK_ID: LazyLock<String> =
    LazyLock::new(|| env::var("TASK_ID").unwrap_or("local".to_string()));
