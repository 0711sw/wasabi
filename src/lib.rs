use std::env;
use std::sync::LazyLock;
use tokio::signal::ctrl_c;
use tokio::signal::unix::{SignalKind, signal};

pub mod aws;
pub mod logging;

pub mod web;

pub static APP_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("APP_NAME").unwrap_or("DBX-CORE".to_string()));

pub static APP_VERSION: LazyLock<String> =
    LazyLock::new(|| env::var("APP_VERSION").unwrap_or("DEVELOPMENT-SNAPSHOT-VERSION".to_string()));

pub static CLUSTER_ID: LazyLock<String> =
    LazyLock::new(|| env::var("CLUSTER_ID").unwrap_or("local".to_string()));

pub static NODE_ID: LazyLock<String> =
    LazyLock::new(|| env::var("NODE_ID").unwrap_or("localhost".to_string()));

pub static TASK_ID: LazyLock<String> =
    LazyLock::new(|| env::var("TASK_ID").unwrap_or("local".to_string()));

pub const KB: usize = 1024;
pub const MB: usize = 1024 * KB;
pub const GB: usize = 1024 * MB;

pub async fn await_termination(purpose: &str) {
    let ctrl_c = ctrl_c();
    if let Ok(mut sig_hup) = signal(SignalKind::hangup()) {
        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received CTRL-C. Shutting down: '{}'...", purpose);
            },
            _ = sig_hup.recv() => {
                tracing::info!("Received SIGHUP. Shutting down: '{}'...", purpose);
            }
        }
    } else {
        let _ = ctrl_c.await;
        tracing::info!("Received CTRL-C. Shutting down: '{}'...", purpose);
    }
}
