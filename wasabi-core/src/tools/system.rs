//! Graceful shutdown handling via Unix signals.
//!
//! Provides a global shutdown flag that gets set when the process receives
//! SIGINT, SIGTERM, or SIGHUP. This allows long-running tasks and HTTP servers
//! to complete in-flight work before exiting.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio::signal::unix::{SignalKind, signal};

static RUNNING: AtomicBool = AtomicBool::new(true);

/// Spawns a background task that listens for termination signals.
///
/// Once any of SIGINT, SIGTERM, or SIGHUP is received, the global running
/// flag is set to false. Call this once at application startup.
pub fn install_termination_listener() {
    tokio::spawn({
        async move {
            let mut sig_term = signal(SignalKind::terminate()).ok();
            let mut sig_int = signal(SignalKind::interrupt()).ok();
            let mut sig_hup = signal(SignalKind::hangup()).ok();

            tokio::select! {
                Some(_) = async { sig_int.as_mut()?.recv().await } => {
                    tracing::info!("Received SIGINT. Shutting down...");
                    RUNNING.store(false, Ordering::Relaxed);
                },
                Some(_) = async { sig_term.as_mut()?.recv().await } => {
                    tracing::info!("Received SIGTERM. Shutting down...");
                    RUNNING.store(false, Ordering::Relaxed);
                },
                Some(_) = async { sig_hup.as_mut()?.recv().await } => {
                    tracing::info!("Received SIGHUP. Shutting down...");
                    RUNNING.store(false, Ordering::Relaxed);
                },
            }
        }
    });
}

/// Returns `true` if the application should continue running.
///
/// Returns `false` after a termination signal has been received.
pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

/// Blocks until a shutdown signal is received.
///
/// Polls the running flag every second. Use this to keep the main task
/// alive while background services handle requests.
pub async fn await_shutdown() {
    while is_running() {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
