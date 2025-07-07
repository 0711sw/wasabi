use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio::signal::unix::{SignalKind, signal};

static RUNNING: AtomicBool = AtomicBool::new(true);

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

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub async fn await_shutdown() {
    while is_running() {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
