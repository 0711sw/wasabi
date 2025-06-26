use tokio::signal::ctrl_c;
use tokio::signal::unix::{signal, SignalKind};

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