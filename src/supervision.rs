//! Minimal systemd notifications and signal handling; no third-party daemon dependency.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

pub fn notify(message: &str) {
    let Ok(address) = std::env::var("NOTIFY_SOCKET") else { return };
    if address.is_empty() {
        return;
    }
    let result = UnixDatagram::unbound().and_then(|sock| {
        let target = match address.strip_prefix('@') {
            Some(name) => SocketAddr::from_abstract_name(name.as_bytes())?,
            None => SocketAddr::from_pathname(&address)?,
        };
        sock.send_to_addr(message.as_bytes(), &target)
    });
    if let Err(e) = result {
        tracing::warn!("systemd notify failed: {e}");
    }
}

/// Stop on SIGINT/SIGTERM.
pub fn stop_on_signals(stop: tokio_util::sync::CancellationToken) -> crate::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        stop.cancel();
    });
    Ok(())
}
