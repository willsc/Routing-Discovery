//! Minimal systemd notifications; no third-party daemon dependency.

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
