//! Shared networking utilities.

use tokio::net::TcpStream;
use tracing::warn;

/// Enables `TCP_NODELAY`, logging a warning if the socket option cannot be set.
pub fn set_tcp_nodelay(tcp: &mut TcpStream) {
    if let Err(error) = tcp.set_nodelay(true) {
        warn!(%error, "failed to set TCP_NODELAY");
    }
}
