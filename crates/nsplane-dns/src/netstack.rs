//! [`Server`] on the flows of an `nsplane-netstack` user-space stack (feature `netstack`).
//!
//! [`Server::serve_udp_flow`] answers the datagrams of one [`UdpFlow`] and
//! [`Server::serve_tcp_connection`] the queries on one [`TcpConnection`]. The stack reports
//! flows and connections to every port; the embedder routes the ones for its DNS port here,
//! by local address:
//!
//! ```no_run
//! use std::future::poll_fn;
//! use std::pin::Pin;
//!
//! use futures_core::Stream;
//! use nsplane_dns::{Server, StaticRecords};
//! use nsplane_netstack::NetStackHandle;
//!
//! async fn serve_dns(handle: &NetStackHandle, server: Server<StaticRecords>) {
//!     let mut flows = handle.incoming_udp();
//!     while let Some(flow) = poll_fn(|cx| Pin::new(&mut flows).poll_next(cx)).await {
//!         if flow.local_addr().port() == 53 {
//!             let server = server.clone();
//!             tokio::spawn(async move { server.serve_udp_flow(flow).await });
//!         }
//!         // Other flows are dropped here, or handed to whatever serves their port.
//!     }
//! }
//! ```
//!
//! TCP connections from [`incoming_tcp`](nsplane_netstack::NetStackHandle::incoming_tcp)
//! are routed the same way, each served by [`Server::serve_tcp_connection`] in its own task.

use std::io;

use nsplane_netstack::{TcpConnection, UdpFlow};

use crate::resolver::Resolver;
use crate::server::{Server, Transport};

impl<R: Resolver + 'static> Server<R> {
    /// Answers the datagrams of `flow` until [`UdpFlow::recv`] returns `None` (the stack
    /// stopped or the flow was revoked). Available with the `netstack` feature.
    ///
    /// Like [`serve_udp`](Self::serve_udp): each datagram is handled in its own task holding
    /// an in-flight permit and answered through the flow's reply handle; without a free
    /// permit the datagram is dropped and counted in
    /// [`ServerStats::dropped_overload`](crate::ServerStats::dropped_overload). Needs a tokio
    /// runtime.
    pub async fn serve_udp_flow(&self, mut flow: UdpFlow) {
        let client = flow.peer_addr();
        while let Some(message) = flow.recv().await {
            let Some(permit) = self.try_udp_permit(client) else {
                continue;
            };
            let server = self.clone();
            let reply = flow.reply_handle();
            tokio::spawn(async move {
                let response = server.handle(&message, client, Transport::Udp).await;
                drop(permit);
                if let Some(response) = response
                    && let Err(err) = reply.send(&response).await
                {
                    tracing::debug!(%client, %err, "DNS UDP send error");
                }
            });
        }
    }

    /// Answers the queries on `conn` with [`serve_stream`](Self::serve_stream), the client
    /// being the connection's peer. Available with the `netstack` feature.
    ///
    /// # Errors
    ///
    /// An I/O error of `conn`.
    pub async fn serve_tcp_connection(&self, conn: TcpConnection) -> io::Result<()> {
        let client = conn.peer_addr();
        self.serve_stream(conn, client).await
    }
}
