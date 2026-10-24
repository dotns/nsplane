//! The [`Resolver`] trait and [`Fallback`] composition.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::message::{Answer, Query, ResponseCode};

/// Answers decoded queries.
///
/// A server calls `resolve` concurrently for many queries, so implementations must not block
/// the executor: slow work (forwarding, lookups) is awaited. `client` is the transport peer
/// the query came from.
pub trait Resolver: Send + Sync {
    /// Answers `query` from `client`.
    fn resolve(&self, query: &Query, client: SocketAddr) -> impl Future<Output = Answer> + Send;
}

impl<R: Resolver + ?Sized> Resolver for Arc<R> {
    fn resolve(&self, query: &Query, client: SocketAddr) -> impl Future<Output = Answer> + Send {
        (**self).resolve(query, client)
    }
}

impl<R: Resolver + ?Sized> Resolver for &R {
    fn resolve(&self, query: &Query, client: SocketAddr) -> impl Future<Output = Answer> + Send {
        (**self).resolve(query, client)
    }
}

/// Asks `first`, and `second` when `first` answers `NXDOMAIN` ([`Answer::Code`] with
/// [`ResponseCode::NxDomain`]). Every other answer of `first`, `NODATA` included, is final.
/// Nest it to chain more resolvers.
#[derive(Debug, Clone)]
pub struct Fallback<A, B> {
    first: A,
    second: B,
}

impl<A, B> Fallback<A, B> {
    /// Chains `first` and `second`.
    pub const fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: Resolver, B: Resolver> Resolver for Fallback<A, B> {
    async fn resolve(&self, query: &Query, client: SocketAddr) -> Answer {
        match self.first.resolve(query, client).await {
            Answer::Code(ResponseCode::NxDomain) => self.second.resolve(query, client).await,
            answer => answer,
        }
    }
}
