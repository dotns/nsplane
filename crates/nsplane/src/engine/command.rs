//! Handle commands on the owner task.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use nsplane_core::x25519::PublicKey;
use nsplane_core::{ConfigChange, Event, Input, PeerStats};
use nsplane_packet::{MAX_BATCH, PacketBuf, TransportId};
use tokio::sync::{mpsc, oneshot};

use super::output::Backoff;
use super::queue::batch_queue;
use super::tasks::forward_path_mtu;
use super::transport::{Datagram, NewTransport, Start, Traffic, TransportSlot};
use super::{Owner, PATH_MTU_REPORTS, Task, now};
use crate::events::DROP_TRANSPORT_REMOVED;
use crate::fragment::{FragmentStats, Fragmenter};
use crate::handle::{Command, EngineStatus, Injection, QueueStats, TransportError, TransportStats};

impl Owner {
    /// Handles a command; breaks with the reply channel on shutdown.
    pub(super) async fn command(&mut self, command: Command) -> ControlFlow<oneshot::Sender<()>> {
        if !matches!(command, Command::QueueStats(..)) {
            self.high_water.command.record_received(self.commands.len());
        }
        // Replies are best effort: the caller may have stopped waiting.
        match command {
            Command::Config(change, reply) => {
                self.config(change);
                let _ = reply.send(());
            }
            Command::PeerId(key, reply) => {
                let _ = reply.send(self.core.peer_id(&key));
            }
            Command::PeerHasSession(peer, reply) => {
                let _ = reply.send(self.core.peer_has_session(peer));
            }
            Command::PeerStats(peer, reply) => {
                let _ = reply.send(self.core.peer_stats(peer));
            }
            Command::Peers(reply) => {
                let _ = reply.send(self.peers());
            }
            Command::PublicKey(reply) => {
                let _ = reply.send(self.core.public_key());
            }
            Command::PrivateKey(reply) => {
                let _ = reply.send(self.private_key.clone());
            }
            Command::Inject(injection, reply) => {
                self.inject(injection);
                let _ = reply.send(());
            }
            Command::AddTransport(transport, reply) => {
                let _ = reply.send(self.add_transport(transport));
            }
            Command::RemoveTransport(id, reply) => {
                let _ = reply.send(self.remove_transport(id).await);
            }
            Command::ReplaceTransport(transport, reply) => {
                let _ = reply.send(self.replace_transport(transport).await);
            }
            Command::Suspend(reply) => {
                self.suspend();
                let _ = reply.send(());
            }
            Command::Resume(reply) => {
                self.resume();
                let _ = reply.send(());
            }
            Command::Mtu(reply) => {
                let _ = reply.send(self.mtu);
            }
            Command::Subscribe(reply) => {
                let _ = reply.send(self.events.subscribe());
            }
            Command::DropCounters(reply) => {
                // Includes failed sends whose signal is not served yet.
                self.send_errors();
                let _ = reply.send(self.drops.clone());
            }
            Command::QueueStats(take, reply) => {
                let _ = reply.send(self.queue_stats(take));
            }
            Command::FragmentStats(reply) => self.fragment_stats(reply),
            Command::TransportStats(reply) => {
                let _ = reply.send(self.transport_stats());
            }
            Command::Status(reply) => {
                let _ = reply.send(self.status());
            }
            command @ (Command::SetTransportMaxDatagram(..)
            | Command::ReportPathMtu(..)
            | Command::PeerMtu(..)
            | Command::PeerMtus(..)
            | Command::PathMtuStats(..)) => self.path_mtu_command(command),
            Command::Shutdown(reply) => return ControlFlow::Break(reply),
            Command::LocalBarrier(position, reply) => self.local_barrier(position, reply),
            Command::SetPlaintextEgress(peer, plaintext, reply) => {
                let _ = reply.send(self.core.set_plaintext_egress(peer, plaintext));
            }
            Command::UnansweredHandshakes(peer, reply) => {
                let _ = reply.send(self.core.unanswered_handshakes(peer));
            }
            Command::TotalUnansweredHandshakes(reply) => {
                let _ = reply.send(self.core.total_unanswered_handshakes());
            }
            command @ (Command::AddLocalIdentity(..)
            | Command::RemoveLocalIdentity(..)
            | Command::SetLocalSources(..)
            | Command::LocalIdentities(..)
            | Command::PeerIdIn(..)) => self.identity_command(command),
        }
        ControlFlow::Continue(())
    }

    /// Applies a configuration change.
    fn config(&mut self, change: ConfigChange) {
        let key = match &change {
            ConfigChange::SetPrivateKey(key) => Some(key.clone()),
            _ => None,
        };
        self.core.handle_input(Input::Config(change), now());
        // The core ignores a key another local identity holds.
        if let Some(key) = key
            && self.core.public_key() == Some(PublicKey::from(&key))
        {
            self.private_key = Some(key);
        }
        self.peers_changed();
    }

    /// Handles a command about the local identities.
    fn identity_command(&mut self, command: Command) {
        match command {
            Command::AddLocalIdentity(key, transports, reply) => {
                let id = match transports {
                    Some(transports) => self.core.add_local_identity_on(key, transports),
                    None => self.core.add_local_identity(key),
                };
                let _ = reply.send(id);
            }
            Command::RemoveLocalIdentity(id, reply) => {
                let removed = self.core.remove_local_identity(id);
                self.peers_changed();
                let _ = reply.send(removed);
            }
            Command::SetLocalSources(id, sources, reply) => {
                let _ = reply.send(self.core.set_local_sources(id, &sources));
            }
            Command::LocalIdentities(reply) => {
                let _ = reply.send(self.core.local_identities().collect());
            }
            Command::PeerIdIn(identity, key, reply) => {
                let _ = reply.send(self.core.peer_id_in(identity, &key));
            }
            _ => {}
        }
    }

    /// Sends what a change of the peers caused and updates the peer MTUs.
    fn peers_changed(&mut self) {
        self.drain(false);
        if self.path_mtus.table.is_some() {
            self.recompute_peer_mtus();
        }
    }

    /// The high-water marks including the current occupancies; with `take`, the marks
    /// restart at 0 afterwards.
    fn queue_stats(&mut self, take: bool) -> QueueStats {
        let marks = &mut self.high_water;
        // The command being served is not counted.
        marks.command.record(self.commands.len());
        if let Some(local) = &self.local {
            marks.local.record(local.len());
        }
        marks.datagrams.record(self.datagrams.len());
        marks
            .deliver
            .record(self.deliver.max_capacity() - self.deliver.capacity());
        marks.recycle.record(self.recycled.len());
        for slot in self.transports.values() {
            marks.transmit.record(slot.queued());
            marks.backlog.record(slot.pending.len());
        }
        marks
            .events
            .record(self.events.len().min(marks.events.capacity));
        if let Some(workers) = &mut self.workers {
            marks
                .crypto
                .record(std::mem::take(&mut workers.peak).max(workers.in_flight()));
            marks.crypto_done.record(workers.done.len());
        }
        let stats = *marks;
        if take {
            for depth in [
                &mut marks.command,
                &mut marks.local,
                &mut marks.datagrams,
                &mut marks.deliver,
                &mut marks.recycle,
                &mut marks.transmit,
                &mut marks.backlog,
                &mut marks.events,
                &mut marks.crypto,
                &mut marks.crypto_done,
            ] {
                depth.high_water = 0;
            }
        }
        stats
    }

    /// Every peer's statistics.
    fn peers(&self) -> Vec<PeerStats> {
        self.core
            .peers()
            .filter_map(|peer| self.core.peer_stats(peer))
            .collect()
    }

    /// A snapshot of the engine, counting the failed sends reported so far.
    fn status(&mut self) -> EngineStatus {
        self.send_errors();
        let queues = self.queue_stats(false);
        EngineStatus {
            public_key: self.core.public_key(),
            mtu: self.mtu,
            suspended: *self.suspended.borrow(),
            peers: self.peers(),
            transports: self.transport_stats(),
            drops: self.drops.clone(),
            queues,
            fragments: self
                .fragmenter
                .as_ref()
                .map(Fragmenter::stats)
                .unwrap_or_default(),
            peer_mtus: self.path_mtus.published.borrow().clone(),
            path_mtu: self
                .path_mtus
                .table
                .as_ref()
                .map(|table| table.stats())
                .unwrap_or_default(),
            local_identities: self.core.local_identities().collect(),
        }
    }

    /// The traffic counters of every transport, ordered by id.
    fn transport_stats(&self) -> Vec<TransportStats> {
        self.transports
            .iter()
            .map(|(id, slot)| slot.traffic.stats(*id))
            .collect()
    }

    /// Replies with the counters of the fragmentation stage; all zeros without one.
    fn fragment_stats(&self, reply: oneshot::Sender<FragmentStats>) {
        let stats = self.fragmenter.as_ref().map(Fragmenter::stats);
        let _ = reply.send(stats.unwrap_or_default());
    }

    /// Starts and installs `transport` unless its id is taken.
    fn add_transport(&mut self, transport: NewTransport) -> Result<(), TransportError> {
        if self.transports.contains_key(&transport.id) {
            return Err(TransportError::Duplicate(transport.id));
        }
        let slot = self.start_transport(transport.start, VecDeque::new(), None);
        self.transports.insert(transport.id, slot);
        Ok(())
    }

    /// Hands an injected packet, its receipt marker cleared, or handshake to the core and
    /// sends what it produced.
    fn inject(&mut self, injection: Injection) {
        let now = now();
        let untracked = |mut packet: PacketBuf| {
            packet.set_tracked(false);
            packet
        };
        match injection {
            Injection::Inbound(peer, packet) => self.core.inject_inbound(peer, untracked(packet)),
            Injection::Outbound(packet) => self.core.inject_outbound(untracked(packet), now),
            Injection::OutboundOn(peer, path, packet) => {
                self.core
                    .inject_outbound_on(peer, path, untracked(packet), now);
            }
            Injection::Handshake(peer, path) => self.core.force_handshake(peer, path, now),
            Injection::HandshakeOn(peer, path) => self.core.force_handshake_on(peer, path, now),
        }
        self.drain(false);
    }

    /// Stops and removes transport `id`; the datagrams still queued for it are dropped.
    async fn remove_transport(&mut self, id: TransportId) -> Result<(), TransportError> {
        let old = self
            .transports
            .remove(&id)
            .ok_or(TransportError::Unknown(id))?;
        for (_, data) in old.stop().await {
            self.finish_tracked(&data, DROP_TRANSPORT_REMOVED);
            self.core.recycle(data);
            self.dropped(None, DROP_TRANSPORT_REMOVED);
        }
        Ok(())
    }

    /// Replaces the transport with `transport`'s id by `transport`.
    async fn replace_transport(&mut self, transport: NewTransport) -> Result<(), TransportError> {
        let old = self
            .transports
            .remove(&transport.id)
            .ok_or(TransportError::Unknown(transport.id))?;
        // The datagrams queued for the old transport go out on the new one, and its counters
        // keep running.
        let traffic = Arc::clone(&old.traffic);
        let pending = old.stop().await;
        // The old transmit task is gone with what it held.
        traffic.outstanding.store(0, Ordering::Relaxed);
        let slot = self.start_transport(transport.start, pending, Some(traffic));
        self.transports.insert(transport.id, slot);
        self.drain(false);
        Ok(())
    }

    /// Suspends every I/O task and the owner's own polling, unless already suspended.
    fn suspend(&mut self) {
        self.inline.allowed = false;
        self.sink.allowed = false;
        if !self.suspended.send_replace(true) {
            self.event(Event::Suspended);
        }
    }

    /// Resumes after [`Owner::suspend`] and runs the timers that did not fire meanwhile.
    fn resume(&mut self) {
        if self.suspended.send_replace(false) {
            self.inline.allowed = self.fast_path;
            self.sink.allowed = self.fast_path;
            self.event(Event::Resumed);
            self.core.handle_timeout(now());
            self.drain(true);
        }
    }

    /// Spawns the receive and transmit tasks of a transport, with `pending` datagrams
    /// waiting for its transmit queue, counting into `traffic` (new counters if `None`).
    pub(super) fn start_transport(
        &mut self,
        start: Start,
        pending: VecDeque<Datagram>,
        traffic: Option<Arc<Traffic>>,
    ) -> TransportSlot {
        let traffic = traffic.unwrap_or_else(|| Arc::new(Traffic::new(self.send_errors.clone())));
        let (queue, transmit_rx) = batch_queue(self.queue_capacity, MAX_BATCH);
        let (receive, transmit, try_send, reports) = start(
            self.datagram_tx.clone(),
            transmit_rx,
            self.recycle.clone(),
            Arc::clone(&traffic),
            self.suspended.subscribe(),
        );
        let reports = reports.map(|reports| {
            let (owner, _) = self
                .path_mtus
                .reports
                .get_or_insert_with(|| mpsc::channel(PATH_MTU_REPORTS));
            Task::spawn(forward_path_mtu(
                reports,
                owner.clone(),
                self.suspended.subscribe(),
            ))
        });
        TransportSlot {
            queue,
            staged: Vec::with_capacity(MAX_BATCH),
            pending,
            flush: None,
            receive,
            transmit,
            reports,
            traffic,
            try_send,
            inline: Vec::new(),
            closed: false,
            backoff: Backoff::default(),
        }
    }

    /// Stops every I/O task and the crypto workers and waits until they are gone.
    pub(super) async fn stop(&mut self) {
        if let Some(workers) = self.workers.take() {
            for task in workers.tasks {
                task.stop().await;
            }
        }
        for (_, transport) in std::mem::take(&mut self.transports) {
            transport.stop().await;
        }
        for task in self.tasks.drain(..) {
            task.stop().await;
        }
        // Every tracked packet without a result is reported before the shutdown returns.
        if let Some(receipts) = &self.send_errors.receipts {
            receipts.stop();
        }
    }
}

/// Whether `command` needs settled crypto jobs before it runs. Key/ID and transport-counter
/// queries are outside this set; the listed commands wait for outstanding jobs.
pub(super) const fn settles(command: &Command) -> bool {
    matches!(
        command,
        Command::Config(..)
            | Command::PeerStats(..)
            | Command::PeerHasSession(..)
            | Command::Peers(..)
            | Command::Inject(..)
            | Command::DropCounters(..)
            | Command::Status(..)
            | Command::UnansweredHandshakes(..)
            | Command::TotalUnansweredHandshakes(..)
            | Command::RemoveLocalIdentity(..)
            | Command::LocalIdentities(..)
    )
}
