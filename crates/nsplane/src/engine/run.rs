//! The owner task's loop: what it waits for and what wakes it.

use std::future::poll_fn;
use std::ops::ControlFlow;
use std::task::{Context, Poll};

use nsplane_core::Event;
use nsplane_packet::{PacketBuf, TransportId};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;

use super::command::settles;
use super::transport::Datagram;
use super::workers::JobBatch;
use super::{Owner, now};
use crate::handle::Command;
use crate::transport::PathMtuReport;

/// What woke the owner task.
enum Wake {
    Command(Option<Command>),
    Datagram(Option<Datagram>),
    Local(Option<PacketBuf>),
    Mtu(Option<u16>),
    /// A transport reported a path MTU.
    PathMtu(Option<PathMtuReport>),
    /// A transmit task reported failed sends.
    SendErrors,
    /// Room in the transmit queue of a transport with waiting datagrams.
    Flush(TransportId, Option<OwnedSemaphorePermit>),
    /// A crypto worker ran a job.
    Crypto(Option<JobBatch>),
    Timer,
}

impl Owner {
    pub(super) async fn run(mut self) {
        loop {
            self.arm_timer();
            let wake = poll_fn(|cx| {
                let wake = self.poll_wake(cx);
                // Nothing else to do: the batched jobs go to the workers now.
                if wake.is_pending() {
                    self.flush_jobs();
                }
                wake
            })
            .await;
            // Datagrams caused by local packets, the network or a timer may overflow the
            // waiting datagrams.
            let droppable = matches!(
                wake,
                Wake::Local(_) | Wake::Datagram(_) | Wake::Crypto(_) | Wake::Timer
            );
            match wake {
                Wake::Command(None) => break,
                Wake::Command(Some(command)) => {
                    if settles(&command) {
                        self.settle().await;
                    }
                    if let ControlFlow::Break(reply) = self.command(command).await {
                        self.stop().await;
                        // The caller may have stopped waiting.
                        let _ = reply.send(());
                        return;
                    }
                }
                Wake::Datagram(Some(datagram)) => self.input_datagrams(datagram),
                // The owner keeps a sender of both queues, so they never close.
                Wake::Datagram(None) | Wake::PathMtu(None) => {}
                Wake::Local(Some(packet)) => self.input_locals(packet),
                Wake::Local(None) => self.local = None,
                Wake::Mtu(Some(mtu)) => {
                    if mtu != self.mtu {
                        self.mtu = mtu;
                        self.event(Event::MtuChanged { mtu });
                        self.recompute_peer_mtus();
                    }
                }
                Wake::PathMtu(Some(report)) => {
                    self.report_path_mtu(&report);
                }
                Wake::Mtu(None) => self.mtu_changes = None,
                Wake::SendErrors => self.send_errors(),
                Wake::Flush(id, permit) => {
                    // No permit: the transmit queue closed, and moving drops the datagrams.
                    if let Some(permit) = permit
                        && let Some(slot) = self.transports.get_mut(&id)
                        && let Some(datagram) = slot.pending.pop_front()
                    {
                        permit.forget();
                        slot.staged.push(datagram);
                        self.staged = true;
                        self.high_water.transmit.record(slot.queued());
                    }
                    self.move_pending(id);
                }
                Wake::Crypto(Some(jobs)) => self.complete_jobs(jobs),
                // The workers are gone (one panicked): the jobs they held are lost.
                Wake::Crypto(None) => self.workers = None,
                Wake::Timer => {
                    let now = now();
                    self.core.handle_timeout(now);
                    if let Some(table) = &mut self.path_mtus.table
                        && table.expire(now)
                    {
                        self.recompute_peer_mtus();
                    }
                }
            }
            self.drain(droppable);
        }
        self.stop().await;
    }

    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        if let Poll::Ready(command) = self.commands.poll_recv(cx) {
            return Poll::Ready(Wake::Command(command));
        }
        // Only handle commands run while suspended.
        if *self.suspended.borrow() {
            return Poll::Pending;
        }
        for (id, slot) in &mut self.transports {
            if let Some(flush) = &mut slot.flush
                && let Poll::Ready(permit) = flush.as_mut().poll(cx)
            {
                slot.flush = None;
                return Poll::Ready(Wake::Flush(*id, permit.ok()));
            }
        }
        if let Some(workers) = &mut self.workers {
            if let Poll::Ready(job) = workers.done.poll_recv(cx) {
                return Poll::Ready(Wake::Crypto(job));
            }
            // Nothing more goes to the workers until they hand jobs back.
            if workers.full() {
                return self.poll_rest(cx);
            }
        }
        self.local_first = !self.local_first;
        if self.local_first {
            if let Poll::Ready(wake) = self.poll_local(cx) {
                return Poll::Ready(wake);
            }
            if let Poll::Ready(wake) = self.poll_datagrams(cx) {
                return Poll::Ready(wake);
            }
        } else {
            if let Poll::Ready(wake) = self.poll_datagrams(cx) {
                return Poll::Ready(wake);
            }
            if let Poll::Ready(wake) = self.poll_local(cx) {
                return Poll::Ready(wake);
            }
        }
        self.poll_rest(cx)
    }

    /// Polls the received datagrams, unless the deliver queue has no room beyond the received
    /// datagrams with the crypto workers ([`Owner::deliver_room`]). Once the sink is closed
    /// every packet is dropped, so nothing is held back.
    fn poll_datagrams(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        if !self.sink.closed && !self.poll_deliver_room(cx) {
            return Poll::Pending;
        }
        self.datagrams.poll_recv(cx).map(Wake::Datagram)
    }

    /// Whether the deliver queue has room beyond the received datagrams with the crypto
    /// workers, if any. Without room and with none of them in flight, waits for
    /// the sink task to make room (a completed job wakes the owner task otherwise).
    fn poll_deliver_room(&mut self, cx: &mut Context<'_>) -> bool {
        if self.deliver_room() > 0 {
            self.deliver_room = None;
            return true;
        }
        if self
            .workers
            .as_ref()
            .is_some_and(|workers| workers.opens > 0)
        {
            return false;
        }
        let deliver = &self.deliver;
        let wait = self
            .deliver_room
            .get_or_insert_with(|| Box::pin(deliver.clone().reserve_owned()));
        match wait.as_mut().poll(cx) {
            Poll::Ready(permit) => {
                self.deliver_room = None;
                // Dropping the permit frees the slot it reserved. A closed queue drops every
                // packet, so it holds nothing back.
                drop(permit);
                true
            }
            Poll::Pending => false,
        }
    }

    /// The free slots of the deliver queue not claimed by received datagrams with the crypto
    /// workers, each of which may deliver a packet.
    pub(super) fn deliver_room(&self) -> usize {
        let opens = self.workers.as_ref().map_or(0, |workers| workers.opens);
        self.deliver.capacity().saturating_sub(opens)
    }

    /// Polls the MTU changes and the timer.
    fn poll_rest(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        if let Some(changes) = &mut self.mtu_changes
            && let Poll::Ready(mtu) = changes.poll_recv(cx)
        {
            return Poll::Ready(Wake::Mtu(mtu));
        }
        if let Some((_, reports)) = &mut self.path_mtus.reports
            && let Poll::Ready(report) = reports.poll_recv(cx)
        {
            return Poll::Ready(Wake::PathMtu(report));
        }
        if self.send_error_signal.poll_recv(cx).is_ready() {
            return Poll::Ready(Wake::SendErrors);
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Wake::Timer);
        }
        Poll::Pending
    }

    /// Polls the source queue, unless there is no room for local packets
    /// ([`Owner::local_room`]).
    fn poll_local(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        let full = self.local_room() == 0;
        match &mut self.local {
            Some(local) if !full => local.poll_recv(cx).map(Wake::Local),
            _ => Poll::Pending,
        }
    }

    /// Arms the timer for the core's next timeout or, if earlier, the next expiry of a
    /// learned path MTU.
    fn arm_timer(&mut self) {
        let mut deadline = self.core.poll_timeout();
        if let Some(expiry) = self
            .path_mtus
            .table
            .as_ref()
            .and_then(|table| table.next_expiry())
        {
            deadline = Some(deadline.map_or(expiry, |deadline| deadline.min(expiry)));
        }
        if let Some(deadline) = deadline {
            let deadline = Instant::from_std(deadline);
            if self.timer.deadline() != deadline {
                self.timer.as_mut().reset(deadline);
            }
        }
    }
}
