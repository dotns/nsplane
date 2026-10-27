//! Bounded label tombstones and queue-position fences.

use std::collections::{HashSet, VecDeque};
use std::num::NonZeroU64;

use crate::flow::{Fence, MAX_FENCES, RetirementOutcome};
use crate::stats;

use super::Driver;
use super::wire::placeholder;

/// Driver-owned ingress positions need no synchronization on the packet path.
/// A fence covers the queue observed at retirement, independently of tombstone eviction.
pub(super) struct Labels {
    revoked: HashSet<NonZeroU64>,
    order: VecDeque<NonZeroU64>,
    limit: usize,
    received: u64,
    fences: Vec<(NonZeroU64, u64)>,
}

impl Labels {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            revoked: HashSet::new(),
            order: VecDeque::new(),
            limit,
            received: 0,
            fences: Vec::new(),
        }
    }

    pub(super) fn revoked(&self, label: NonZeroU64) -> bool {
        self.revoked.contains(&label)
    }

    /// Advances one queue position and reports whether its label is retired.
    pub(super) fn ingest(&mut self, label: Option<NonZeroU64>) -> bool {
        let position = self.received;
        self.received += 1;
        if !self.fences.is_empty() {
            self.fences.retain(|&(_, end)| position < end);
        }
        label.is_some_and(|label| {
            self.revoked(label)
                || self
                    .fences
                    .iter()
                    .any(|&(held, end)| held == label && position < end)
        })
    }

    fn retire(&mut self, label: NonZeroU64, queued: usize) -> bool {
        self.fences.retain(|&(_, end)| self.received < end);
        if self.revoked.insert(label) {
            self.order.push_back(label);
            if self.order.len() > self.limit
                && let Some(oldest) = self.order.pop_front()
            {
                self.revoked.remove(&oldest);
            }
        }
        if queued == 0 {
            return true;
        }
        let end = self.received + queued as u64;
        if let Some((_, held_end)) = self.fences.iter_mut().find(|(held, _)| *held == label) {
            *held_end = (*held_end).max(end);
            return true;
        }
        if self.fences.len() >= MAX_FENCES {
            return false;
        }
        self.fences.push((label, end));
        true
    }
}

impl Driver {
    /// Retires state even if either bounded queue fence cannot be installed.
    pub(super) fn retire_label(&mut self, label: NonZeroU64) -> RetirementOutcome {
        let queued = self.ingress.len() + usize::from(self.carried.is_some());
        let ingress_fenced = self.labels.retire(label, queued);
        let flows = self.revocations.labeled(label);
        for flow in &flows {
            flow.mark_revoked();
            self.retire(flow, false);
        }
        if let Some(reassembler) = self.reassembler.as_mut() {
            reassembler.discard_tagged(label);
        }
        self.device
            .rx_queue
            .retain(|packet| packet.tag() != Some(label));
        let mut dropped = 0;
        for packet in &mut self.device.tx_queue {
            if packet.tag() == Some(label) {
                *packet = placeholder();
                dropped += 1;
            }
        }
        self.marks
            .retain(|(_, flow)| flow.ingress_label() != Some(label));
        stats::add(&self.stats.retired, dropped);
        let egress_fenced = self.egress.capacity() == self.egress.max_capacity()
            || self.fences.insert(Fence::Label {
                label,
                end: self.sent,
            });
        let outcome = if ingress_fenced && egress_fenced {
            RetirementOutcome::Retired
        } else {
            RetirementOutcome::Failed
        };
        for flow in flows {
            flow.finish(outcome);
        }
        outcome
    }
}
