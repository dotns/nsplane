//! The encryption and decryption of data packets, separable from the core.

use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use nsplane_noise::noise::errors::WireGuardError;
use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_packet::{PacketBuf, Path, PeerId};

/// What sealing a local packet or opening a datagram resulted in.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Sealed into a datagram of this length: transport data, or a handshake initiation when
    /// the packet was queued for lack of a session.
    Sealed(usize),
    /// Queued behind a handshake in progress.
    Queued,
    /// Opened: the plaintext length, its source address (`None` for a keepalive) and the
    /// tunnel's handshake count right afterwards.
    Opened {
        plain_len: usize,
        src: Option<IpAddr>,
        handshakes: u64,
    },
    Failed(WireGuardError),
    /// The tunnel answered with a result that does not fit the operation.
    Unexpected,
}

/// Seals the local packet in `buf[DATA_HEADER_SZ..DATA_HEADER_SZ + len]` in place.
pub(crate) fn seal(tunnel: &mut Tunn, buf: &mut PacketBuf, len: usize) -> Outcome {
    match tunnel.encapsulate_in_place(buf.as_packet_mut(), len) {
        TunnResult::WriteToNetwork(datagram) => Outcome::Sealed(datagram.len()),
        TunnResult::Done => Outcome::Queued,
        TunnResult::Err(e) => Outcome::Failed(e),
        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Outcome::Unexpected,
    }
}

/// Opens the transport data message in `buf`, received on `path`, in place.
pub(crate) fn open(tunnel: &mut Tunn, path: Path, buf: &mut PacketBuf) -> Outcome {
    let len = buf.len();
    let (plain_len, src) =
        match tunnel.decapsulate_in_place(Some(path.addr), buf.as_packet_mut(), len) {
            TunnResult::Done => (0, None),
            TunnResult::WriteToTunnelV4(packet, src) => (packet.len(), Some(IpAddr::V4(src))),
            TunnResult::WriteToTunnelV6(packet, src) => (packet.len(), Some(IpAddr::V6(src))),
            TunnResult::Err(e) => return Outcome::Failed(e),
            TunnResult::WriteToNetwork(_) => return Outcome::Unexpected,
        };
    Outcome::Opened {
        plain_len,
        src,
        handshakes: tunnel.handshake_count(),
    }
}

/// Which way a job goes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Direction {
    /// Seals the local packet of this length.
    Seal { len: usize },
    /// Opens a datagram received on this path.
    Open { path: Path },
}

/// The encryption of one local packet or the decryption of one received transport data
/// message, taken out of the core by [`Core::handle_input_deferred`] so that it can run on
/// another thread.
///
/// [`CryptoJob::run`] does the cryptography: it locks only the tunnel of [`CryptoJob::peer`],
/// so jobs of different peers run in parallel. [`Core::complete_job`] then finishes the
/// packet in the core (counters, roaming, filters, the output). Jobs of one peer must run in
/// the order the core handed them out to keep that peer's packets in order; jobs may be
/// completed in any order across peers.
///
/// [`Core::handle_input_deferred`]: crate::Core::handle_input_deferred
/// [`Core::complete_job`]: crate::Core::complete_job
pub struct CryptoJob {
    pub(crate) peer: PeerId,
    tunnel: Arc<Mutex<Tunn>>,
    pub(crate) buf: PacketBuf,
    pub(crate) direction: Direction,
    /// `None` until the job ran.
    outcome: Option<Outcome>,
}

impl fmt::Debug for CryptoJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoJob")
            .field("peer", &self.peer)
            .field("direction", &self.direction)
            .field("len", &self.buf.len())
            .field("ran", &self.outcome.is_some())
            .finish_non_exhaustive()
    }
}

impl CryptoJob {
    pub(crate) const fn new(
        peer: PeerId,
        tunnel: Arc<Mutex<Tunn>>,
        buf: PacketBuf,
        direction: Direction,
    ) -> Self {
        Self {
            peer,
            tunnel,
            buf,
            direction,
            outcome: None,
        }
    }

    /// The peer whose tunnel the job uses.
    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    /// Seals or opens the packet in place, under the lock of the peer's tunnel. Running a
    /// job again does nothing.
    pub fn run(&mut self) {
        if self.outcome.is_none() {
            self.outcome = Some(self.compute());
        }
    }

    /// The outcome, running the job first if it has not run.
    pub(crate) fn take_outcome(&mut self) -> Outcome {
        self.outcome.take().unwrap_or_else(|| self.compute())
    }

    fn compute(&mut self) -> Outcome {
        // A job that panicked while holding the lock leaves a usable tunnel behind.
        let mut tunnel = self.tunnel.lock().unwrap_or_else(PoisonError::into_inner);
        match self.direction {
            Direction::Seal { len } => seal(&mut tunnel, &mut self.buf, len),
            Direction::Open { path } => open(&mut tunnel, path, &mut self.buf),
        }
    }
}
