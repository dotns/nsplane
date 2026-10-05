//! The encryption and decryption of data packets, separable from the core.

use std::fmt;
use std::net::IpAddr;

use nsplane_noise::noise::errors::WireGuardError;
use nsplane_noise::noise::{OpenTicket, Reservation, SealTicket, Tunn, TunnResult};
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
    sealed_outcome(tunnel.encapsulate_in_place(buf.as_packet_mut(), len))
}

/// Opens the transport data message in `buf`, received on `path`, in place.
pub(crate) fn open(tunnel: &mut Tunn, path: Path, buf: &mut PacketBuf) -> Outcome {
    let len = buf.len();
    let result = tunnel.decapsulate_in_place(Some(path.addr), buf.as_packet_mut(), len);
    opened_outcome(result, tunnel.handshake_count())
}

/// Which way a job goes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Direction {
    /// Seals a local packet.
    Seal,
    /// Opens a datagram received on this path.
    Open { path: Path },
}

/// Where a job stands.
#[derive(Debug)]
enum Stage {
    /// To seal with the reserved counter.
    Seal(SealTicket),
    /// Sealed into a datagram of this length, unless it failed.
    Sealed(SealTicket, Result<usize, WireGuardError>),
    /// To open.
    Open(OpenTicket),
    /// Opened: the plaintext length (with padding), unless it failed. Not committed yet.
    Opened(OpenTicket, Result<usize, WireGuardError>),
    /// Finished when the job was handed out: no cryptography to run.
    Done(Outcome),
}

/// The encryption of one local packet or the decryption of one received transport data
/// message, taken out of the core by [`Core::handle_input_deferred`] so that it can run on
/// another thread.
///
/// The core prepares the job on its peer's tunnel when it hands it out: a local packet gets
/// the next counter (nonce) of the current session, in order, and a received message passes
/// the replay check. [`CryptoJob::run`] then does only the cryptography, with the session key
/// the job carries and without touching the tunnel, so any jobs, of one peer or of several,
/// run in parallel. [`Core::complete_job`] finishes the packet in the core: a received
/// message's counter is marked as received there (a replay is rejected even when both copies
/// ran at the same time), a datagram of a session that expired or was replaced in the
/// meantime is dropped, then come counters, roaming, filters and the output.
///
/// Jobs run in any order; complete the jobs of one peer in the order the core handed them
/// out to keep that peer's packets in order. Jobs of different peers may be completed in any
/// order. A job that is never completed is simply lost: its counter is skipped, never reused.
///
/// [`Core::handle_input_deferred`]: crate::Core::handle_input_deferred
/// [`Core::complete_job`]: crate::Core::complete_job
pub struct CryptoJob {
    pub(crate) peer: PeerId,
    pub(crate) buf: PacketBuf,
    pub(crate) direction: Direction,
    stage: Stage,
}

impl fmt::Debug for CryptoJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoJob")
            .field("peer", &self.peer)
            .field("direction", &self.direction)
            .field("len", &self.buf.len())
            .field("ran", &self.ran())
            .finish_non_exhaustive()
    }
}

impl CryptoJob {
    /// Prepares the sealing of the local packet in `buf[DATA_HEADER_SZ..DATA_HEADER_SZ + len]`
    /// on peer `peer`'s `tunnel`: reserves its counter, or finishes it at once without a
    /// session (queued behind a handshake).
    pub(crate) fn seal(peer: PeerId, tunnel: &mut Tunn, mut buf: PacketBuf, len: usize) -> Self {
        let stage = match tunnel.reserve_in_place(buf.as_packet_mut(), len) {
            Reservation::Seal(ticket) => Stage::Seal(ticket),
            Reservation::Done(result) => Stage::Done(sealed_outcome(result)),
        };
        Self {
            peer,
            buf,
            direction: Direction::Seal,
            stage,
        }
    }

    /// Prepares the opening of the transport data message in `buf`, received on `path`, on
    /// peer `peer`'s `tunnel`: checks its session and counter.
    pub(crate) fn open(peer: PeerId, tunnel: &Tunn, buf: PacketBuf, path: Path) -> Self {
        let stage = match tunnel.open_ticket(buf.as_packet()) {
            Ok(ticket) => Stage::Open(ticket),
            Err(e) => Stage::Done(Outcome::Failed(e)),
        };
        Self {
            peer,
            buf,
            direction: Direction::Open { path },
            stage,
        }
    }

    /// The peer whose tunnel the job uses.
    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    /// Seals or opens the packet in place with the key the job carries. Running a job again
    /// does nothing.
    pub fn run(&mut self) {
        self.stage = match std::mem::replace(&mut self.stage, Stage::Done(Outcome::Unexpected)) {
            Stage::Seal(ticket) => {
                let sealed = ticket.seal(self.buf.as_packet_mut()).map(|d| d.len());
                Stage::Sealed(ticket, sealed)
            }
            Stage::Open(ticket) => {
                let opened = ticket.open(self.buf.as_packet_mut());
                Stage::Opened(ticket, opened)
            }
            stage => stage,
        };
    }

    /// Whether the job ran (or needed not run).
    const fn ran(&self) -> bool {
        !matches!(self.stage, Stage::Seal(_) | Stage::Open(_))
    }

    /// The outcome, finishing the job on its peer's `tunnel`, running it first if it has not
    /// run: a sealed datagram stands only while its session is in the tunnel, an opened
    /// message is committed ([`Tunn::commit_open`]).
    pub(crate) fn finish(&mut self, tunnel: &mut Tunn) -> Outcome {
        self.run();
        match std::mem::replace(&mut self.stage, Stage::Done(Outcome::Unexpected)) {
            Stage::Sealed(ticket, sealed) => match sealed {
                // Sealed with the key of a session that expired or was replaced meanwhile.
                Ok(_) if !tunnel.is_live(&ticket) => {
                    Outcome::Failed(WireGuardError::ConnectionExpired)
                }
                Ok(len) => Outcome::Sealed(len),
                Err(e) => Outcome::Failed(e),
            },
            Stage::Opened(ticket, opened) => match opened {
                Ok(plain_len) => {
                    let result = tunnel.commit_open(&ticket, self.buf.as_packet_mut(), plain_len);
                    opened_outcome(result, tunnel.handshake_count())
                }
                Err(e) => Outcome::Failed(e),
            },
            Stage::Done(outcome) => outcome,
            // `run` left neither.
            Stage::Seal(_) | Stage::Open(_) => Outcome::Unexpected,
        }
    }

    /// The failure of a job whose peer is gone, running it first if it has not run; `None`
    /// if it did not fail as far as it got without the tunnel.
    pub(crate) fn failure(&mut self) -> Option<WireGuardError> {
        self.run();
        match std::mem::replace(&mut self.stage, Stage::Done(Outcome::Unexpected)) {
            Stage::Sealed(_, Err(e))
            | Stage::Opened(_, Err(e))
            | Stage::Done(Outcome::Failed(e)) => Some(e),
            _ => None,
        }
    }
}

/// The outcome of sealing a local packet, from the tunnel's `result`.
const fn sealed_outcome(result: TunnResult<'_>) -> Outcome {
    match result {
        TunnResult::WriteToNetwork(datagram) => Outcome::Sealed(datagram.len()),
        TunnResult::Done => Outcome::Queued,
        TunnResult::Err(e) => Outcome::Failed(e),
        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Outcome::Unexpected,
    }
}

/// The outcome of opening a datagram, from the tunnel's `result` and its handshake count
/// right afterwards.
const fn opened_outcome(result: TunnResult<'_>, handshakes: u64) -> Outcome {
    let (plain_len, src) = match result {
        TunnResult::Done => (0, None),
        TunnResult::WriteToTunnelV4(packet, src) => (packet.len(), Some(IpAddr::V4(src))),
        TunnResult::WriteToTunnelV6(packet, src) => (packet.len(), Some(IpAddr::V6(src))),
        TunnResult::Err(e) => return Outcome::Failed(e),
        TunnResult::WriteToNetwork(_) => return Outcome::Unexpected,
    };
    Outcome::Opened {
        plain_len,
        src,
        handshakes,
    }
}
