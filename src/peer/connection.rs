//! Peer Connection (Handshake Phase)
//!
//! Represents an in-progress connection before authentication completes.
//! PeerConnection tracks the Noise handshake state and transitions to
//! ActivePeer upon successful authentication.

use crate::transport::{LinkDirection, LinkId, LinkStats};
use crate::PeerIdentity;
use std::fmt;

/// Handshake protocol state machine.
///
/// For Noise KK pattern:
/// - Initiator: SentHello → AwaitingAuth → Complete
/// - Responder: AwaitingHello → SentAuth → Complete
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for initial Hello from remote (responder role).
    AwaitingHello,
    /// Sent Hello, waiting for Auth response (initiator role).
    SentHello,
    /// Received Hello, sent Auth, waiting for AuthAck (responder role).
    SentAuth,
    /// Sent Auth, waiting for AuthAck (initiator role).
    AwaitingAuthAck,
    /// Handshake completed successfully.
    Complete,
    /// Handshake failed.
    Failed,
}

impl HandshakeState {
    /// Check if handshake is still in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            HandshakeState::AwaitingHello
                | HandshakeState::SentHello
                | HandshakeState::SentAuth
                | HandshakeState::AwaitingAuthAck
        )
    }

    /// Check if handshake completed successfully.
    pub fn is_complete(&self) -> bool {
        matches!(self, HandshakeState::Complete)
    }

    /// Check if handshake failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, HandshakeState::Failed)
    }

    /// Check if we are the initiator (sent first message).
    pub fn is_initiator(&self) -> bool {
        matches!(
            self,
            HandshakeState::SentHello | HandshakeState::AwaitingAuthAck
        )
    }

    /// Check if we are the responder (received first message).
    pub fn is_responder(&self) -> bool {
        matches!(
            self,
            HandshakeState::AwaitingHello | HandshakeState::SentAuth
        )
    }
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HandshakeState::AwaitingHello => "awaiting_hello",
            HandshakeState::SentHello => "sent_hello",
            HandshakeState::SentAuth => "sent_auth",
            HandshakeState::AwaitingAuthAck => "awaiting_auth_ack",
            HandshakeState::Complete => "complete",
            HandshakeState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// A connection in the handshake phase, before authentication completes.
///
/// For outbound connections, we know the expected peer identity from config.
/// For inbound connections, we learn the identity during the handshake.
#[derive(Clone, Debug)]
pub struct PeerConnection {
    // === Link Reference ===
    /// The link carrying this connection.
    link_id: LinkId,

    /// Connection direction (we initiated or they initiated).
    direction: LinkDirection,

    // === Handshake State ===
    /// Current handshake state.
    handshake_state: HandshakeState,

    /// Expected peer identity (known for outbound, learned for inbound).
    /// None until we receive their public key in the handshake.
    expected_identity: Option<PeerIdentity>,

    // === Noise Session State ===
    // TODO: Add actual Noise protocol state when implementing crypto
    // noise_state: Option<NoiseSession>,

    // === Timing ===
    /// When the connection attempt started (Unix milliseconds).
    started_at: u64,

    /// When the last handshake message was sent/received.
    last_activity: u64,

    /// Number of retries attempted.
    retry_count: u32,

    // === Statistics ===
    /// Link statistics during handshake.
    link_stats: LinkStats,
}

impl PeerConnection {
    /// Create a new outbound connection (we are initiating).
    ///
    /// For outbound, we know who we're trying to reach from configuration.
    pub fn outbound(
        link_id: LinkId,
        expected_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Outbound,
            handshake_state: HandshakeState::SentHello,
            expected_identity: Some(expected_identity),
            started_at: current_time_ms,
            last_activity: current_time_ms,
            retry_count: 0,
            link_stats: LinkStats::new(),
        }
    }

    /// Create a new inbound connection (they are initiating).
    ///
    /// For inbound, we don't know who they are until they identify in handshake.
    pub fn inbound(link_id: LinkId, current_time_ms: u64) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Inbound,
            handshake_state: HandshakeState::AwaitingHello,
            expected_identity: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,
            retry_count: 0,
            link_stats: LinkStats::new(),
        }
    }

    // === Accessors ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the connection direction.
    pub fn direction(&self) -> LinkDirection {
        self.direction
    }

    /// Get the handshake state.
    pub fn handshake_state(&self) -> HandshakeState {
        self.handshake_state
    }

    /// Get the expected/learned peer identity, if known.
    pub fn expected_identity(&self) -> Option<&PeerIdentity> {
        self.expected_identity.as_ref()
    }

    /// Check if this is an outbound connection.
    pub fn is_outbound(&self) -> bool {
        self.direction == LinkDirection::Outbound
    }

    /// Check if this is an inbound connection.
    pub fn is_inbound(&self) -> bool {
        self.direction == LinkDirection::Inbound
    }

    /// Check if handshake is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.handshake_state.is_in_progress()
    }

    /// Check if handshake completed.
    pub fn is_complete(&self) -> bool {
        self.handshake_state.is_complete()
    }

    /// Check if handshake failed.
    pub fn is_failed(&self) -> bool {
        self.handshake_state.is_failed()
    }

    /// When the connection started.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// When the last activity occurred.
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Connection duration so far.
    pub fn duration(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.started_at)
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_activity)
    }

    /// Number of retries.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.link_stats
    }

    // === State Transitions ===

    /// Record that we sent a Hello message (initiator).
    pub fn mark_hello_sent(&mut self, current_time_ms: u64) {
        self.handshake_state = HandshakeState::SentHello;
        self.last_activity = current_time_ms;
    }

    /// Record that we received a Hello and learned peer identity.
    pub fn mark_hello_received(&mut self, identity: PeerIdentity, current_time_ms: u64) {
        self.expected_identity = Some(identity);
        self.last_activity = current_time_ms;
    }

    /// Record that we sent Auth response (responder).
    pub fn mark_auth_sent(&mut self, current_time_ms: u64) {
        self.handshake_state = HandshakeState::SentAuth;
        self.last_activity = current_time_ms;
    }

    /// Record that we're awaiting AuthAck (initiator).
    pub fn mark_awaiting_auth_ack(&mut self, current_time_ms: u64) {
        self.handshake_state = HandshakeState::AwaitingAuthAck;
        self.last_activity = current_time_ms;
    }

    /// Mark handshake as complete.
    pub fn mark_complete(&mut self, current_time_ms: u64) {
        self.handshake_state = HandshakeState::Complete;
        self.last_activity = current_time_ms;
    }

    /// Mark handshake as failed.
    pub fn mark_failed(&mut self) {
        self.handshake_state = HandshakeState::Failed;
    }

    /// Increment retry counter.
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_activity = current_time_ms;
    }

    // === Validation ===

    /// Check if the connection has timed out.
    pub fn is_timed_out(&self, current_time_ms: u64, timeout_ms: u64) -> bool {
        self.idle_time(current_time_ms) > timeout_ms
    }

    /// Check if max retries exceeded.
    pub fn max_retries_exceeded(&self, max_retries: u32) -> bool {
        self.retry_count >= max_retries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_handshake_state_properties() {
        assert!(HandshakeState::AwaitingHello.is_in_progress());
        assert!(HandshakeState::SentHello.is_in_progress());
        assert!(HandshakeState::SentAuth.is_in_progress());
        assert!(HandshakeState::AwaitingAuthAck.is_in_progress());
        assert!(!HandshakeState::Complete.is_in_progress());
        assert!(!HandshakeState::Failed.is_in_progress());

        assert!(HandshakeState::Complete.is_complete());
        assert!(HandshakeState::Failed.is_failed());

        assert!(HandshakeState::SentHello.is_initiator());
        assert!(HandshakeState::AwaitingAuthAck.is_initiator());
        assert!(HandshakeState::AwaitingHello.is_responder());
        assert!(HandshakeState::SentAuth.is_responder());
    }

    #[test]
    fn test_outbound_connection() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity.clone(), 1000);

        assert!(conn.is_outbound());
        assert!(!conn.is_inbound());
        assert_eq!(conn.handshake_state(), HandshakeState::SentHello);
        assert!(conn.expected_identity().is_some());
        assert_eq!(conn.started_at(), 1000);
        assert_eq!(conn.retry_count(), 0);
    }

    #[test]
    fn test_inbound_connection() {
        let conn = PeerConnection::inbound(LinkId::new(2), 2000);

        assert!(conn.is_inbound());
        assert!(!conn.is_outbound());
        assert_eq!(conn.handshake_state(), HandshakeState::AwaitingHello);
        assert!(conn.expected_identity().is_none());
        assert_eq!(conn.started_at(), 2000);
    }

    #[test]
    fn test_outbound_handshake_flow() {
        let identity = make_peer_identity();
        let mut conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        // Initial state: SentHello
        assert_eq!(conn.handshake_state(), HandshakeState::SentHello);
        assert!(conn.is_in_progress());

        // Received response, awaiting auth ack
        conn.mark_awaiting_auth_ack(1100);
        assert_eq!(conn.handshake_state(), HandshakeState::AwaitingAuthAck);
        assert!(conn.is_in_progress());

        // Complete
        conn.mark_complete(1200);
        assert!(conn.is_complete());
        assert!(!conn.is_in_progress());
    }

    #[test]
    fn test_inbound_handshake_flow() {
        let mut conn = PeerConnection::inbound(LinkId::new(2), 2000);

        // Initial state: AwaitingHello
        assert_eq!(conn.handshake_state(), HandshakeState::AwaitingHello);

        // Received Hello, learned identity
        let identity = make_peer_identity();
        conn.mark_hello_received(identity, 2100);
        assert!(conn.expected_identity().is_some());

        // Sent Auth response
        conn.mark_auth_sent(2200);
        assert_eq!(conn.handshake_state(), HandshakeState::SentAuth);

        // Complete
        conn.mark_complete(2300);
        assert!(conn.is_complete());
    }

    #[test]
    fn test_connection_timing() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        assert_eq!(conn.duration(1500), 500);
        assert_eq!(conn.idle_time(1500), 500);
        assert!(!conn.is_timed_out(1500, 1000));
        assert!(conn.is_timed_out(2500, 1000));
    }

    #[test]
    fn test_retry_tracking() {
        let identity = make_peer_identity();
        let mut conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        assert_eq!(conn.retry_count(), 0);
        assert!(!conn.max_retries_exceeded(3));

        conn.increment_retry();
        conn.increment_retry();
        conn.increment_retry();

        assert_eq!(conn.retry_count(), 3);
        assert!(conn.max_retries_exceeded(3));
    }

    #[test]
    fn test_connection_failure() {
        let identity = make_peer_identity();
        let mut conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        conn.mark_failed();
        assert!(conn.is_failed());
        assert!(!conn.is_in_progress());
        assert!(!conn.is_complete());
    }
}
