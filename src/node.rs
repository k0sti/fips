//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::config::PeerConfig;
use crate::peer::{
    cross_connection_winner, ActivePeer, PeerConnection, PromotionResult,
};
use crate::transport::{
    packet_channel, Link, LinkDirection, LinkId, PacketRx, PacketTx, TransportAddr,
    TransportHandle, TransportId,
};
use crate::transport::udp::UdpTransport;
use crate::tree::TreeState;
use crate::tun::{run_tun_reader, shutdown_tun_interface, TunDevice, TunError, TunState, TunTx};
use crate::{Config, ConfigError, Identity, IdentityError, NodeId, PeerIdentity};
use std::collections::HashMap;
use std::fmt;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors related to node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("node not started")]
    NotStarted,

    #[error("node already started")]
    AlreadyStarted,

    #[error("node already stopped")]
    AlreadyStopped,

    #[error("transport not found: {0}")]
    TransportNotFound(TransportId),

    #[error("no transport available for type: {0}")]
    NoTransportForType(String),

    #[error("link not found: {0}")]
    LinkNotFound(LinkId),

    #[error("connection not found: {0}")]
    ConnectionNotFound(LinkId),

    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeId),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeId),

    #[error("connection already exists for link: {0}")]
    ConnectionAlreadyExists(LinkId),

    #[error("invalid peer npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },

    #[error("max connections exceeded: {max}")]
    MaxConnectionsExceeded { max: usize },

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },

    #[error("max links exceeded: {max}")]
    MaxLinksExceeded { max: usize },

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("TUN error: {0}")]
    Tun(#[from] TunError),
}

/// Node operational state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    /// Created but not started.
    Created,
    /// Starting up (initializing transports).
    Starting,
    /// Fully operational.
    Running,
    /// Shutting down.
    Stopping,
    /// Stopped.
    Stopped,
}

impl NodeState {
    /// Check if node is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, NodeState::Running)
    }

    /// Check if node can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, NodeState::Created | NodeState::Stopped)
    }

    /// Check if node can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, NodeState::Running)
    }
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NodeState::Created => "created",
            NodeState::Starting => "starting",
            NodeState::Running => "running",
            NodeState::Stopping => "stopping",
            NodeState::Stopped => "stopped",
        };
        write!(f, "{}", s)
    }
}

/// Key for addr_to_link reverse lookup.
type AddrKey = (TransportId, TransportAddr);

/// A running FIPS node instance.
///
/// This is the top-level container holding all node state.
///
/// ## Peer Lifecycle
///
/// Peers go through two phases:
/// 1. **Connection phase** (`connections`): Handshake in progress, indexed by LinkId
/// 2. **Active phase** (`peers`): Authenticated, indexed by NodeId
///
/// The `addr_to_link` map enables dispatching incoming packets to the right
/// connection before authentication completes.
pub struct Node {
    // === Identity ===
    /// This node's cryptographic identity.
    identity: Identity,

    // === Configuration ===
    /// Loaded configuration.
    config: Config,

    // === State ===
    /// Node operational state.
    state: NodeState,

    /// Whether this is a leaf-only node.
    is_leaf_only: bool,

    // === Spanning Tree ===
    /// Local spanning tree state.
    tree_state: TreeState,

    // === Bloom Filter ===
    /// Local Bloom filter state.
    bloom_state: BloomState,

    // === Routing ===
    /// Address -> coordinates cache.
    coord_cache: CoordCache,

    // === Transports & Links ===
    /// Active transports (owned by Node).
    transports: HashMap<TransportId, TransportHandle>,
    /// Active links.
    links: HashMap<LinkId, Link>,
    /// Reverse lookup: (transport_id, remote_addr) -> link_id.
    addr_to_link: HashMap<AddrKey, LinkId>,

    // === Packet Channel ===
    /// Packet sender for transports.
    packet_tx: Option<PacketTx>,
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Connections (Handshake Phase) ===
    /// Pending connections (handshake in progress).
    /// Indexed by LinkId since we don't know the peer's identity yet.
    connections: HashMap<LinkId, PeerConnection>,

    // === Peers (Active Phase) ===
    /// Authenticated peers.
    /// Indexed by NodeId (verified identity).
    peers: HashMap<NodeId, ActivePeer>,

    // === Resource Limits ===
    /// Maximum connections (0 = unlimited).
    max_connections: usize,
    /// Maximum peers (0 = unlimited).
    max_peers: usize,
    /// Maximum links (0 = unlimited).
    max_links: usize,

    // === Counters ===
    /// Next link ID to allocate.
    next_link_id: u64,
    /// Next transport ID to allocate.
    next_transport_id: u32,

    // === TUN Interface ===
    /// TUN device state.
    tun_state: TunState,
    /// TUN interface name (for cleanup).
    tun_name: Option<String>,
    /// TUN packet sender channel.
    tun_tx: Option<TunTx>,
    /// TUN reader thread handle.
    tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    tun_writer_handle: Option<JoinHandle<()>>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        let identity = config.create_identity()?;
        let node_id = *identity.node_id();
        let is_leaf_only = config.is_leaf_only();

        let bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_id)
        } else {
            BloomState::new(node_id)
        };

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_id);
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        info!(
            node_id = %node_id,
            address = %identity.address(),
            "Node initialized as root"
        );

        Ok(Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only,
            tree_state,
            bloom_state,
            coord_cache: CoordCache::with_defaults(),
            transports: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
        })
    }

    /// Create a node with a specific identity.
    pub fn with_identity(identity: Identity, config: Config) -> Self {
        let node_id = *identity.node_id();
        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_id);
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        info!(
            node_id = %node_id,
            address = %identity.address(),
            "Node initialized as root"
        );

        Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state: BloomState::new(node_id),
            coord_cache: CoordCache::with_defaults(),
            transports: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
        }
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_id());
        Ok(node)
    }

    /// Create transport instances from configuration.
    ///
    /// Returns a vector of TransportHandles for all configured transports.
    fn create_transports(&mut self, packet_tx: &PacketTx) -> Vec<TransportHandle> {
        let mut transports = Vec::new();

        // Collect UDP configs with optional names to avoid borrow conflicts
        let udp_instances: Vec<_> = self
            .config
            .transports
            .udp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        // Create UDP transport instances
        for (name, udp_config) in udp_instances {
            let transport_id = self.allocate_transport_id();
            let udp = UdpTransport::new(transport_id, name, udp_config, packet_tx.clone());
            transports.push(TransportHandle::Udp(udp));
        }

        // Future transports follow same pattern:
        // for (name, tcp_config) in self.config.transports.tcp.iter() { ... }

        transports
    }

    /// Find an operational transport that matches the given transport type name.
    fn find_transport_for_type(&self, transport_type: &str) -> Option<TransportId> {
        self.transports
            .iter()
            .find(|(_, handle)| {
                handle.transport_type().name == transport_type && handle.is_operational()
            })
            .map(|(id, _)| *id)
    }

    /// Initiate connections to configured static peers.
    ///
    /// For each peer configured with AutoConnect policy, creates a link and
    /// peer entry. The peer starts in Connecting state; authentication
    /// handshake will be handled by the event loop.
    fn initiate_peer_connections(&mut self) {
        // Collect peer configs to avoid borrow conflicts
        let peer_configs: Vec<_> = self.config.auto_connect_peers().cloned().collect();

        if peer_configs.is_empty() {
            debug!("No static peers configured");
            return;
        }

        info!(count = peer_configs.len(), "Initiating static peer connections");

        for peer_config in peer_configs {
            if let Err(e) = self.initiate_peer_connection(&peer_config) {
                warn!(
                    npub = %peer_config.npub,
                    alias = ?peer_config.alias,
                    error = %e,
                    "Failed to initiate peer connection"
                );
            }
        }
    }

    /// Initiate a connection to a single peer.
    fn initiate_peer_connection(&mut self, peer_config: &PeerConfig) -> Result<(), NodeError> {
        // Parse the peer's npub to get their identity
        let peer_identity = PeerIdentity::from_npub(&peer_config.npub).map_err(|e| {
            NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            }
        })?;

        let peer_node_id = *peer_identity.node_id();

        // Check if peer already exists (fully authenticated)
        if self.peers.contains_key(&peer_node_id) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping"
            );
            return Ok(());
        }

        // Check if connection already in progress to this peer
        let already_connecting = self.connections.values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_id() == &peer_node_id)
                .unwrap_or(false)
        });
        if already_connecting {
            debug!(
                npub = %peer_config.npub,
                "Connection already in progress, skipping"
            );
            return Ok(());
        }

        // Try addresses in priority order until one works
        for addr in peer_config.addresses_by_priority() {
            // Find a transport matching this address type
            let transport_id = match self.find_transport_for_type(&addr.transport) {
                Some(id) => id,
                None => {
                    debug!(
                        transport = %addr.transport,
                        addr = %addr.addr,
                        "No operational transport for address type"
                    );
                    continue;
                }
            };

            // Allocate link ID and create link
            let link_id = self.allocate_link_id();
            let remote_addr = TransportAddr::from_string(&addr.addr);

            // For UDP, links are immediately "connected" (connectionless)
            // TODO: For connection-oriented transports, state would be Connecting
            let link = Link::connectionless(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(100), // Base RTT estimate for UDP
            );

            self.links.insert(link_id, link);

            // Add reverse lookup for packet dispatch
            self.addr_to_link
                .insert((transport_id, remote_addr), link_id);

            // Create connection in handshake phase (outbound knows expected identity)
            let current_time_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let connection = PeerConnection::outbound(link_id, peer_identity.clone(), current_time_ms);

            let alias_display = peer_config
                .alias
                .as_deref()
                .map(|a| format!(" ({})", a))
                .unwrap_or_default();

            info!("Peer connection initiated{}", alias_display);
            info!("  npub: {}", peer_config.npub);
            info!("  node_id: {}", peer_node_id);
            info!("  transport: {}", addr.transport);
            info!("  addr: {}", addr.addr);
            info!("  link_id: {}", link_id);

            self.connections.insert(link_id, connection);

            // Successfully initiated connection via this address
            return Ok(());
        }

        // No address worked
        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get this node's NodeId.
    pub fn node_id(&self) -> &NodeId {
        self.identity.node_id()
    }

    /// Get this node's npub.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    // === Configuration ===

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    // === State ===

    /// Get the node state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Check if node is operational.
    pub fn is_running(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    // === Tree State ===

    /// Get the tree state.
    pub fn tree_state(&self) -> &TreeState {
        &self.tree_state
    }

    /// Get mutable tree state.
    pub fn tree_state_mut(&mut self) -> &mut TreeState {
        &mut self.tree_state
    }

    // === Bloom State ===

    /// Get the Bloom filter state.
    pub fn bloom_state(&self) -> &BloomState {
        &self.bloom_state
    }

    /// Get mutable Bloom filter state.
    pub fn bloom_state_mut(&mut self) -> &mut BloomState {
        &mut self.bloom_state
    }

    // === Coord Cache ===

    /// Get the coordinate cache.
    pub fn coord_cache(&self) -> &CoordCache {
        &self.coord_cache
    }

    /// Get mutable coordinate cache.
    pub fn coord_cache_mut(&mut self) -> &mut CoordCache {
        &mut self.coord_cache
    }

    // === TUN Interface ===

    /// Get the TUN state.
    pub fn tun_state(&self) -> TunState {
        self.tun_state
    }


    // === Resource Limits ===

    /// Set the maximum number of connections (handshake phase).
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Set the maximum number of peers (authenticated).
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max;
    }

    /// Set the maximum number of links.
    pub fn set_max_links(&mut self, max: usize) {
        self.max_links = max;
    }

    // === Counts ===

    /// Number of pending connections (handshake in progress).
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Number of authenticated peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of active transports.
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    // === Transport Management ===

    /// Allocate a new transport ID.
    pub fn allocate_transport_id(&mut self) -> TransportId {
        let id = TransportId::new(self.next_transport_id);
        self.next_transport_id += 1;
        id
    }

    /// Get a transport by ID.
    pub fn get_transport(&self, id: &TransportId) -> Option<&TransportHandle> {
        self.transports.get(id)
    }

    /// Get mutable transport by ID.
    pub fn get_transport_mut(&mut self, id: &TransportId) -> Option<&mut TransportHandle> {
        self.transports.get_mut(id)
    }

    /// Iterate over transport IDs.
    pub fn transport_ids(&self) -> impl Iterator<Item = &TransportId> {
        self.transports.keys()
    }

    /// Get the packet receiver for the event loop.
    pub fn packet_rx(&mut self) -> Option<&mut PacketRx> {
        self.packet_rx.as_mut()
    }

    // === Link Management ===

    /// Allocate a new link ID.
    pub fn allocate_link_id(&mut self) -> LinkId {
        let id = LinkId::new(self.next_link_id);
        self.next_link_id += 1;
        id
    }

    /// Add a link.
    pub fn add_link(&mut self, link: Link) -> Result<(), NodeError> {
        if self.max_links > 0 && self.links.len() >= self.max_links {
            return Err(NodeError::MaxLinksExceeded { max: self.max_links });
        }
        let link_id = link.link_id();
        let transport_id = link.transport_id();
        let remote_addr = link.remote_addr().clone();

        self.links.insert(link_id, link);
        self.addr_to_link.insert((transport_id, remote_addr), link_id);
        Ok(())
    }

    /// Get a link by ID.
    pub fn get_link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Get a mutable link by ID.
    pub fn get_link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Find link ID by transport address.
    pub fn find_link_by_addr(&self, transport_id: TransportId, addr: &TransportAddr) -> Option<LinkId> {
        self.addr_to_link.get(&(transport_id, addr.clone())).copied()
    }

    /// Remove a link.
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        if let Some(link) = self.links.remove(link_id) {
            // Clean up reverse lookup
            let key = (link.transport_id(), link.remote_addr().clone());
            self.addr_to_link.remove(&key);
            Some(link)
        } else {
            None
        }
    }

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Connection Management (Handshake Phase) ===

    /// Add a pending connection.
    pub fn add_connection(&mut self, connection: PeerConnection) -> Result<(), NodeError> {
        let link_id = connection.link_id();

        if self.connections.contains_key(&link_id) {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections > 0 && self.connections.len() >= self.max_connections {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections,
            });
        }

        self.connections.insert(link_id, connection);
        Ok(())
    }

    /// Get a connection by LinkId.
    pub fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.connections.get(link_id)
    }

    /// Get a mutable connection by LinkId.
    pub fn get_connection_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.connections.get_mut(link_id)
    }

    /// Remove a connection.
    pub fn remove_connection(&mut self, link_id: &LinkId) -> Option<PeerConnection> {
        self.connections.remove(link_id)
    }

    /// Iterate over all connections.
    pub fn connections(&self) -> impl Iterator<Item = &PeerConnection> {
        self.connections.values()
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    pub fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Remove the connection from pending
        let connection = self
            .connections
            .remove(&link_id)
            .ok_or(NodeError::ConnectionNotFound(link_id))?;

        let peer_node_id = *verified_identity.node_id();
        let is_outbound = connection.is_outbound();

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_id) {
            let existing_link_id = existing_peer.link_id();

            // Determine which connection wins
            let this_wins = cross_connection_winner(
                self.identity.node_id(),
                &peer_node_id,
                is_outbound,
            );

            if this_wins {
                // This connection wins, replace the existing peer
                let old_peer = self.peers.remove(&peer_node_id).unwrap();
                let loser_link_id = old_peer.link_id();

                // Create new active peer with stats from handshake
                let new_peer = ActivePeer::with_stats(
                    verified_identity,
                    link_id,
                    current_time_ms,
                    connection.link_stats().clone(),
                );

                self.peers.insert(peer_node_id, new_peer.clone());

                info!(
                    node_id = %peer_node_id,
                    winner_link = %link_id,
                    loser_link = %loser_link_id,
                    "Cross-connection resolved: this connection won"
                );

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    peer: new_peer,
                })
            } else {
                // This connection loses, keep existing
                info!(
                    node_id = %peer_node_id,
                    winner_link = %existing_link_id,
                    loser_link = %link_id,
                    "Cross-connection resolved: this connection lost"
                );

                Ok(PromotionResult::CrossConnectionLost {
                    winner_link_id: existing_link_id,
                })
            }
        } else {
            // No cross-connection, normal promotion
            if self.max_peers > 0 && self.peers.len() >= self.max_peers {
                return Err(NodeError::MaxPeersExceeded { max: self.max_peers });
            }

            let new_peer = ActivePeer::with_stats(
                verified_identity,
                link_id,
                current_time_ms,
                connection.link_stats().clone(),
            );

            self.peers.insert(peer_node_id, new_peer.clone());

            info!(
                node_id = %peer_node_id,
                link_id = %link_id,
                "Connection promoted to active peer"
            );

            Ok(PromotionResult::Promoted(new_peer))
        }
    }

    // === Peer Management (Active Phase) ===

    /// Get a peer by NodeId.
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&ActivePeer> {
        self.peers.get(node_id)
    }

    /// Get a mutable peer by NodeId.
    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_id)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_id: &NodeId) -> Option<ActivePeer> {
        self.peers.remove(node_id)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.peers.keys()
    }

    /// Iterate over peers that can send traffic.
    pub fn sendable_peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values().filter(|p| p.can_send())
    }

    /// Number of peers that can send traffic.
    pub fn sendable_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.can_send()).count()
    }

    // === Routing (stubs) ===

    /// Find next hop for a destination (stub).
    ///
    /// Returns the peer that minimizes tree distance to the destination.
    pub fn find_next_hop(&self, _dest_node_id: &NodeId) -> Option<&ActivePeer> {
        // Stub: would implement greedy tree routing
        None
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeId) -> Vec<&ActivePeer> {
        self.peers.values().filter(|p| p.may_reach(dest)).collect()
    }

    // === State Transitions ===

    /// Start the node.
    ///
    /// Initializes the TUN interface (if configured), spawns I/O threads,
    /// and transitions to the Running state.
    pub async fn start(&mut self) -> Result<(), NodeError> {
        if !self.state.can_start() {
            return Err(NodeError::AlreadyStarted);
        }
        self.state = NodeState::Starting;

        // Create packet channel for transport -> Node communication
        const PACKET_BUFFER_SIZE: usize = 1024;
        let (packet_tx, packet_rx) = packet_channel(PACKET_BUFFER_SIZE);
        self.packet_tx = Some(packet_tx.clone());
        self.packet_rx = Some(packet_rx);

        // Initialize transports first (before TUN)
        let transport_handles = self.create_transports(&packet_tx);

        for mut handle in transport_handles {
            let transport_id = handle.transport_id();
            let transport_type = handle.transport_type().name;
            let name = handle.name().map(|s| s.to_string());

            match handle.start().await {
                Ok(()) => {
                    self.transports.insert(transport_id, handle);
                }
                Err(e) => {
                    if let Some(ref n) = name {
                        warn!(transport_type, name = %n, error = %e, "Transport failed to start");
                    } else {
                        warn!(transport_type, error = %e, "Transport failed to start");
                    }
                }
            }
        }

        if !self.transports.is_empty() {
            info!(count = self.transports.len(), "Transports initialized");
        }

        // Initialize TUN interface if configured
        if self.config.tun.enabled {
            let address = *self.identity.address();
            match TunDevice::create(&self.config.tun, address).await {
                Ok(device) => {
                    let mtu = device.mtu();
                    let name = device.name().to_string();
                    let our_addr = *device.address();

                    info!(
                        name = %name,
                        mtu,
                        address = %device.address(),
                        "TUN device active"
                    );

                    // Create writer (dups the fd for independent write access)
                    let (writer, tun_tx) = device.create_writer()?;

                    info!(mtu, name = %name, "Starting TUN reader and writer");

                    // Spawn writer thread
                    let writer_handle = thread::spawn(move || {
                        writer.run();
                    });

                    // Clone tun_tx for the reader
                    let reader_tun_tx = tun_tx.clone();

                    // Spawn reader thread
                    let reader_handle = thread::spawn(move || {
                        run_tun_reader(device, mtu, our_addr, reader_tun_tx);
                    });

                    self.tun_state = TunState::Active;
                    self.tun_name = Some(name);
                    self.tun_tx = Some(tun_tx);
                    self.tun_reader_handle = Some(reader_handle);
                    self.tun_writer_handle = Some(writer_handle);
                }
                Err(e) => {
                    self.tun_state = TunState::Failed;
                    warn!(error = %e, "Failed to initialize TUN, continuing without it");
                }
            }
        }

        // Connect to static peers (step 5 per architecture doc)
        self.initiate_peer_connections();

        self.state = NodeState::Running;
        info!(
            state = %self.state,
            transports = self.transports.len(),
            connections = self.connections.len(),
            "Node started"
        );
        Ok(())
    }

    /// Stop the node.
    ///
    /// Shuts down TUN interface, stops I/O threads, and transitions to
    /// the Stopped state.
    pub async fn stop(&mut self) -> Result<(), NodeError> {
        if !self.state.can_stop() {
            return Err(NodeError::NotStarted);
        }
        self.state = NodeState::Stopping;
        info!(state = %self.state, "Node stopping");

        // Shutdown transports first (they're packet producers)
        let transport_ids: Vec<_> = self.transports.keys().cloned().collect();
        for transport_id in transport_ids {
            if let Some(mut handle) = self.transports.remove(&transport_id) {
                let transport_type = handle.transport_type().name;
                match handle.stop().await {
                    Ok(()) => {
                        info!(transport_id = %transport_id, transport_type, "Transport stopped");
                    }
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            transport_type,
                            error = %e,
                            "Transport stop failed"
                        );
                    }
                }
            }
        }

        // Drop packet channels
        self.packet_tx.take();
        self.packet_rx.take();

        // Shutdown TUN interface
        if let Some(name) = self.tun_name.take() {
            info!(name = %name, "Shutting down TUN interface");

            // Drop the tun_tx to signal the writer to stop
            self.tun_tx.take();

            // Delete the interface (causes reader to get EFAULT)
            if let Err(e) = shutdown_tun_interface(&name).await {
                warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
            }

            // Wait for threads to finish
            if let Some(handle) = self.tun_reader_handle.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tun_writer_handle.take() {
                let _ = handle.join();
            }

            self.tun_state = TunState::Disabled;
        }

        self.state = NodeState::Stopped;
        info!(state = %self.state, "Node stopped");
        Ok(())
    }

    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.tun_tx.as_ref()
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("node_id", self.node_id())
            .field("state", &self.state)
            .field("is_leaf_only", &self.is_leaf_only)
            .field("connections", &self.connection_count())
            .field("peers", &self.peer_count())
            .field("links", &self.link_count())
            .field("transports", &self.transport_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{LinkDirection, TransportAddr};
    use std::time::Duration;

    fn make_node() -> Node {
        let config = Config::new();
        Node::new(config).unwrap()
    }

    #[allow(dead_code)]
    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_node_creation() {
        let node = make_node();

        assert_eq!(node.state(), NodeState::Created);
        assert_eq!(node.peer_count(), 0);
        assert_eq!(node.connection_count(), 0);
        assert_eq!(node.link_count(), 0);
        assert!(!node.is_leaf_only());
    }

    #[test]
    fn test_node_with_identity() {
        let identity = Identity::generate();
        let expected_node_id = *identity.node_id();
        let config = Config::new();

        let node = Node::with_identity(identity, config);

        assert_eq!(node.node_id(), &expected_node_id);
    }

    #[test]
    fn test_node_leaf_only() {
        let config = Config::new();
        let node = Node::leaf_only(config).unwrap();

        assert!(node.is_leaf_only());
        assert!(node.bloom_state().is_leaf_only());
    }

    #[tokio::test]
    async fn test_node_state_transitions() {
        let mut node = make_node();

        assert!(!node.is_running());
        assert!(node.state().can_start());

        node.start().await.unwrap();
        assert!(node.is_running());
        assert!(!node.state().can_start());

        node.stop().await.unwrap();
        assert!(!node.is_running());
        assert_eq!(node.state(), NodeState::Stopped);
    }

    #[tokio::test]
    async fn test_node_double_start() {
        let mut node = make_node();
        node.start().await.unwrap();

        let result = node.start().await;
        assert!(matches!(result, Err(NodeError::AlreadyStarted)));

        // Clean up
        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_node_stop_not_started() {
        let mut node = make_node();

        let result = node.stop().await;
        assert!(matches!(result, Err(NodeError::NotStarted)));
    }

    #[test]
    fn test_node_link_management() {
        let mut node = make_node();

        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        node.add_link(link).unwrap();
        assert_eq!(node.link_count(), 1);

        assert!(node.get_link(&link_id).is_some());

        // Test addr_to_link lookup
        assert_eq!(
            node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")),
            Some(link_id)
        );

        node.remove_link(&link_id);
        assert_eq!(node.link_count(), 0);

        // Lookup should be gone
        assert!(node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")).is_none());
    }

    #[test]
    fn test_node_link_limit() {
        let mut node = make_node();
        node.set_max_links(2);

        for i in 0..2 {
            let link_id = node.allocate_link_id();
            let link = Link::connectionless(
                link_id,
                TransportId::new(1),
                TransportAddr::from_string(&format!("test{}", i)),
                LinkDirection::Outbound,
                Duration::from_millis(50),
            );
            node.add_link(link).unwrap();
        }

        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string("test_extra"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        let result = node.add_link(link);
        assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
    }

    #[test]
    fn test_node_connection_management() {
        let mut node = make_node();

        let identity = make_peer_identity();
        let link_id = LinkId::new(1);
        let conn = PeerConnection::outbound(link_id, identity, 1000);

        node.add_connection(conn).unwrap();
        assert_eq!(node.connection_count(), 1);

        assert!(node.get_connection(&link_id).is_some());

        node.remove_connection(&link_id);
        assert_eq!(node.connection_count(), 0);
    }

    #[test]
    fn test_node_connection_duplicate() {
        let mut node = make_node();

        let identity = make_peer_identity();
        let link_id = LinkId::new(1);
        let conn1 = PeerConnection::outbound(link_id, identity.clone(), 1000);
        let conn2 = PeerConnection::outbound(link_id, identity, 2000);

        node.add_connection(conn1).unwrap();
        let result = node.add_connection(conn2);

        assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
    }

    #[test]
    fn test_node_promote_connection() {
        let mut node = make_node();

        let identity = make_peer_identity();
        let node_id = *identity.node_id();
        let link_id = LinkId::new(1);
        let conn = PeerConnection::outbound(link_id, identity.clone(), 1000);

        node.add_connection(conn).unwrap();
        assert_eq!(node.connection_count(), 1);
        assert_eq!(node.peer_count(), 0);

        let result = node.promote_connection(link_id, identity, 2000).unwrap();

        assert!(matches!(result, PromotionResult::Promoted(_)));
        assert_eq!(node.connection_count(), 0);
        assert_eq!(node.peer_count(), 1);

        let peer = node.get_peer(&node_id).unwrap();
        assert_eq!(peer.authenticated_at(), 2000);
    }

    #[test]
    fn test_node_cross_connection_resolution() {
        let mut node = make_node();

        // First connection and promotion (becomes active peer)
        let identity = make_peer_identity();
        let node_id = *identity.node_id();
        let link_id1 = LinkId::new(1);
        let conn1 = PeerConnection::outbound(link_id1, identity.clone(), 1000);

        node.add_connection(conn1).unwrap();
        node.promote_connection(link_id1, identity.clone(), 1500).unwrap();

        assert_eq!(node.peer_count(), 1);
        assert_eq!(node.get_peer(&node_id).unwrap().link_id(), link_id1);

        // Second connection (simulates cross-connection scenario)
        let link_id2 = LinkId::new(2);
        let conn2 = PeerConnection::inbound(link_id2, 2000);

        node.add_connection(conn2).unwrap();

        // Promote second connection - tie-breaker determines outcome
        let result = node.promote_connection(link_id2, identity, 2500).unwrap();

        // One connection should win, one should lose
        match result {
            PromotionResult::CrossConnectionWon { loser_link_id, .. } => {
                assert_eq!(loser_link_id, link_id1);
                assert_eq!(node.get_peer(&node_id).unwrap().link_id(), link_id2);
            }
            PromotionResult::CrossConnectionLost { winner_link_id } => {
                assert_eq!(winner_link_id, link_id1);
                assert_eq!(node.get_peer(&node_id).unwrap().link_id(), link_id1);
            }
            PromotionResult::Promoted(_) => {
                panic!("Expected cross-connection, got normal promotion");
            }
        }

        // Still only one peer
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn test_node_peer_limit() {
        let mut node = make_node();
        node.set_max_peers(2);

        // Add two peers via promotion
        for i in 0..2 {
            let identity = make_peer_identity();
            let link_id = LinkId::new(i as u64 + 1);
            let conn = PeerConnection::outbound(link_id, identity.clone(), 1000);
            node.add_connection(conn).unwrap();
            node.promote_connection(link_id, identity, 2000).unwrap();
        }

        assert_eq!(node.peer_count(), 2);

        // Third should fail
        let identity = make_peer_identity();
        let link_id = LinkId::new(3);
        let conn = PeerConnection::outbound(link_id, identity.clone(), 3000);
        node.add_connection(conn).unwrap();

        let result = node.promote_connection(link_id, identity, 4000);
        assert!(matches!(result, Err(NodeError::MaxPeersExceeded { .. })));
    }

    #[test]
    fn test_node_link_id_allocation() {
        let mut node = make_node();

        let id1 = node.allocate_link_id();
        let id2 = node.allocate_link_id();
        let id3 = node.allocate_link_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_eq!(id1.as_u64(), 1);
        assert_eq!(id2.as_u64(), 2);
        assert_eq!(id3.as_u64(), 3);
    }

    #[test]
    fn test_node_transport_management() {
        let mut node = make_node();

        // Initially no transports (transports are created during start())
        assert_eq!(node.transport_count(), 0);

        // Allocating IDs still works
        let id1 = node.allocate_transport_id();
        let id2 = node.allocate_transport_id();
        assert_ne!(id1, id2);

        // get_transport returns None when transport doesn't exist
        assert!(node.get_transport(&id1).is_none());
        assert!(node.get_transport(&id2).is_none());

        // transport_ids() iterator is empty
        assert_eq!(node.transport_ids().count(), 0);
    }

    #[test]
    fn test_node_sendable_peers() {
        let mut node = make_node();

        // Add a healthy peer
        let identity1 = make_peer_identity();
        let node_id1 = *identity1.node_id();
        let link_id1 = LinkId::new(1);
        let conn1 = PeerConnection::outbound(link_id1, identity1.clone(), 1000);
        node.add_connection(conn1).unwrap();
        node.promote_connection(link_id1, identity1, 2000).unwrap();

        // Add another peer and mark it stale (still sendable)
        let identity2 = make_peer_identity();
        let link_id2 = LinkId::new(2);
        let conn2 = PeerConnection::outbound(link_id2, identity2.clone(), 1000);
        node.add_connection(conn2).unwrap();
        node.promote_connection(link_id2, identity2, 2000).unwrap();

        // Add a third peer and mark it disconnected (not sendable)
        let identity3 = make_peer_identity();
        let node_id3 = *identity3.node_id();
        let link_id3 = LinkId::new(3);
        let conn3 = PeerConnection::outbound(link_id3, identity3.clone(), 1000);
        node.add_connection(conn3).unwrap();
        node.promote_connection(link_id3, identity3, 2000).unwrap();
        node.get_peer_mut(&node_id3).unwrap().mark_disconnected();

        assert_eq!(node.peer_count(), 3);
        assert_eq!(node.sendable_peer_count(), 2);

        let sendable: Vec<_> = node.sendable_peers().collect();
        assert_eq!(sendable.len(), 2);
        assert!(sendable.iter().any(|p| p.node_id() == &node_id1));
    }
}
