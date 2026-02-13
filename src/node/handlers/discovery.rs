//! LookupRequest/LookupResponse discovery protocol handlers.
//!
//! Handles coordinate discovery requests: flood-based lookup with TTL,
//! visited filter for loop prevention, and reverse-path forwarding for
//! responses.

use crate::node::{Node, RecentRequest};
use crate::protocol::{LookupRequest, LookupResponse};
use crate::NodeAddr;
use tracing::{debug, trace};

impl Node {
    /// Handle an incoming LookupRequest from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check request_id for duplicates (dedup)
    /// 3. Record request for reverse-path forwarding
    /// 4. Lazy purge expired entries
    /// 5. Check visited filter (loop prevention)
    /// 6. If we're the target, generate and send response
    /// 7. If TTL > 0, forward to peers not in visited filter
    pub(in crate::node) async fn handle_lookup_request(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        let request = match LookupRequest::decode(payload) {
            Ok(req) => req,
            Err(e) => {
                debug!(from = %from, error = %e, "Malformed LookupRequest");
                return;
            }
        };

        let now_ms = Self::now_ms();

        // Dedup: drop if we've already seen this request_id
        if self.recent_requests.contains_key(&request.request_id) {
            trace!(
                request_id = request.request_id,
                from = %from,
                "Duplicate LookupRequest, dropping"
            );
            return;
        }

        // Record for reverse-path forwarding and dedup
        self.recent_requests.insert(
            request.request_id,
            RecentRequest::new(*from, now_ms),
        );

        // Lazy purge expired entries
        self.purge_expired_requests(now_ms);

        // Loop prevention: drop if we've already been visited
        if request.was_visited(self.node_addr()) {
            trace!(
                request_id = request.request_id,
                target = %request.target,
                "Already visited, dropping LookupRequest"
            );
            return;
        }

        // Are we the target?
        if request.target == *self.node_addr() {
            debug!(
                request_id = request.request_id,
                origin = %request.origin,
                "We are the lookup target, generating response"
            );
            self.send_lookup_response(&request).await;
            return;
        }

        // Forward if TTL permits
        if request.can_forward() {
            self.forward_lookup_request(request).await;
        } else {
            trace!(
                request_id = request.request_id,
                target = %request.target,
                "LookupRequest TTL exhausted, not forwarding"
            );
        }
    }

    /// Handle an incoming LookupResponse from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check recent_requests to determine if we originated or are forwarding
    /// 3. If originator: cache target_coords in route_cache
    /// 4. If transit: reverse-path forward to from_peer
    pub(in crate::node) async fn handle_lookup_response(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        let response = match LookupResponse::decode(payload) {
            Ok(resp) => resp,
            Err(e) => {
                debug!(from = %from, error = %e, "Malformed LookupResponse");
                return;
            }
        };

        let now_ms = Self::now_ms();

        // Check if we forwarded this request (transit node) or originated it
        if let Some(recent) = self.recent_requests.get(&response.request_id) {
            // Transit node: reverse-path forward
            let from_peer = recent.from_peer;

            debug!(
                request_id = response.request_id,
                target = %response.target,
                next_hop = %from_peer,
                "Reverse-path forwarding LookupResponse"
            );

            let encoded = response.encode();
            if let Err(e) = self.send_encrypted_link_message(&from_peer, &encoded).await {
                debug!(
                    next_hop = %from_peer,
                    error = %e,
                    "Failed to forward LookupResponse"
                );
            }
        } else {
            // We originated this request — cache the discovered coordinates
            debug!(
                request_id = response.request_id,
                target = %response.target,
                depth = response.target_coords.depth(),
                "Received LookupResponse, caching route"
            );

            self.route_cache.insert(
                response.target,
                response.target_coords,
                now_ms,
            );
        }
    }

    /// Generate and send a LookupResponse when we are the target.
    ///
    /// Signs a proof using our identity and routes the response toward
    /// the origin. The first hop uses find_next_hop; subsequent hops use
    /// reverse-path forwarding via recent_requests.
    async fn send_lookup_response(&mut self, request: &LookupRequest) {
        let our_coords = self.tree_state().my_coords().clone();

        // Sign proof: Identity::sign hashes with SHA-256 internally
        let proof_data = LookupResponse::proof_bytes(request.request_id, &request.target);
        let proof = self.identity().sign(&proof_data);

        let response = LookupResponse::new(
            request.request_id,
            request.target,
            our_coords,
            proof,
        );

        // Route toward origin
        let next_hop_addr = match self.find_next_hop(&request.origin) {
            Some(peer) => *peer.node_addr(),
            None => {
                // Origin might be our direct peer that sent us the request
                // Check if origin == the peer we received from
                if let Some(recent) = self.recent_requests.get(&request.request_id) {
                    recent.from_peer
                } else {
                    debug!(
                        origin = %request.origin,
                        "Cannot route LookupResponse: no path to origin"
                    );
                    return;
                }
            }
        };

        debug!(
            request_id = request.request_id,
            origin = %request.origin,
            next_hop = %next_hop_addr,
            "Sending LookupResponse"
        );

        let encoded = response.encode();
        if let Err(e) = self.send_encrypted_link_message(&next_hop_addr, &encoded).await {
            debug!(
                next_hop = %next_hop_addr,
                error = %e,
                "Failed to send LookupResponse"
            );
        }
    }

    /// Forward a LookupRequest to peers not in the visited filter.
    ///
    /// Decrements TTL, adds self to visited, and sends to all eligible peers.
    async fn forward_lookup_request(&mut self, mut request: LookupRequest) {
        if !request.forward(self.node_addr()) {
            return;
        }

        // Collect peers not in visited filter
        let forward_to: Vec<NodeAddr> = self
            .peers
            .keys()
            .filter(|addr| !request.was_visited(addr))
            .copied()
            .collect();

        if forward_to.is_empty() {
            trace!(
                request_id = request.request_id,
                "No eligible peers to forward LookupRequest"
            );
            return;
        }

        debug!(
            request_id = request.request_id,
            target = %request.target,
            ttl = request.ttl,
            peer_count = forward_to.len(),
            "Forwarding LookupRequest"
        );

        let encoded = request.encode();

        for peer_addr in forward_to {
            if let Err(e) = self.send_encrypted_link_message(&peer_addr, &encoded).await {
                debug!(
                    peer = %peer_addr,
                    error = %e,
                    "Failed to forward LookupRequest to peer"
                );
            }
        }
    }

    /// Initiate a discovery lookup for a target node.
    ///
    /// Creates a LookupRequest and floods it to all peers. The originator
    /// does NOT record the request_id in recent_requests, so when the
    /// response arrives, it's recognized as "our request" and the
    /// target's coordinates are cached in route_cache.
    #[allow(dead_code)] // Called from integration tests; will be used from event loop
    pub(in crate::node) async fn initiate_lookup(&mut self, target: &NodeAddr, ttl: u8) {
        let origin = *self.node_addr();
        let origin_coords = self.tree_state().my_coords().clone();
        let mut request = LookupRequest::generate(*target, origin, origin_coords, ttl);

        // Add ourselves to the visited filter so forwarding nodes
        // won't send the request back to us
        request.visited.insert(&origin);

        debug!(
            request_id = request.request_id,
            target = %target,
            ttl = ttl,
            "Initiating LookupRequest"
        );

        // Send to all peers (flood)
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let encoded = request.encode();

        for peer_addr in peer_addrs {
            if let Err(e) = self.send_encrypted_link_message(&peer_addr, &encoded).await {
                debug!(
                    peer = %peer_addr,
                    error = %e,
                    "Failed to send LookupRequest to peer"
                );
            }
        }
    }

    /// Remove expired entries from the recent_requests cache.
    fn purge_expired_requests(&mut self, current_time_ms: u64) {
        self.recent_requests
            .retain(|_, entry| !entry.is_expired(current_time_ms));
    }

}
