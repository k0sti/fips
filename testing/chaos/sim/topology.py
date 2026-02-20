"""Topology generation: random graphs with connectivity guarantees."""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass, field

from .keys import derive
from .scenario import TopologyConfig


@dataclass
class SimNode:
    node_id: str  # "n01", "n02", ...
    docker_ip: str  # "172.20.0.10", ...
    nsec: str  # 64-char hex
    npub: str  # bech32 npub1...
    peers: list[str] = field(default_factory=list)


@dataclass
class SimTopology:
    nodes: dict[str, SimNode] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)

    def is_connected(self) -> bool:
        """BFS connectivity check."""
        if len(self.nodes) <= 1:
            return True
        start = next(iter(self.nodes))
        visited = set()
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for peer in self.nodes[node].peers:
                if peer not in visited:
                    queue.append(peer)
        return len(visited) == len(self.nodes)

    def neighbors(self, node_id: str) -> list[str]:
        return self.nodes[node_id].peers

    def would_disconnect(self, edge: tuple[str, str]) -> bool:
        """Check if removing this edge would disconnect the graph."""
        a, b = edge
        # Temporarily remove edge
        self.nodes[a].peers.remove(b)
        self.nodes[b].peers.remove(a)
        connected = self.is_connected()
        # Restore
        self.nodes[a].peers.append(b)
        self.nodes[b].peers.append(a)
        return not connected

    def container_name(self, node_id: str) -> str:
        return f"fips-node-{node_id}"


def generate_topology(
    config: TopologyConfig,
    rng: random.Random,
    mesh_name: str,
) -> SimTopology:
    """Generate a topology according to the config."""
    n = config.num_nodes
    subnet_base = config.subnet.rsplit(".", 1)[0]  # "172.20.0"

    # Create nodes with IPs and keys
    nodes: dict[str, SimNode] = {}
    for i in range(n):
        node_id = f"n{i + 1:02d}"
        docker_ip = f"{subnet_base}.{config.ip_start + i}"
        nsec, npub = derive(mesh_name, node_id)
        nodes[node_id] = SimNode(
            node_id=node_id,
            docker_ip=docker_ip,
            nsec=nsec,
            npub=npub,
        )

    node_ids = sorted(nodes.keys())

    # Generate edges
    if config.algorithm == "chain":
        edges = _generate_chain(node_ids)
    elif config.algorithm == "random_geometric":
        radius = config.params.get("radius", 0.5)
        edges = _generate_random_geometric(node_ids, radius, rng)
    elif config.algorithm == "erdos_renyi":
        p = config.params.get("p", 0.3)
        edges = _generate_erdos_renyi(node_ids, p, rng)
    else:
        raise ValueError(f"Unknown algorithm: {config.algorithm}")

    # Build peer lists from edges
    for a, b in edges:
        nodes[a].peers.append(b)
        nodes[b].peers.append(a)

    topo = SimTopology(nodes=nodes, edges=edges)

    # Connectivity check with retry
    if config.ensure_connected:
        max_retries = 50
        attempt = 0
        while not topo.is_connected() and attempt < max_retries:
            attempt += 1
            # Clear and regenerate
            for node in nodes.values():
                node.peers.clear()

            if config.algorithm == "random_geometric":
                edges = _generate_random_geometric(node_ids, radius, rng)
            elif config.algorithm == "erdos_renyi":
                edges = _generate_erdos_renyi(node_ids, p, rng)
            else:
                break  # chain is always connected

            for a, b in edges:
                nodes[a].peers.append(b)
                nodes[b].peers.append(a)

            topo.edges = edges

        if not topo.is_connected():
            raise RuntimeError(
                f"Failed to generate connected topology after {max_retries} attempts"
            )

    return topo


def _generate_chain(node_ids: list[str]) -> set[tuple[str, str]]:
    """Linear topology: n01-n02-n03-..."""
    edges = set()
    for i in range(len(node_ids) - 1):
        edge = _make_edge(node_ids[i], node_ids[i + 1])
        edges.add(edge)
    return edges


def _generate_random_geometric(
    node_ids: list[str],
    radius: float,
    rng: random.Random,
) -> set[tuple[str, str]]:
    """Place nodes randomly in [0,1]^2, connect if distance < radius."""
    positions = {nid: (rng.random(), rng.random()) for nid in node_ids}
    edges = set()
    for i, a in enumerate(node_ids):
        for b in node_ids[i + 1 :]:
            ax, ay = positions[a]
            bx, by = positions[b]
            dist = math.sqrt((ax - bx) ** 2 + (ay - by) ** 2)
            if dist < radius:
                edges.add(_make_edge(a, b))
    return edges


def _generate_erdos_renyi(
    node_ids: list[str],
    p: float,
    rng: random.Random,
) -> set[tuple[str, str]]:
    """Include each edge with probability p."""
    edges = set()
    for i, a in enumerate(node_ids):
        for b in node_ids[i + 1 :]:
            if rng.random() < p:
                edges.add(_make_edge(a, b))
    return edges


def _make_edge(a: str, b: str) -> tuple[str, str]:
    """Canonical edge representation (sorted)."""
    return (min(a, b), max(a, b))
