"""Random iperf3 traffic generation between node pairs.

Spawns iperf3 clients as background processes in containers. The iperf3
server is already running in each container (started by the Dockerfile
entrypoint).
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field

from .docker_exec import docker_exec_quiet
from .scenario import TrafficConfig
from .topology import SimTopology

log = logging.getLogger(__name__)


@dataclass
class TrafficSession:
    client_node: str
    server_node: str
    started_at: float
    duration_secs: int
    container: str


class TrafficManager:
    """Manages random iperf3 sessions across the mesh."""

    def __init__(
        self,
        topology: SimTopology,
        config: TrafficConfig,
        rng: random.Random,
        down_nodes: set[str] | None = None,
    ):
        self.topology = topology
        self.config = config
        self.rng = rng
        self.down_nodes = down_nodes or set()
        self.active_sessions: list[TrafficSession] = []

    @property
    def active_count(self) -> int:
        return len(self.active_sessions)

    def maybe_spawn(self):
        """Spawn a new iperf3 session if under the concurrency limit."""
        if self.active_count >= self.config.max_concurrent:
            log.debug(
                "At max_concurrent (%d), skipping traffic spawn",
                self.config.max_concurrent,
            )
            return

        node_ids = [nid for nid in self.topology.nodes if nid not in self.down_nodes]
        if len(node_ids) < 2:
            return

        # Pick random client and server (different nodes, both up)
        client, server = self.rng.sample(node_ids, 2)
        server_npub = self.topology.nodes[server].npub
        container = self.topology.container_name(client)

        duration = int(
            self.rng.uniform(
                self.config.duration_secs.min,
                self.config.duration_secs.max,
            )
        )
        streams = self.config.parallel_streams

        # Start iperf3 in background (nohup, stdout to /dev/null)
        cmd = (
            f"nohup iperf3 -c {server_npub}.fips -t {duration} "
            f"-P {streams} > /dev/null 2>&1 &"
        )
        result = docker_exec_quiet(container, cmd)
        if result is not None:
            session = TrafficSession(
                client_node=client,
                server_node=server,
                started_at=time.time(),
                duration_secs=duration,
                container=container,
            )
            self.active_sessions.append(session)
            log.info(
                "Traffic: %s -> %s (%ds, %d streams)",
                client,
                server,
                duration,
                streams,
            )
        else:
            log.warning("Failed to start iperf3 on %s", container)

    def cleanup_expired(self):
        """Remove sessions that have completed (based on time)."""
        now = time.time()
        grace = 5  # seconds after expected completion
        before = len(self.active_sessions)
        self.active_sessions = [
            s
            for s in self.active_sessions
            if now - s.started_at < s.duration_secs + grace
        ]
        removed = before - len(self.active_sessions)
        if removed > 0:
            log.debug("Cleaned up %d expired traffic sessions", removed)

    def stop_all(self):
        """Kill all iperf3 client processes in running containers."""
        seen = set()
        for session in self.active_sessions:
            if session.container not in seen:
                if session.client_node not in self.down_nodes:
                    docker_exec_quiet(
                        session.container,
                        "killall iperf3 2>/dev/null; true",
                    )
                seen.add(session.container)
        self.active_sessions.clear()
