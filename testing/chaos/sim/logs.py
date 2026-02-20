"""Log collection and post-run analysis."""

from __future__ import annotations

import os
import re
import subprocess
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# Regex to strip ANSI escape codes from tracing output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class AnalysisResult:
    errors: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    sessions_established: list[tuple[str, str]] = field(default_factory=list)
    peers_promoted: list[tuple[str, str]] = field(default_factory=list)
    peer_removals: list[tuple[str, str]] = field(default_factory=list)
    parent_switches: list[tuple[str, str]] = field(default_factory=list)
    mmp_link_metrics: list[tuple[str, str]] = field(default_factory=list)
    mmp_session_metrics: list[tuple[str, str]] = field(default_factory=list)
    handshake_timeouts: list[tuple[str, str]] = field(default_factory=list)
    panics: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=== Simulation Analysis ===",
            "",
            f"Panics:               {len(self.panics)}",
            f"Errors:               {len(self.errors)}",
            f"Warnings:             {len(self.warnings)}",
            f"Sessions established:  {len(self.sessions_established)}",
            f"Peers promoted:        {len(self.peers_promoted)}",
            f"Peer removals:         {len(self.peer_removals)}",
            f"Parent switches:       {len(self.parent_switches)}",
            f"Handshake timeouts:    {len(self.handshake_timeouts)}",
            f"MMP link samples:      {len(self.mmp_link_metrics)}",
            f"MMP session samples:   {len(self.mmp_session_metrics)}",
        ]

        if self.panics:
            lines.append("")
            lines.append("--- PANICS ---")
            for container, line in self.panics[:10]:
                lines.append(f"  [{container}] {line.strip()}")

        if self.errors:
            lines.append("")
            lines.append("--- ERRORS (first 20) ---")
            for container, line in self.errors[:20]:
                lines.append(f"  [{container}] {line.strip()}")

        if self.handshake_timeouts:
            lines.append("")
            lines.append("--- HANDSHAKE TIMEOUTS (first 10) ---")
            for container, line in self.handshake_timeouts[:10]:
                lines.append(f"  [{container}] {line.strip()}")

        lines.append("")
        return "\n".join(lines)


def collect_logs(container_names: list[str], output_dir: str) -> dict[str, str]:
    """Collect all output (stdout + stderr) from all containers."""
    os.makedirs(output_dir, exist_ok=True)
    logs = {}

    for name in container_names:
        try:
            result = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Combine stdout and stderr — tracing may go to either
            # depending on the subscriber configuration.
            # Strip ANSI escape codes for clean log files.
            raw = result.stdout + result.stderr
            log_text = _ANSI_RE.sub("", raw)
            logs[name] = log_text

            path = os.path.join(output_dir, f"{name}.log")
            with open(path, "w") as f:
                f.write(log_text)

        except (subprocess.TimeoutExpired, Exception) as e:
            log.warning("Failed to collect logs from %s: %s", name, e)
            logs[name] = ""

    return logs


def analyze_logs(logs: dict[str, str]) -> AnalysisResult:
    """Parse structured tracing output and categorize events."""
    result = AnalysisResult()

    for container, log_text in logs.items():
        for raw_line in log_text.splitlines():
            # Strip ANSI escape codes for reliable matching
            line = _ANSI_RE.sub("", raw_line)

            # Panics
            if "panicked" in line or "PANIC" in line:
                result.panics.append((container, line))
            # Errors and warnings
            elif " ERROR " in line:
                result.errors.append((container, line))
            elif " WARN " in line:
                result.warnings.append((container, line))

            # Session establishment
            if "Session established" in line:
                result.sessions_established.append((container, line))
            # Peer promotion
            if "Inbound peer promoted" in line or "Outbound handshake completed" in line:
                result.peers_promoted.append((container, line))
            # Peer removal
            if "Peer removed" in line:
                result.peer_removals.append((container, line))
            # Parent switches
            if "Parent switched" in line:
                result.parent_switches.append((container, line))
            # Handshake timeouts
            if "timed out" in line and ("handshake" in line.lower() or "Handshake" in line):
                result.handshake_timeouts.append((container, line))
            # MMP metrics
            if "MMP link metrics" in line:
                result.mmp_link_metrics.append((container, line))
            if "MMP session metrics" in line:
                result.mmp_session_metrics.append((container, line))

    return result


def write_sim_metadata(
    output_dir: str,
    scenario_name: str,
    seed: int,
    num_nodes: int,
    num_edges: int,
    duration_secs: int,
    topology=None,
):
    """Write simulation metadata for reproducibility."""
    path = os.path.join(output_dir, "metadata.txt")
    with open(path, "w") as f:
        f.write(f"scenario: {scenario_name}\n")
        f.write(f"seed: {seed}\n")
        f.write(f"nodes: {num_nodes}\n")
        f.write(f"edges: {num_edges}\n")
        f.write(f"duration_secs: {duration_secs}\n")

        if topology:
            f.write("\nadjacency:\n")
            for nid in sorted(topology.nodes):
                node = topology.nodes[nid]
                peers = sorted(node.peers)
                f.write(f"  {nid} ({node.docker_ip}): {', '.join(peers)}\n")
            f.write("\nedges:\n")
            for a, b in sorted(topology.edges):
                f.write(f"  {a} -- {b}\n")
