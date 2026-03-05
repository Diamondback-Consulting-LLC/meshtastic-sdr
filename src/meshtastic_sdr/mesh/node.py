"""Meshtastic local node identity and node database.

Manages the local node's identity and tracks discovered mesh nodes.
"""

import os
import struct
import time
from dataclasses import dataclass, field


@dataclass
class NodeInfo:
    """Information about a discovered mesh node."""
    node_id: int
    long_name: str = ""
    short_name: str = ""
    hardware_model: int = 0
    last_heard: float = 0.0
    snr: float = 0.0
    rssi: int = 0

    @property
    def node_id_str(self) -> str:
        return f"!{self.node_id:08x}"

    def __repr__(self) -> str:
        name = self.long_name or self.short_name or self.node_id_str
        return f"NodeInfo({name}, id={self.node_id_str})"


class MeshNode:
    """Local mesh node identity and node database."""

    def __init__(self, node_id: int | None = None, long_name: str = "SDR Node",
                 short_name: str = "SDR"):
        """Initialize local node.

        Args:
            node_id: 4-byte node ID. If None, generates a random one.
            long_name: Human-readable name (up to 39 chars)
            short_name: Short name (up to 4 chars)
        """
        if node_id is None:
            # Generate random node ID (avoiding reserved ranges)
            node_id = struct.unpack("<I", os.urandom(4))[0]
            # Ensure it's not broadcast (0xFFFFFFFF) or zero
            node_id = node_id & 0xFFFFFFFF
            if node_id == 0xFFFFFFFF or node_id == 0:
                node_id = 1

        self.node_id = node_id
        self.long_name = long_name
        self.short_name = short_name[:4]
        self._node_db: dict[int, NodeInfo] = {}

    @property
    def node_id_str(self) -> str:
        return f"!{self.node_id:08x}"

    def update_node(self, node_id: int, **kwargs) -> NodeInfo:
        """Update or create a node in the database."""
        if node_id not in self._node_db:
            self._node_db[node_id] = NodeInfo(node_id=node_id)

        info = self._node_db[node_id]
        info.last_heard = time.time()

        for key, value in kwargs.items():
            if hasattr(info, key):
                setattr(info, key, value)

        return info

    def get_node(self, node_id: int) -> NodeInfo | None:
        return self._node_db.get(node_id)

    @property
    def known_nodes(self) -> list[NodeInfo]:
        return list(self._node_db.values())

    @property
    def num_nodes(self) -> int:
        return len(self._node_db)

    def __repr__(self) -> str:
        return f"MeshNode({self.node_id_str}, name={self.long_name!r}, nodes={self.num_nodes})"
