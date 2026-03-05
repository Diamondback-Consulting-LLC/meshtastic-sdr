"""Meshtastic mesh router.

Implements flood routing with hop limit, duplicate detection,
and rebroadcast logic.
"""

import time
from collections import OrderedDict
from dataclasses import dataclass

from ..protocol.header import MeshtasticHeader, BROADCAST_ADDR
from ..protocol.mesh_packet import MeshPacket


# How long to remember packet IDs for duplicate detection (seconds)
DUPLICATE_WINDOW = 600  # 10 minutes
MAX_TRACKED_PACKETS = 1000


@dataclass
class PacketRecord:
    """Record of a seen packet for duplicate detection."""
    packet_id: int
    from_node: int
    timestamp: float
    hop_count: int = 0


class MeshRouter:
    """Flood-based mesh packet router."""

    def __init__(self, local_node_id: int, default_hop_limit: int = 3):
        self.local_node_id = local_node_id
        self.default_hop_limit = min(default_hop_limit, 7)
        self._seen_packets: OrderedDict[tuple[int, int], PacketRecord] = OrderedDict()

    def _cleanup_old_packets(self) -> None:
        """Remove expired packet records."""
        now = time.time()
        cutoff = now - DUPLICATE_WINDOW

        # Remove from front (oldest first) since OrderedDict maintains insertion order
        while self._seen_packets:
            key, record = next(iter(self._seen_packets.items()))
            if record.timestamp < cutoff:
                self._seen_packets.pop(key)
            else:
                break

        # Also trim if too many entries
        while len(self._seen_packets) > MAX_TRACKED_PACKETS:
            self._seen_packets.popitem(last=False)

    def is_duplicate(self, header: MeshtasticHeader) -> bool:
        """Check if we've already seen this packet."""
        self._cleanup_old_packets()
        key = (header.id, header.from_node)
        return key in self._seen_packets

    def record_packet(self, header: MeshtasticHeader) -> None:
        """Record that we've seen this packet."""
        key = (header.id, header.from_node)
        self._seen_packets[key] = PacketRecord(
            packet_id=header.id,
            from_node=header.from_node,
            timestamp=time.time(),
            hop_count=header.hop_start - header.hop_limit,
        )

    def should_rebroadcast(self, packet: MeshPacket) -> bool:
        """Determine if a received packet should be rebroadcast.

        Rules:
        - Don't rebroadcast our own packets
        - Don't rebroadcast duplicates
        - Don't rebroadcast if hop_limit == 0
        - Don't rebroadcast unicast packets not addressed to us
        """
        header = packet.header

        if header.from_node == self.local_node_id:
            return False

        if self.is_duplicate(header):
            return False

        if header.hop_limit <= 0:
            return False

        # For unicast, only rebroadcast if we're not the final destination
        if not header.is_broadcast and header.to == self.local_node_id:
            return False

        return True

    def prepare_rebroadcast(self, packet: MeshPacket) -> MeshPacket:
        """Prepare a packet for rebroadcast (decrement hop_limit)."""
        # Create a new packet with decremented hop limit
        new_header = MeshtasticHeader(
            to=packet.header.to,
            from_node=packet.header.from_node,
            id=packet.header.id,
            hop_limit=packet.header.hop_limit - 1,
            want_ack=packet.header.want_ack,
            via_mqtt=packet.header.via_mqtt,
            hop_start=packet.header.hop_start,
            channel=packet.header.channel,
            next_hop=packet.header.next_hop,
            relay_node=self.local_node_id & 0xFF,
        )

        return MeshPacket(header=new_header, encrypted=packet.encrypted)

    def is_for_us(self, header: MeshtasticHeader) -> bool:
        """Check if this packet is addressed to us (unicast or broadcast)."""
        return header.is_broadcast or header.to == self.local_node_id

    def process_incoming(self, packet: MeshPacket) -> tuple[bool, bool]:
        """Process an incoming packet.

        Returns:
            (is_for_us, should_rebroadcast) tuple
        """
        header = packet.header

        # Check duplicate BEFORE recording (should_rebroadcast also checks)
        duplicate = self.is_duplicate(header)

        if duplicate:
            return False, False

        for_us = self.is_for_us(header)
        rebroadcast = self.should_rebroadcast(packet)

        # Record AFTER rebroadcast check so is_duplicate() inside
        # should_rebroadcast() doesn't falsely mark it as seen
        self.record_packet(header)

        return for_us, rebroadcast
