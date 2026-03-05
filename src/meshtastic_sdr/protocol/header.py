"""Meshtastic 16-byte over-the-air packet header.

This is the raw header sent before the encrypted payload in every LoRa packet.
It is NOT protobuf-encoded — it's raw bytes, little-endian.

Header layout (16 bytes):
  Bytes 0-3:   to          (destination node ID, 0xFFFFFFFF = broadcast)
  Bytes 4-7:   from        (sender node ID)
  Bytes 8-11:  id          (packet ID, also used as encryption nonce)
  Byte 12:     flags       (bits 0-2: hop_limit, bit 3: want_ack, bit 4: via_mqtt,
                             bits 5-7: hop_start)
  Byte 13:     channel     (channel hash)
  Byte 14:     next_hop    (next hop node, low byte of node ID)
  Byte 15:     relay_node  (relay node, low byte of node ID)

Reference: meshtastic/firmware/src/mesh/RadioInterface.cpp
"""

import struct
from dataclasses import dataclass

BROADCAST_ADDR = 0xFFFFFFFF
HEADER_SIZE = 16


@dataclass
class MeshtasticHeader:
    to: int = BROADCAST_ADDR
    from_node: int = 0
    id: int = 0
    hop_limit: int = 3
    want_ack: bool = False
    via_mqtt: bool = False
    hop_start: int = 3
    channel: int = 0
    next_hop: int = 0
    relay_node: int = 0

    @property
    def flags(self) -> int:
        f = self.hop_limit & 0x07
        if self.want_ack:
            f |= 0x08
        if self.via_mqtt:
            f |= 0x10
        f |= (self.hop_start & 0x07) << 5
        return f

    @flags.setter
    def flags(self, value: int) -> None:
        self.hop_limit = value & 0x07
        self.want_ack = bool(value & 0x08)
        self.via_mqtt = bool(value & 0x10)
        self.hop_start = (value >> 5) & 0x07

    def pack(self) -> bytes:
        """Pack header into 16 raw bytes (little-endian)."""
        return struct.pack(
            "<IIIBBB B",
            self.to & 0xFFFFFFFF,
            self.from_node & 0xFFFFFFFF,
            self.id & 0xFFFFFFFF,
            self.flags,
            self.channel & 0xFF,
            self.next_hop & 0xFF,
            self.relay_node & 0xFF,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "MeshtasticHeader":
        """Unpack 16 raw bytes into a header object."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header must be {HEADER_SIZE} bytes, got {len(data)}")

        to, from_node, pkt_id, flags, channel, next_hop, relay_node = struct.unpack(
            "<IIIBBB B", data[:HEADER_SIZE]
        )

        hdr = cls(
            to=to,
            from_node=from_node,
            id=pkt_id,
            channel=channel,
            next_hop=next_hop,
            relay_node=relay_node,
        )
        hdr.flags = flags
        return hdr

    @property
    def is_broadcast(self) -> bool:
        return self.to == BROADCAST_ADDR

    def __repr__(self) -> str:
        dest = "broadcast" if self.is_broadcast else f"!{self.to:08x}"
        return (
            f"MeshtasticHeader(to={dest}, from=!{self.from_node:08x}, "
            f"id=0x{self.id:08x}, hop={self.hop_limit}/{self.hop_start}, "
            f"ch={self.channel}, ack={self.want_ack})"
        )
