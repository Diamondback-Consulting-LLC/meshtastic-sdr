"""Meshtastic MeshPacket construction and parsing.

Uses protobuf for the Data payload portion. The over-the-air format is:
  [16-byte header] [encrypted protobuf Data payload]

The Data protobuf contains: portnum, payload bytes, want_response, etc.
"""

import struct
import os
from dataclasses import dataclass, field
from typing import Optional

from .header import MeshtasticHeader, BROADCAST_ADDR, HEADER_SIZE
from .encryption import MeshtasticCrypto
from .portnums import PortNum, decode_text_payload, describe_portnum


# Try to import the official protobuf definitions
try:
    from meshtastic.protobuf.mesh_pb2 import Data
    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False


@dataclass
class DataPayload:
    """Represents the decoded Data portion of a MeshPacket."""
    portnum: int = PortNum.TEXT_MESSAGE_APP
    payload: bytes = b""
    want_response: bool = False
    dest: int = 0
    source: int = 0
    request_id: int = 0
    reply_id: int = 0
    emoji: int = 0

    def to_bytes(self) -> bytes:
        """Serialize to protobuf bytes (if protobuf available) or manual encoding."""
        if HAS_PROTOBUF:
            data = Data()
            data.portnum = self.portnum
            data.payload = self.payload
            if self.want_response:
                data.want_response = True
            if self.dest:
                data.dest = self.dest
            if self.source:
                data.source = self.source
            if self.request_id:
                data.request_id = self.request_id
            if self.reply_id:
                data.reply_id = self.reply_id
            if self.emoji:
                data.emoji = self.emoji
            return data.SerializeToString()
        else:
            return self._manual_encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DataPayload":
        """Deserialize from protobuf bytes."""
        if HAS_PROTOBUF:
            data = Data()
            data.ParseFromString(raw)
            return cls(
                portnum=data.portnum,
                payload=data.payload,
                want_response=data.want_response,
                dest=data.dest,
                source=data.source,
                request_id=data.request_id,
                reply_id=data.reply_id,
                emoji=data.emoji,
            )
        else:
            return cls._manual_decode(raw)

    def _manual_encode(self) -> bytes:
        """Manual protobuf encoding for Data message (no protobuf dependency).

        Data message fields:
          1: portnum (varint)
          2: payload (bytes)
          3: want_response (bool/varint)
          4: dest (fixed32)
          5: source (fixed32)
          6: request_id (fixed32)
          7: reply_id (fixed32)
          8: emoji (fixed32)
        """
        parts = []

        # Field 1: portnum (varint), tag = (1 << 3) | 0 = 0x08
        parts.append(b"\x08" + _encode_varint(self.portnum))

        # Field 2: payload (length-delimited), tag = (2 << 3) | 2 = 0x12
        if self.payload:
            parts.append(b"\x12" + _encode_varint(len(self.payload)) + self.payload)

        # Field 3: want_response (varint), tag = 0x18
        if self.want_response:
            parts.append(b"\x18\x01")

        # Field 4: dest (fixed32), tag = (4 << 3) | 5 = 0x25
        if self.dest:
            parts.append(b"\x25" + struct.pack("<I", self.dest))

        # Field 5: source (fixed32), tag = (5 << 3) | 5 = 0x2d
        if self.source:
            parts.append(b"\x2d" + struct.pack("<I", self.source))

        # Field 6: request_id (fixed32), tag = (6 << 3) | 5 = 0x35
        if self.request_id:
            parts.append(b"\x35" + struct.pack("<I", self.request_id))

        # Field 7: reply_id (fixed32), tag = (7 << 3) | 5 = 0x3d
        if self.reply_id:
            parts.append(b"\x3d" + struct.pack("<I", self.reply_id))

        # Field 8: emoji (fixed32), tag = (8 << 3) | 5 = 0x45
        if self.emoji:
            parts.append(b"\x45" + struct.pack("<I", self.emoji))

        return b"".join(parts)

    @classmethod
    def _manual_decode(cls, raw: bytes) -> "DataPayload":
        """Manual protobuf decoding for Data message."""
        result = cls()
        pos = 0
        while pos < len(raw):
            tag_byte, pos = _decode_varint(raw, pos)
            field_num = tag_byte >> 3
            wire_type = tag_byte & 0x07

            if wire_type == 0:  # varint
                value, pos = _decode_varint(raw, pos)
                if field_num == 1:
                    result.portnum = value
                elif field_num == 3:
                    result.want_response = bool(value)
            elif wire_type == 2:  # length-delimited
                length, pos = _decode_varint(raw, pos)
                data = raw[pos:pos + length]
                pos += length
                if field_num == 2:
                    result.payload = data
            elif wire_type == 5:  # 32-bit fixed
                if pos + 4 > len(raw):
                    break
                value = struct.unpack("<I", raw[pos:pos + 4])[0]
                pos += 4
                if field_num == 4:
                    result.dest = value
                elif field_num == 5:
                    result.source = value
                elif field_num == 6:
                    result.request_id = value
                elif field_num == 7:
                    result.reply_id = value
                elif field_num == 8:
                    result.emoji = value
            elif wire_type == 1:  # 64-bit fixed
                if pos + 8 > len(raw):
                    break
                pos += 8
            else:
                break  # Unknown wire type — cannot determine field size

        return result

    @property
    def text(self) -> str | None:
        """If this is a text message, return the decoded text."""
        if self.portnum == PortNum.TEXT_MESSAGE_APP:
            return decode_text_payload(self.payload)
        return None

    def __repr__(self) -> str:
        port_name = describe_portnum(self.portnum)
        text = self.text
        if text:
            return f"DataPayload(port={port_name}, text={text!r})"
        return f"DataPayload(port={port_name}, payload={len(self.payload)}B)"


@dataclass
class MeshPacket:
    """A complete Meshtastic mesh packet (header + encrypted data)."""

    header: MeshtasticHeader = field(default_factory=MeshtasticHeader)
    data: DataPayload | None = None
    encrypted: bytes = b""

    @classmethod
    def create_text(cls, text: str, from_node: int, to: int = BROADCAST_ADDR,
                    channel: int = 0, hop_limit: int = 3) -> "MeshPacket":
        """Create a text message packet."""
        pkt_id = struct.unpack("<I", os.urandom(4))[0]

        header = MeshtasticHeader(
            to=to,
            from_node=from_node,
            id=pkt_id,
            hop_limit=hop_limit,
            hop_start=hop_limit,
            channel=channel,
        )

        data = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=text.encode("utf-8"),
        )

        return cls(header=header, data=data)

    def encrypt_payload(self, crypto: MeshtasticCrypto) -> bytes:
        """Encrypt the data payload and return the full OTA packet bytes."""
        if self.data is None:
            raise ValueError("No data payload to encrypt")

        plaintext = self.data.to_bytes()
        self.encrypted = crypto.encrypt(
            plaintext, self.header.id, self.header.from_node
        )
        return self.to_bytes()

    def decrypt_payload(self, crypto: MeshtasticCrypto) -> DataPayload:
        """Decrypt the encrypted payload and return the Data."""
        if not self.encrypted:
            raise ValueError("No encrypted payload to decrypt")

        plaintext = crypto.decrypt(
            self.encrypted, self.header.id, self.header.from_node
        )
        self.data = DataPayload.from_bytes(plaintext)
        return self.data

    def to_bytes(self) -> bytes:
        """Serialize the complete packet (header + encrypted payload)."""
        return self.header.pack() + self.encrypted

    @classmethod
    def from_bytes(cls, raw: bytes) -> "MeshPacket":
        """Parse a complete OTA packet from raw bytes."""
        if len(raw) < HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(raw)} bytes")

        header = MeshtasticHeader.unpack(raw[:HEADER_SIZE])
        encrypted = raw[HEADER_SIZE:]

        return cls(header=header, encrypted=encrypted)

    def __repr__(self) -> str:
        if self.data:
            return f"MeshPacket({self.header}, {self.data})"
        return f"MeshPacket({self.header}, encrypted={len(self.encrypted)}B)"


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a protobuf varint starting at pos. Returns (value, new_pos).

    Raises ValueError if the varint is truncated (data ends mid-varint).
    """
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
    if shift > 0:
        raise ValueError("Truncated varint: unexpected end of data")
    return result, pos
