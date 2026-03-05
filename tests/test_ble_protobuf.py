"""Tests for BLE protobuf codec — ToRadio/FromRadio round-trips and MeshPacket format conversion."""

import sys
import struct
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.ble.protobuf_codec import (
    mesh_packet_to_protobuf,
    mesh_packet_from_protobuf,
    encode_toradio_packet,
    encode_toradio_want_config,
    encode_toradio_disconnect,
    decode_toradio,
    encode_fromradio_packet,
    encode_fromradio_config_complete,
    encode_fromradio_my_info,
    encode_fromradio_node_info,
    decode_fromradio,
)


class TestMeshPacketProtobuf:
    def _make_packet(self, encrypted=True):
        header = MeshtasticHeader(
            to=BROADCAST_ADDR,
            from_node=0xAABBCCDD,
            id=0x12345678,
            hop_limit=3,
            hop_start=3,
            channel=0,
            want_ack=True,
        )
        data = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=b"Hello BLE!",
        )
        pkt = MeshPacket(header=header, data=data)
        if encrypted:
            pkt.encrypted = b"\xde\xad\xbe\xef" * 4
            pkt.data = None
        return pkt

    def test_mesh_packet_roundtrip_encrypted(self):
        """Encode/decode a MeshPacket with encrypted payload."""
        pkt = self._make_packet(encrypted=True)
        encoded = mesh_packet_to_protobuf(pkt)
        assert len(encoded) > 0

        decoded = mesh_packet_from_protobuf(encoded)
        assert decoded.header.from_node == 0xAABBCCDD
        assert decoded.header.to == BROADCAST_ADDR
        assert decoded.header.id == 0x12345678
        assert decoded.header.hop_limit == 3
        assert decoded.header.want_ack is True
        assert decoded.encrypted == b"\xde\xad\xbe\xef" * 4

    def test_mesh_packet_roundtrip_decoded(self):
        """Encode/decode a MeshPacket with decoded (cleartext) Data payload."""
        pkt = self._make_packet(encrypted=False)
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)

        assert decoded.header.from_node == 0xAABBCCDD
        assert decoded.header.id == 0x12345678
        assert decoded.data is not None
        assert decoded.data.portnum == PortNum.TEXT_MESSAGE_APP
        assert decoded.data.payload == b"Hello BLE!"

    def test_mesh_packet_preserves_all_fields(self):
        """All header fields survive encode/decode round-trip."""
        header = MeshtasticHeader(
            to=0x11111111,
            from_node=0x22222222,
            id=0x33333333,
            hop_limit=5,
            want_ack=False,
            hop_start=7,
            channel=42,
        )
        pkt = MeshPacket(header=header, encrypted=b"\x01\x02\x03")
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)

        assert decoded.header.to == 0x11111111
        assert decoded.header.from_node == 0x22222222
        assert decoded.header.id == 0x33333333
        assert decoded.header.hop_limit == 5
        assert decoded.header.hop_start == 7
        assert decoded.header.channel == 42
        assert decoded.encrypted == b"\x01\x02\x03"


class TestToRadio:
    def test_toradio_packet_roundtrip(self):
        """Encode a MeshPacket in ToRadio, decode it back."""
        header = MeshtasticHeader(
            to=BROADCAST_ADDR,
            from_node=0xDEADBEEF,
            id=0xCAFEBABE,
            hop_limit=3,
        )
        pkt = MeshPacket(header=header, encrypted=b"\xAA\xBB\xCC")
        encoded = encode_toradio_packet(pkt)
        decoded = decode_toradio(encoded)

        assert "packet" in decoded
        assert decoded["packet"].header.from_node == 0xDEADBEEF
        assert decoded["packet"].header.id == 0xCAFEBABE
        assert decoded["packet"].encrypted == b"\xAA\xBB\xCC"

    def test_toradio_want_config(self):
        """Encode/decode want_config_id."""
        encoded = encode_toradio_want_config(69420)
        decoded = decode_toradio(encoded)
        assert decoded == {"want_config_id": 69420}

    def test_toradio_disconnect(self):
        """Encode/decode disconnect."""
        encoded = encode_toradio_disconnect()
        decoded = decode_toradio(encoded)
        assert decoded.get("disconnect") is True


class TestFromRadio:
    def test_fromradio_packet_roundtrip(self):
        """Encode a MeshPacket in FromRadio, decode it back."""
        header = MeshtasticHeader(
            to=BROADCAST_ADDR,
            from_node=0x11223344,
            id=0x55667788,
            hop_limit=2,
        )
        pkt = MeshPacket(header=header, encrypted=b"\x01\x02\x03\x04")
        encoded = encode_fromradio_packet(pkt, msg_id=42)
        decoded = decode_fromradio(encoded)

        assert decoded["id"] == 42
        assert "packet" in decoded
        assert decoded["packet"].header.from_node == 0x11223344
        assert decoded["packet"].encrypted == b"\x01\x02\x03\x04"

    def test_fromradio_config_complete(self):
        """Encode/decode config_complete_id."""
        encoded = encode_fromradio_config_complete(69420, msg_id=7)
        decoded = decode_fromradio(encoded)
        assert decoded["id"] == 7
        assert decoded["config_complete_id"] == 69420

    def test_fromradio_my_info(self):
        """Encode/decode MyNodeInfo."""
        encoded = encode_fromradio_my_info(
            node_id=0xAABBCCDD,
            msg_id=1,
            nodedb_count=5,
        )
        decoded = decode_fromradio(encoded)
        assert decoded["id"] == 1
        assert "my_info" in decoded
        assert decoded["my_info"]["my_node_num"] == 0xAABBCCDD
        assert decoded["my_info"]["nodedb_count"] == 5

    def test_fromradio_node_info(self):
        """Encode/decode NodeInfo."""
        encoded = encode_fromradio_node_info(
            node_id=0x12345678,
            long_name="Test Node",
            short_name="TST",
            hw_model=255,
            msg_id=2,
        )
        decoded = decode_fromradio(encoded)
        assert decoded["id"] == 2
        assert "node_info" in decoded
        assert decoded["node_info"]["num"] == 0x12345678
        assert decoded["node_info"]["long_name"] == "Test Node"
        assert decoded["node_info"]["short_name"] == "TST"

    def test_fromradio_empty_data(self):
        """Decode empty data returns minimal dict."""
        decoded = decode_fromradio(b"")
        assert "id" in decoded
