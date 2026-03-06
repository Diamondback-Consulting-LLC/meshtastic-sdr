"""Tests for CLI formatting helpers."""

import sys
import time
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.cli.formatting import format_packet, format_status_banner
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.header import MeshtasticHeader
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.mesh.node import NodeInfo


class TestFormatPacket:
    def test_text_packet(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0xAABBCCDD),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"Hello"),
        )
        result = format_packet(pkt)
        assert "!aabbccdd" in result
        assert "Hello" in result
        # Has timestamp
        assert "[" in result and "]" in result

    def test_data_packet(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0x12345678),
            data=DataPayload(portnum=PortNum.POSITION_APP, payload=b"\x00" * 20),
        )
        result = format_packet(pkt)
        assert "!12345678" in result
        assert "POSITION_APP" in result
        assert "20B" in result

    def test_encrypted_packet(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0xDEADBEEF),
            encrypted=b"\x00" * 42,
        )
        result = format_packet(pkt)
        assert "!deadbeef" in result
        assert "encrypted" in result
        assert "42B" in result

    def test_node_name_lookup(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0x11223344),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"hi"),
        )
        node_db = {
            0x11223344: NodeInfo(node_id=0x11223344, long_name="Alice"),
        }
        result = format_packet(pkt, node_db)
        assert "Alice" in result
        assert "!11223344" in result

    def test_node_name_short_name_fallback(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0x11223344),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"hi"),
        )
        node_db = {
            0x11223344: NodeInfo(node_id=0x11223344, short_name="AL"),
        }
        result = format_packet(pkt, node_db)
        assert "AL" in result

    def test_node_db_miss(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0x11223344),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"hi"),
        )
        # Node not in db — should just show hex ID
        node_db = {0xAAAAAAAA: NodeInfo(node_id=0xAAAAAAAA, long_name="Bob")}
        result = format_packet(pkt, node_db)
        assert "!11223344" in result
        assert "Bob" not in result

    def test_no_node_db(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0xCAFEBABE),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"test"),
        )
        result = format_packet(pkt, None)
        assert "!cafebabe" in result


class TestFormatStatusBanner:
    def _make_interface(self):
        iface = MagicMock()
        iface.node.node_id_str = "!abcd1234"
        iface.node.long_name = "TestNode"
        iface.node.short_name = "TST"
        iface.region = "US"
        iface.preset.name = "LONG_FAST"
        iface.preset.spreading_factor = 11
        iface.preset.bandwidth = 250000
        iface.preset.cr_denom = 5
        iface.frequency = 906875000.0
        iface.channel.display_name = "LongFast"
        iface.channel.channel_hash = 0x08
        iface.channel.has_encryption.return_value = True
        iface.radio.device_name = "SimulatedRadio"
        return iface

    def test_contains_node_id(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "!abcd1234" in result

    def test_contains_region(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "US" in result

    def test_contains_preset(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "LONG_FAST" in result

    def test_contains_frequency(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "906.875" in result

    def test_contains_channel(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "LongFast" in result
        assert "0x08" in result

    def test_contains_encryption(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "True" in result

    def test_contains_backend(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "SimulatedRadio" in result

    def test_contains_modem_params(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "SF11" in result
        assert "250kHz" in result
        assert "CR 4/5" in result

    def test_contains_names(self):
        iface = self._make_interface()
        result = format_status_banner(iface)
        assert "TestNode" in result
        assert "TST" in result
