"""Tests for AdminMessage handling in BLE Gateway mode."""

import sys
sys.path.insert(0, "src")

import pytest

from meshtastic_sdr.ble.admin_handler import (
    decode_admin_message,
    _encode_config_response,
    encode_owner_response,
    encode_channel_response,
    AdminHandler,
    REGION_CODE_MAP,
    MODEM_PRESET_MAP,
    CONFIG_LORA,
)
from meshtastic_sdr.ble.protobuf_codec import encode_config_lora
from meshtastic_sdr.ble.constants import REGION_NAME_TO_CODE, PRESET_NAME_TO_CODE
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload, _encode_varint
from meshtastic_sdr.protocol.header import MeshtasticHeader
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.protocol.channels import ChannelConfig
from meshtastic_sdr.protocol.encryption import DEFAULT_KEY
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.config import SDRConfig


class TestDecodeAdminMessage:
    def test_decode_get_config_request_lora(self):
        # AdminMessage field 5 (get_config_request) = CONFIG_LORA (5)
        # tag = (5 << 3) | 0 = 0x28, value = 5
        payload = b"\x28" + _encode_varint(5)
        result = decode_admin_message(payload)
        assert result == {"get_config_request": 5}

    def test_decode_get_owner_request(self):
        # AdminMessage field 3 (get_owner_request), tag = 0x18, value = 1
        payload = b"\x18\x01"
        result = decode_admin_message(payload)
        assert result == {"get_owner_request": True}

    def test_decode_get_channel_request(self):
        # AdminMessage field 1 (get_channel_request), tag = 0x08, value = 0
        payload = b"\x08\x00"
        result = decode_admin_message(payload)
        assert result == {"get_channel_request": 0}

    def test_decode_begin_edit(self):
        # AdminMessage field 64, tag = (64 << 3) | 0 = 0x80 0x02, value = 1
        tag = _encode_varint(64 << 3)
        payload = tag + b"\x01"
        result = decode_admin_message(payload)
        assert result == {"begin_edit_settings": True}

    def test_decode_commit_edit(self):
        # AdminMessage field 65, tag = (65 << 3) | 0
        tag = _encode_varint(65 << 3)
        payload = tag + b"\x01"
        result = decode_admin_message(payload)
        assert result == {"commit_edit_settings": True}

    def test_decode_set_config_lora(self):
        # Build a minimal LoRaConfig: region=3 (EU_868), modem_preset=0 (LONG_FAST)
        lora_bytes = b"\x08\x01"  # use_preset=true
        lora_bytes += b"\x10\x00"  # modem_preset=LONG_FAST (0)
        lora_bytes += b"\x38\x03"  # region=EU_868 (3)
        lora_bytes += b"\x40\x03"  # hop_limit=3

        # Wrap in Config (field 6 = lora)
        config_bytes = b"\x32" + _encode_varint(len(lora_bytes)) + lora_bytes

        # Wrap in AdminMessage (field 34 = set_config)
        tag = _encode_varint((34 << 3) | 2)
        admin_bytes = tag + _encode_varint(len(config_bytes)) + config_bytes

        result = decode_admin_message(admin_bytes)
        assert "set_config" in result
        assert "lora" in result["set_config"]
        lora = result["set_config"]["lora"]
        assert lora["region"] == 3
        assert lora["region_name"] == "EU_868"
        assert lora["modem_preset"] == 0
        assert lora["modem_preset_name"] == "LONG_FAST"
        assert lora["hop_limit"] == 3

    def test_decode_set_owner(self):
        # User: long_name="Test Node", short_name="TST"
        user_parts = []
        ln = b"Test Node"
        user_parts.append(b"\x12" + _encode_varint(len(ln)) + ln)
        sn = b"TST"
        user_parts.append(b"\x1a" + _encode_varint(len(sn)) + sn)
        user_bytes = b"".join(user_parts)

        # AdminMessage field 32 = set_owner
        tag = _encode_varint((32 << 3) | 2)
        admin_bytes = tag + _encode_varint(len(user_bytes)) + user_bytes

        result = decode_admin_message(admin_bytes)
        assert "set_owner" in result
        assert result["set_owner"]["long_name"] == "Test Node"
        assert result["set_owner"]["short_name"] == "TST"

    def test_decode_set_channel(self):
        # ChannelSettings: name="TestCh", psk=16 bytes
        psk = b"\x01" * 16
        settings = b"\x12" + _encode_varint(len(psk)) + psk
        name = b"TestCh"
        settings += b"\x1a" + _encode_varint(len(name)) + name
        # Channel: index=0, settings, role=1
        ch = b"\x08\x00"  # index
        ch += b"\x12" + _encode_varint(len(settings)) + settings
        ch += b"\x18\x01"  # role=PRIMARY

        # AdminMessage field 33 = set_channel
        tag = _encode_varint((33 << 3) | 2)
        admin_bytes = tag + _encode_varint(len(ch)) + ch

        result = decode_admin_message(admin_bytes)
        assert "set_channel" in result
        assert result["set_channel"]["index"] == 0
        assert result["set_channel"]["settings"]["name"] == "TestCh"
        assert result["set_channel"]["settings"]["psk"] == psk

    def test_decode_empty_returns_empty(self):
        assert decode_admin_message(b"") == {}


class TestEncodeResponses:
    def test_encode_lora_config_response(self):
        config_bytes = encode_config_lora(
            region=REGION_NAME_TO_CODE.get("EU_868", 0),
            modem_preset=PRESET_NAME_TO_CODE.get("LONG_FAST", 0),
            hop_limit=3,
        )
        data = _encode_config_response(config_bytes)
        # Should be valid protobuf bytes (AdminMessage wrapping Config wrapping LoRaConfig)
        assert len(data) > 0
        # Decode it back via our decoder
        result = decode_admin_message(data)
        assert "get_config_response" in result
        assert "lora" in result["get_config_response"]
        lora = result["get_config_response"]["lora"]
        assert lora["region_name"] == "EU_868"
        assert lora["modem_preset_name"] == "LONG_FAST"

    def test_encode_owner_response(self):
        data = encode_owner_response("My Node", "MN", 0xDEADBEEF)
        assert len(data) > 0
        result = decode_admin_message(data)
        assert "get_owner_response" in result
        assert result["get_owner_response"]["long_name"] == "My Node"
        assert result["get_owner_response"]["short_name"] == "MN"

    def test_encode_channel_response(self):
        data = encode_channel_response(0, "LongFast", DEFAULT_KEY)
        assert len(data) > 0
        result = decode_admin_message(data)
        assert "get_channel_response" in result
        assert result["get_channel_response"]["index"] == 0
        assert result["get_channel_response"]["settings"]["name"] == "LongFast"
        assert result["get_channel_response"]["settings"]["psk"] == DEFAULT_KEY


class FakeLora:
    def __init__(self, preset=None, sample_rate=None):
        self.preset = preset
        self.sample_rate = sample_rate


class FakeInterface:
    """Minimal fake MeshInterface for testing AdminHandler."""
    def __init__(self):
        self.preset = None
        self.region = "EU_868"
        self.frequency = 869.525e6
        self.sample_rate = 250000
        self.crypto = None
        self.channel = ChannelConfig.default()
        self.lora = FakeLora()
        self.radio = type('FakeRadio', (), {'configure': lambda *a, **kw: None})()
        self.router = type('FakeRouter', (), {'default_hop_limit': 3})()


class FakeGateway:
    """Minimal fake BLEGateway for testing AdminHandler."""
    def __init__(self):
        self.node = MeshNode(node_id=0x12345678, long_name="Test GW", short_name="TGW")
        self.channel = ChannelConfig.default()
        self.channels: list[ChannelConfig | None] = [self.channel] + [None] * 7
        self.config = SDRConfig.defaults()
        self.interface = FakeInterface()


class TestAdminHandler:
    def test_handle_set_config_lora_changes_region(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)
        assert gw.config.region == "EU_868"

        # Build set_config lora with region=US
        lora_bytes = b"\x08\x01\x10\x00\x38\x01"  # use_preset, LONG_FAST, region=US(1)
        config_bytes = b"\x32" + _encode_varint(len(lora_bytes)) + lora_bytes
        tag = _encode_varint((34 << 3) | 2)
        admin_payload = tag + _encode_varint(len(config_bytes)) + config_bytes

        packet = MeshPacket(
            header=MeshtasticHeader(to=0x12345678, from_node=0xAABBCCDD, id=1),
            data=DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload),
        )
        handler.handle_admin_packet(packet)
        assert gw.config.region == "US"

    def test_handle_set_owner_updates_node(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        user_parts = b"\x12\x08New Name\x1a\x02NN"
        tag = _encode_varint((32 << 3) | 2)
        admin_payload = tag + _encode_varint(len(user_parts)) + user_parts

        packet = MeshPacket(
            header=MeshtasticHeader(to=0x12345678, from_node=0xAABBCCDD, id=2),
            data=DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload),
        )
        handler.handle_admin_packet(packet)
        assert gw.node.long_name == "New Name"
        assert gw.node.short_name == "NN"
        assert gw.config.node.long_name == "New Name"

    def test_handle_set_channel_updates_psk(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        new_psk = b"\x42" * 16
        settings = b"\x12" + _encode_varint(len(new_psk)) + new_psk
        ch = b"\x08\x00\x12" + _encode_varint(len(settings)) + settings
        tag = _encode_varint((33 << 3) | 2)
        admin_payload = tag + _encode_varint(len(ch)) + ch

        packet = MeshPacket(
            header=MeshtasticHeader(to=0x12345678, from_node=0xAABBCCDD, id=3),
            data=DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload),
        )
        handler.handle_admin_packet(packet)
        assert gw.channel.psk == new_psk

    def test_handle_get_config_lora_returns_response(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        admin_payload = b"\x28\x05"  # get_config_request = CONFIG_LORA (5)
        packet = MeshPacket(
            header=MeshtasticHeader(to=0x12345678, from_node=0xAABBCCDD, id=4),
            data=DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload),
        )
        responses = handler.handle_admin_packet(packet)
        assert len(responses) == 1  # One FromRadio response

    def test_handle_get_owner_returns_response(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        admin_payload = b"\x18\x01"  # get_owner_request
        packet = MeshPacket(
            header=MeshtasticHeader(to=0x12345678, from_node=0xAABBCCDD, id=5),
            data=DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload),
        )
        responses = handler.handle_admin_packet(packet)
        assert len(responses) == 1

    def test_non_admin_packet_ignored(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        packet = MeshPacket(
            header=MeshtasticHeader(to=0x12345678, from_node=0xAABBCCDD, id=6),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"hello"),
        )
        responses = handler.handle_admin_packet(packet)
        assert responses == []


class TestRegionPresetMaps:
    def test_region_map_covers_main_regions(self):
        for code, name in REGION_CODE_MAP.items():
            assert isinstance(name, str)
        assert REGION_CODE_MAP[1] == "US"
        assert REGION_CODE_MAP[3] == "EU_868"

    def test_preset_map_covers_all(self):
        expected = {"LONG_FAST", "LONG_SLOW", "VERY_LONG_SLOW", "MEDIUM_SLOW",
                    "MEDIUM_FAST", "SHORT_SLOW", "SHORT_FAST", "LONG_MODERATE",
                    "SHORT_TURBO", "LONG_TURBO"}
        assert set(MODEM_PRESET_MAP.values()) == expected
