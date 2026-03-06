"""Tests for phone config persistence — set_config/set_module_config → YAML → reload."""

import sys
import asyncio
import pytest
import yaml

sys.path.insert(0, "src")

from meshtastic_sdr.config import SDRConfig, save_config, load_config
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.protocol.channels import ChannelConfig
from meshtastic_sdr.protocol.header import MeshtasticHeader
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload, _encode_varint
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.ble.admin_handler import (
    AdminHandler, decode_admin_message,
    _decode_named_fields, _CONFIG_VARINT_FIELDS, _CONFIG_STRING_FIELDS,
    _MODULE_VARINT_FIELDS, _MODULE_STRING_FIELDS,
)
from meshtastic_sdr.ble.constants import (
    ADMIN_SET_CONFIG, ADMIN_SET_MODULE_CONFIG,
    CONFIG_DEVICE, CONFIG_DISPLAY, CONFIG_BLUETOOTH, CONFIG_LORA,
)
from meshtastic_sdr.ble.protobuf_codec import (
    _field_submsg, _field_varint, _field_bool, _field_string, _tag,
    encode_config_device, encode_config_display, encode_config_bluetooth,
    encode_config_power, encode_config_position, encode_config_network,
    encode_config_security,
    encode_module_mqtt, encode_module_telemetry, encode_module_neighbor_info,
)
from meshtastic_sdr.ble.config_state import ConfigState
from meshtastic_sdr.ble.protobuf_codec import decode_fromradio


# --- Helpers ---

def _make_admin_packet(admin_payload: bytes, from_node=0xAAAAAAAA, to_node=0xBBBBBBBB):
    """Wrap an AdminMessage payload in a MeshPacket."""
    header = MeshtasticHeader(to=to_node, from_node=from_node, id=0x12345678)
    data = DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload)
    return MeshPacket(header=header, data=data)


def _make_set_config_payload(config_bytes: bytes) -> bytes:
    """Wrap config bytes in AdminMessage set_config (field 34)."""
    return _field_submsg(ADMIN_SET_CONFIG, config_bytes)


def _make_set_module_config_payload(module_bytes: bytes) -> bytes:
    """Wrap module config bytes in AdminMessage set_module_config (field 35)."""
    return _field_submsg(ADMIN_SET_MODULE_CONFIG, module_bytes)


class FakeGateway:
    """Minimal gateway mock for AdminHandler tests."""
    def __init__(self, config=None):
        self.node = MeshNode(node_id=0xBBBBBBBB, long_name="Test GW")
        self.channel = ChannelConfig.default()
        self.channels: list[ChannelConfig | None] = [self.channel] + [None] * 7
        self.config = config or SDRConfig.defaults()
        self.interface = None


# --- Named field decoder tests ---

class TestNamedFieldDecoder:
    def test_decode_device_config(self):
        """DeviceConfig fields decode to encoder-compatible names."""
        # role=2, node_info_broadcast_secs=1800, tzdef="UTC"
        data = b""
        data += _tag(1, 0) + _encode_varint(2)  # role
        data += _tag(7, 0) + _encode_varint(1800)  # node_info_broadcast_secs
        data += _field_string(11, "UTC")  # tzdef

        result = _decode_named_fields(
            data, _CONFIG_VARINT_FIELDS["device"], _CONFIG_STRING_FIELDS.get("device")
        )
        assert result["role"] == 2
        assert result["node_info_broadcast_secs"] == 1800
        assert result["tzdef"] == "UTC"

    def test_decode_display_config(self):
        """DisplayConfig fields decode correctly."""
        data = _tag(1, 0) + _encode_varint(120)  # screen_on_secs
        data += _tag(6, 0) + _encode_varint(1)  # units (imperial)

        result = _decode_named_fields(data, _CONFIG_VARINT_FIELDS["display"])
        assert result["screen_on_secs"] == 120
        assert result["units"] == 1

    def test_decode_bool_fields(self):
        """Boolean fields decode as True/False, not 0/1."""
        data = _tag(1, 0) + _encode_varint(1)  # wifi_enabled

        result = _decode_named_fields(data, _CONFIG_VARINT_FIELDS["network"])
        assert result["wifi_enabled"] is True

    def test_decode_bool_false(self):
        """Boolean field with value 0 decodes as False."""
        data = _tag(1, 0) + _encode_varint(0)  # wifi_enabled = false

        result = _decode_named_fields(data, _CONFIG_VARINT_FIELDS["network"])
        assert result["wifi_enabled"] is False

    def test_decode_mqtt_module(self):
        """MQTT module fields decode with named keys."""
        data = _tag(1, 0) + _encode_varint(1)  # enabled
        data += _tag(8, 0) + _encode_varint(1)  # proxy_to_client_enabled

        result = _decode_named_fields(data, _MODULE_VARINT_FIELDS["mqtt"])
        assert result["enabled"] is True
        assert result["proxy_to_client_enabled"] is True

    def test_decode_telemetry_module(self):
        """Telemetry module fields are ints, not bools."""
        data = _tag(1, 0) + _encode_varint(300)  # device_update_interval
        data += _tag(2, 0) + _encode_varint(600)  # environment_update_interval

        result = _decode_named_fields(data, _MODULE_VARINT_FIELDS["telemetry"])
        assert result["device_update_interval"] == 300
        assert result["environment_update_interval"] == 600

    def test_unknown_fields_ignored(self):
        """Fields not in the map are silently skipped."""
        data = _tag(1, 0) + _encode_varint(2)  # role (known)
        data += _tag(99, 0) + _encode_varint(42)  # unknown

        result = _decode_named_fields(data, _CONFIG_VARINT_FIELDS["device"])
        assert result == {"role": 2}


# --- AdminHandler set_config storage ---

class TestAdminSetConfigStorage:
    def test_set_device_config_stored(self):
        """Phone set_config device → stored in config.configs."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Encode a device config: role=2, node_info_broadcast_secs=1800
        device_inner = _tag(1, 0) + _encode_varint(2) + _tag(7, 0) + _encode_varint(1800)
        config_bytes = _field_submsg(1, device_inner)  # Config field 1 = device
        admin_payload = _make_set_config_payload(config_bytes)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        assert "device" in gw.config.configs
        assert gw.config.configs["device"]["role"] == 2
        assert gw.config.configs["device"]["node_info_broadcast_secs"] == 1800

    def test_set_display_config_stored(self):
        """Phone set_config display → stored in config.configs."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        display_inner = _tag(1, 0) + _encode_varint(120) + _tag(6, 0) + _encode_varint(1)
        config_bytes = _field_submsg(5, display_inner)  # Config field 5 = display
        admin_payload = _make_set_config_payload(config_bytes)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        assert gw.config.configs["display"]["screen_on_secs"] == 120
        assert gw.config.configs["display"]["units"] == 1

    def test_set_bluetooth_config_stored(self):
        """Phone set_config bluetooth → stored in config.configs."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        bt_inner = _tag(1, 0) + _encode_varint(1) + _tag(3, 0) + _encode_varint(999999)
        config_bytes = _field_submsg(7, bt_inner)  # Config field 7 = bluetooth
        admin_payload = _make_set_config_payload(config_bytes)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        assert gw.config.configs["bluetooth"]["enabled"] is True
        assert gw.config.configs["bluetooth"]["fixed_pin"] == 999999

    def test_set_lora_not_stored_in_configs(self):
        """LoRa config is applied via _apply_lora_config, not stored in configs dict."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        lora_inner = _tag(7, 0) + _encode_varint(3)  # region = EU_868
        config_bytes = _field_submsg(6, lora_inner)  # Config field 6 = lora
        admin_payload = _make_set_config_payload(config_bytes)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        # LoRa is NOT stored in configs dict — it goes through _apply_lora_config
        assert "lora" not in gw.config.configs

    def test_multiple_configs_accumulate(self):
        """Multiple set_config calls accumulate in configs dict."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Set device config
        device_inner = _tag(1, 0) + _encode_varint(2)
        admin1 = _make_set_config_payload(_field_submsg(1, device_inner))
        handler.handle_admin_packet(_make_admin_packet(admin1))

        # Set display config
        display_inner = _tag(1, 0) + _encode_varint(30)
        admin2 = _make_set_config_payload(_field_submsg(5, display_inner))
        handler.handle_admin_packet(_make_admin_packet(admin2))

        assert "device" in gw.config.configs
        assert "display" in gw.config.configs


# --- AdminHandler set_module_config storage ---

class TestAdminSetModuleConfigStorage:
    def test_set_mqtt_module_stored(self):
        """Phone set_module_config mqtt → stored in config.modules."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        mqtt_inner = _tag(1, 0) + _encode_varint(1)  # enabled=true
        module_bytes = _field_submsg(1, mqtt_inner)  # ModuleConfig field 1 = mqtt
        admin_payload = _make_set_module_config_payload(module_bytes)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        assert "mqtt" in gw.config.modules
        assert gw.config.modules["mqtt"]["enabled"] is True

    def test_set_telemetry_module_stored(self):
        """Phone set_module_config telemetry → stored in config.modules."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        tel_inner = _tag(1, 0) + _encode_varint(300) + _tag(2, 0) + _encode_varint(600)
        module_bytes = _field_submsg(6, tel_inner)  # ModuleConfig field 6 = telemetry
        admin_payload = _make_set_module_config_payload(module_bytes)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        assert gw.config.modules["telemetry"]["device_update_interval"] == 300
        assert gw.config.modules["telemetry"]["environment_update_interval"] == 600


# --- Full round-trip: phone → config → YAML → reload → handshake ---

class TestConfigPersistenceRoundTrip:
    def test_set_config_persists_and_reloads(self, tmp_path):
        """Phone set_config → save → load → values preserved."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Phone sets display config
        display_inner = _tag(1, 0) + _encode_varint(120) + _tag(6, 0) + _encode_varint(1)
        config_bytes = _field_submsg(5, display_inner)
        admin_payload = _make_set_config_payload(config_bytes)
        handler.handle_admin_packet(_make_admin_packet(admin_payload))

        # Phone sets MQTT module
        mqtt_inner = _tag(1, 0) + _encode_varint(1)
        module_bytes = _field_submsg(1, mqtt_inner)
        admin_payload = _make_set_module_config_payload(module_bytes)
        handler.handle_admin_packet(_make_admin_packet(admin_payload))

        # Save config
        path = tmp_path / "config.yaml"
        save_config(gw.config, path)

        # Reload
        loaded = load_config(str(path))

        assert loaded.configs["display"]["screen_on_secs"] == 120
        assert loaded.configs["display"]["units"] == 1
        assert loaded.modules["mqtt"]["enabled"] is True

    def test_handshake_uses_stored_configs(self):
        """ConfigState handshake reflects stored config values."""
        config = SDRConfig.defaults()
        config.configs["display"] = {"screen_on_secs": 120, "units": 1}
        config.configs["bluetooth"] = {"enabled": True, "fixed_pin": 999999}
        config.modules["telemetry"] = {
            "device_update_interval": 300,
            "environment_update_interval": 600,
        }

        node = MeshNode(node_id=0xAAAAAAAA, long_name="Test")
        state = ConfigState(node, config=config)
        responses = state.generate_config_response(69420)  # CONFIG_NONCE

        # Stage 1 should still be 37 messages (my_info + metadata + own_nodeinfo + 10 configs + 15 modules + 8 channels + complete)
        assert len(responses) == 37

    def test_full_save_load_handshake_cycle(self, tmp_path):
        """Full cycle: set configs → save → load → new ConfigState uses stored values."""
        # Step 1: Phone sets configs
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Set device config
        device_inner = _tag(1, 0) + _encode_varint(2) + _tag(7, 0) + _encode_varint(1800)
        handler.handle_admin_packet(_make_admin_packet(
            _make_set_config_payload(_field_submsg(1, device_inner))
        ))

        # Set display config
        display_inner = _tag(1, 0) + _encode_varint(90)
        handler.handle_admin_packet(_make_admin_packet(
            _make_set_config_payload(_field_submsg(5, display_inner))
        ))

        # Set neighbor_info module
        ni_inner = _tag(1, 0) + _encode_varint(1) + _tag(2, 0) + _encode_varint(600)
        handler.handle_admin_packet(_make_admin_packet(
            _make_set_module_config_payload(_field_submsg(10, ni_inner))
        ))

        # Step 2: Save
        path = tmp_path / "config.yaml"
        save_config(gw.config, path)

        # Step 3: Reload into new config
        loaded = load_config(str(path))

        # Verify stored values
        assert loaded.configs["device"]["role"] == 2
        assert loaded.configs["display"]["screen_on_secs"] == 90
        assert loaded.modules["neighbor_info"]["enabled"] is True
        assert loaded.modules["neighbor_info"]["update_interval"] == 600

        # Step 4: New ConfigState with loaded config
        node = MeshNode(node_id=0xCCCCCCCC)
        state = ConfigState(node, config=loaded)
        responses = state.generate_config_response(69420)
        assert len(responses) == 37  # same count


# --- PSK persistence ---

class TestPSKPersistence:
    def test_psk_change_persisted_as_base64(self):
        """When phone changes PSK, it's stored as base64 in config."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Simulate phone setting channel with new PSK
        new_psk = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        channel_settings = _field_bytes_raw(2, new_psk) + _field_string(3, "MyChannel")
        channel_data = _tag(1, 0) + _encode_varint(0) + _field_submsg(2, channel_settings) + _tag(3, 0) + _encode_varint(1)
        admin_payload = _field_submsg(33, channel_data)  # ADMIN_SET_CHANNEL
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        import base64
        assert gw.config.channel.name == "MyChannel"
        expected = base64.b64encode(new_psk).decode()
        assert gw.config.channel.psk == expected

    def test_default_psk_stored_as_default(self):
        """When phone sets the default PSK, it's stored as 'default'."""
        from meshtastic_sdr.protocol.encryption import DEFAULT_KEY

        gw = FakeGateway()
        handler = AdminHandler(gw)

        channel_settings = _field_bytes_raw(2, DEFAULT_KEY)
        channel_data = _tag(1, 0) + _encode_varint(0) + _field_submsg(2, channel_settings) + _tag(3, 0) + _encode_varint(1)
        admin_payload = _field_submsg(33, channel_data)
        packet = _make_admin_packet(admin_payload)

        handler.handle_admin_packet(packet)

        assert gw.config.channel.psk == "default"


def _field_bytes_raw(field_num, value):
    """Encode a bytes field (always emits, even if empty)."""
    return _tag(field_num, 2) + _encode_varint(len(value)) + value
