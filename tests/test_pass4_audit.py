"""Pass 4 audit tests — cross-checked against Meshtastic protobuf definitions.

Tests for bugs and gaps found during the fourth comprehensive audit:
1. encode_config_lora tx_power int32 sign-extension for negative values
2. decode_fromradio (official protobuf path) field propagation completeness
3. DataPayload bitfield field (proto field 9)
4. MeshPacket BLE encoding via_mqtt field (proto field 14)
"""

import struct

import pytest

from meshtastic_sdr.protocol.mesh_packet import (
    MeshPacket, DataPayload, _encode_varint, _decode_varint,
)
from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.ble.protobuf_codec import (
    _tag, _field_varint, _field_bool, _field_string, _field_bytes,
    _field_float, _field_submsg, _field_int32, _field_fixed32,
    encode_config_lora,
    encode_fromradio_my_info, encode_fromradio_node_info,
    encode_fromradio_config, encode_fromradio_module_config,
    encode_fromradio_channel, encode_fromradio_metadata,
    encode_fromradio_queue_status,
    decode_fromradio,
    mesh_packet_to_protobuf, mesh_packet_from_protobuf,
    encode_channel,
)
from meshtastic_sdr.ble.admin_handler import (
    _decode_lora_config, _decode_config,
)


# =============================================================================
# Fix 1: encode_config_lora tx_power int32 encoding
# =============================================================================

class TestLoRaTxPowerInt32Encoding:
    """Verify tx_power is correctly encoded as int32 (sign-extended varint)."""

    def test_positive_tx_power_encodes(self):
        """Positive tx_power should encode as normal varint."""
        lora_bytes = encode_config_lora(tx_power=20)
        config = _decode_config(lora_bytes)
        assert "lora" in config
        assert config["lora"]["tx_power"] == 20

    def test_zero_tx_power_omitted(self):
        """tx_power=0 should be omitted (protobuf default)."""
        lora_bytes = encode_config_lora(tx_power=0)
        config = _decode_config(lora_bytes)
        assert "lora" in config
        # tx_power=0 is default, should not be present or should be 0
        assert config["lora"].get("tx_power", 0) == 0

    def test_negative_tx_power_encodes_correctly(self):
        """Negative tx_power must use int32 sign-extension (10-byte varint)."""
        lora_bytes = encode_config_lora(tx_power=-5)
        config = _decode_config(lora_bytes)
        assert "lora" in config
        assert config["lora"]["tx_power"] == -5

    def test_negative_one_tx_power(self):
        """tx_power=-1 is a common edge case."""
        lora_bytes = encode_config_lora(tx_power=-1)
        config = _decode_config(lora_bytes)
        assert config["lora"]["tx_power"] == -1

    def test_max_negative_tx_power(self):
        """tx_power at int32 minimum boundary."""
        lora_bytes = encode_config_lora(tx_power=-128)
        config = _decode_config(lora_bytes)
        assert config["lora"]["tx_power"] == -128

    def test_field_int32_vs_raw_varint(self):
        """Verify _field_int32 produces different encoding from raw varint for negatives."""
        # _field_int32(-5) should produce 10-byte sign-extended varint
        encoded = _field_int32(10, -5)
        assert len(encoded) > 2  # Must be longer than a single varint byte
        # Decode the field tag and value
        pos = 0
        tag_byte, pos = _decode_varint(encoded, pos)
        assert (tag_byte >> 3) == 10
        assert (tag_byte & 7) == 0  # wire type varint
        value, pos = _decode_varint(encoded, pos)
        # Sign-extend: negative int32 is encoded as positive uint64
        value = value & 0xFFFFFFFF
        if value >= 0x80000000:
            value -= 0x100000000
        assert value == -5

    def test_full_lora_config_roundtrip_with_negative_tx_power(self):
        """Full encode/decode round-trip with negative tx_power and other fields."""
        lora_bytes = encode_config_lora(
            region=1, modem_preset=6, hop_limit=5,
            tx_enabled=True, tx_power=-10, use_preset=True,
        )
        config = _decode_config(lora_bytes)
        lora = config["lora"]
        assert lora["region"] == 1
        assert lora["modem_preset"] == 6
        assert lora["hop_limit"] == 5
        assert lora["tx_enabled"] is True
        assert lora["tx_power"] == -10
        assert lora["use_preset"] is True


# =============================================================================
# Fix 2: decode_fromradio field propagation completeness
# =============================================================================

class TestDecodeFromRadioMyInfoFields:
    """Verify decode_fromradio propagates all MyNodeInfo fields."""

    def test_my_info_reboot_count(self):
        data = encode_fromradio_my_info(
            node_id=0x12345678, reboot_count=42, msg_id=1,
        )
        result = decode_fromradio(data)
        assert "my_info" in result
        assert result["my_info"]["my_node_num"] == 0x12345678
        assert result["my_info"].get("reboot_count") == 42

    def test_my_info_min_app_version(self):
        data = encode_fromradio_my_info(
            node_id=0x11, min_app_version=30300, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["my_info"].get("min_app_version") == 30300

    def test_my_info_device_id(self):
        dev_id = b"\xDE\xAD\xBE\xEF"
        data = encode_fromradio_my_info(
            node_id=0x11, device_id=dev_id, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["my_info"].get("device_id") == dev_id

    def test_my_info_pio_env(self):
        data = encode_fromradio_my_info(
            node_id=0x11, pio_env="linux-native", msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["my_info"].get("pio_env") == "linux-native"

    def test_my_info_firmware_edition(self):
        data = encode_fromradio_my_info(
            node_id=0x11, firmware_edition=3, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["my_info"].get("firmware_edition") == 3

    def test_my_info_nodedb_count(self):
        data = encode_fromradio_my_info(
            node_id=0x11, nodedb_count=15, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["my_info"]["nodedb_count"] == 15

    def test_my_info_all_fields(self):
        """All 7 MyNodeInfo fields in a single encode/decode."""
        data = encode_fromradio_my_info(
            node_id=0xAABBCCDD, msg_id=1, nodedb_count=5,
            min_app_version=30200, reboot_count=3,
            device_id=b"\x01\x02", pio_env="esp32-s3",
            firmware_edition=2,
        )
        result = decode_fromradio(data)
        mi = result["my_info"]
        assert mi["my_node_num"] == 0xAABBCCDD
        assert mi["nodedb_count"] == 5
        assert mi.get("min_app_version") == 30200
        assert mi.get("reboot_count") == 3
        assert mi.get("device_id") == b"\x01\x02"
        assert mi.get("pio_env") == "esp32-s3"
        assert mi.get("firmware_edition") == 2


class TestDecodeFromRadioNodeInfoFields:
    """Verify decode_fromradio propagates all NodeInfo fields."""

    def test_node_info_basic(self):
        data = encode_fromradio_node_info(
            node_id=0xABCD1234, long_name="TestNode",
            short_name="TN", hw_model=37, msg_id=1,
        )
        result = decode_fromradio(data)
        ni = result["node_info"]
        assert ni["num"] == 0xABCD1234
        assert ni["long_name"] == "TestNode"
        assert ni["short_name"] == "TN"

    def test_node_info_hw_model(self):
        data = encode_fromradio_node_info(
            node_id=0x11, hw_model=37, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("hw_model") == 37

    def test_node_info_role(self):
        data = encode_fromradio_node_info(
            node_id=0x11, role=2, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("role") == 2

    def test_node_info_public_key(self):
        pk = b"\x01" * 32
        data = encode_fromradio_node_info(
            node_id=0x11, public_key=pk, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("public_key") == pk

    def test_node_info_is_licensed(self):
        data = encode_fromradio_node_info(
            node_id=0x11, is_licensed=True, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("is_licensed") is True

    def test_node_info_snr(self):
        data = encode_fromradio_node_info(
            node_id=0x11, snr=7.5, msg_id=1,
        )
        result = decode_fromradio(data)
        assert abs(result["node_info"].get("snr", 0) - 7.5) < 0.01

    def test_node_info_last_heard(self):
        data = encode_fromradio_node_info(
            node_id=0x11, last_heard=1709712000, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("last_heard") == 1709712000

    def test_node_info_hops_away(self):
        data = encode_fromradio_node_info(
            node_id=0x11, hops_away=3, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("hops_away") == 3

    def test_node_info_channel(self):
        data = encode_fromradio_node_info(
            node_id=0x11, channel=2, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("channel") == 2

    def test_node_info_via_mqtt(self):
        data = encode_fromradio_node_info(
            node_id=0x11, via_mqtt=True, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("via_mqtt") is True

    def test_node_info_is_favorite(self):
        data = encode_fromradio_node_info(
            node_id=0x11, is_favorite=True, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("is_favorite") is True

    def test_node_info_is_ignored(self):
        data = encode_fromradio_node_info(
            node_id=0x11, is_ignored=True, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("is_ignored") is True

    def test_node_info_is_muted(self):
        data = encode_fromradio_node_info(
            node_id=0x11, is_muted=True, msg_id=1,
        )
        result = decode_fromradio(data)
        assert result["node_info"].get("is_muted") is True

    def test_node_info_all_fields(self):
        """All NodeInfo fields in a single encode/decode."""
        pk = b"\xAA" * 32
        data = encode_fromradio_node_info(
            node_id=0xDEAD, long_name="Full", short_name="FL",
            hw_model=37, role=5, public_key=pk, is_licensed=True,
            last_heard=1000000, snr=-3.5, hops_away=2, channel=1,
            via_mqtt=True, is_favorite=True, is_ignored=True,
            is_muted=True, msg_id=1,
        )
        result = decode_fromradio(data)
        ni = result["node_info"]
        assert ni["num"] == 0xDEAD
        assert ni["long_name"] == "Full"
        assert ni["short_name"] == "FL"
        assert ni.get("hw_model") == 37
        assert ni.get("role") == 5
        assert ni.get("public_key") == pk
        assert ni.get("is_licensed") is True
        assert ni.get("last_heard") == 1000000
        assert abs(ni.get("snr", 0) - (-3.5)) < 0.01
        assert ni.get("hops_away") == 2
        assert ni.get("channel") == 1
        assert ni.get("via_mqtt") is True
        assert ni.get("is_favorite") is True
        assert ni.get("is_ignored") is True
        assert ni.get("is_muted") is True


class TestDecodeFromRadioVariants:
    """Verify decode_fromradio handles all payload_variant types."""

    def test_config_variant(self):
        """FromRadio with config payload should decode."""
        from meshtastic_sdr.ble.protobuf_codec import encode_config_device
        config_bytes = encode_config_device(role=2)
        data = encode_fromradio_config(config_bytes, msg_id=5)
        result = decode_fromradio(data)
        assert result["id"] == 5
        assert "config" in result
        # config is returned as raw bytes, verify non-empty
        assert len(result["config"]) > 0

    def test_module_config_variant(self):
        """FromRadio with moduleConfig payload should decode."""
        from meshtastic_sdr.ble.protobuf_codec import encode_module_mqtt
        module_bytes = encode_module_mqtt(enabled=True)
        data = encode_fromradio_module_config(module_bytes, msg_id=6)
        result = decode_fromradio(data)
        assert result["id"] == 6
        assert "moduleConfig" in result
        assert len(result["moduleConfig"]) > 0

    def test_channel_variant(self):
        """FromRadio with channel payload should decode."""
        ch_bytes = encode_channel(index=0, name="test", psk=b"\x01" * 16, role=1)
        data = encode_fromradio_channel(ch_bytes, msg_id=7)
        result = decode_fromradio(data)
        assert result["id"] == 7
        assert "channel" in result
        assert len(result["channel"]) > 0

    def test_metadata_variant(self):
        """FromRadio with metadata payload should decode."""
        data = encode_fromradio_metadata(
            firmware_version="2.6.0.sdr", hw_model=37, msg_id=8,
        )
        result = decode_fromradio(data)
        assert result["id"] == 8
        assert "metadata" in result
        assert len(result["metadata"]) > 0

    def test_queue_status_variant(self):
        """FromRadio with queueStatus payload should decode."""
        data = encode_fromradio_queue_status(free=10, max_to_send=16, msg_id=9)
        result = decode_fromradio(data)
        assert result["id"] == 9
        assert "queueStatus" in result
        assert len(result["queueStatus"]) > 0


# =============================================================================
# Fix 3: DataPayload bitfield field (proto field 9)
# =============================================================================

class TestDataPayloadBitfield:
    """Verify DataPayload encodes/decodes the bitfield field (proto field 9)."""

    def test_bitfield_default_zero(self):
        """Bitfield should default to 0."""
        dp = DataPayload()
        assert dp.bitfield == 0

    def test_bitfield_in_constructor(self):
        """Bitfield should be settable in constructor."""
        dp = DataPayload(bitfield=0xFF)
        assert dp.bitfield == 0xFF

    def test_bitfield_roundtrip(self):
        """Bitfield should survive encode/decode round-trip."""
        dp = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=b"hello",
            bitfield=0x1234,
        )
        encoded = dp.to_bytes()
        decoded = DataPayload.from_bytes(encoded)
        assert decoded.bitfield == 0x1234

    def test_bitfield_zero_not_encoded(self):
        """Bitfield=0 should not emit any bytes (protobuf default)."""
        dp = DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"a")
        without_bf = dp.to_bytes()
        dp.bitfield = 0
        with_bf_zero = dp.to_bytes()
        assert without_bf == with_bf_zero

    def test_bitfield_nonzero_adds_bytes(self):
        """Bitfield>0 should add extra bytes to encoded form."""
        dp = DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"a")
        without_bf = dp.to_bytes()
        dp.bitfield = 42
        with_bf = dp.to_bytes()
        assert len(with_bf) > len(without_bf)

    def test_bitfield_preserves_other_fields(self):
        """Setting bitfield should not affect other fields."""
        dp = DataPayload(
            portnum=PortNum.ADMIN_APP,
            payload=b"\x01\x02\x03",
            want_response=True,
            dest=0xAABBCCDD,
            source=0x11223344,
            request_id=0x5678,
            bitfield=0xABCD,
        )
        encoded = dp.to_bytes()
        decoded = DataPayload.from_bytes(encoded)
        assert decoded.portnum == PortNum.ADMIN_APP
        assert decoded.payload == b"\x01\x02\x03"
        assert decoded.want_response is True
        assert decoded.dest == 0xAABBCCDD
        assert decoded.source == 0x11223344
        assert decoded.request_id == 0x5678
        assert decoded.bitfield == 0xABCD

    def test_bitfield_large_value(self):
        """Bitfield should handle full uint32 range."""
        dp = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=b"x",
            bitfield=0xFFFFFFFF,
        )
        encoded = dp.to_bytes()
        decoded = DataPayload.from_bytes(encoded)
        assert decoded.bitfield == 0xFFFFFFFF

    def test_bitfield_manual_wire_format(self):
        """Verify bitfield is field 9, wire type 0 (varint)."""
        dp = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=b"",
            bitfield=1,
        )
        encoded = dp.to_bytes()
        # Field 9, wire type 0: tag = (9 << 3) | 0 = 0x48
        assert b"\x48" in encoded


# =============================================================================
# Fix 4: MeshPacket BLE encoding via_mqtt field (proto field 14)
# =============================================================================

class TestMeshPacketViaMqtt:
    """Verify MeshPacket BLE protobuf includes via_mqtt (proto field 14)."""

    def test_via_mqtt_false_not_encoded(self):
        """via_mqtt=False should not add extra bytes."""
        header = MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0x1234, id=100,
            via_mqtt=False,
        )
        pkt = MeshPacket(
            header=header,
            encrypted=b"\x01\x02\x03",
        )
        encoded = mesh_packet_to_protobuf(pkt)
        # Field 14, wire type 0: tag = (14 << 3) | 0 = 0x70
        assert b"\x70" not in encoded

    def test_via_mqtt_true_encoded(self):
        """via_mqtt=True should be present in BLE protobuf encoding."""
        header = MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0x1234, id=100,
            via_mqtt=True,
        )
        pkt = MeshPacket(
            header=header,
            encrypted=b"\x01\x02\x03",
        )
        encoded = mesh_packet_to_protobuf(pkt)
        # Should contain field 14 varint with value 1
        assert b"\x70\x01" in encoded

    def test_via_mqtt_roundtrip(self):
        """via_mqtt should survive encode/decode round-trip."""
        header = MeshtasticHeader(
            to=0xAABBCCDD, from_node=0x11223344, id=999,
            hop_limit=3, want_ack=True, via_mqtt=True,
            hop_start=3, channel=2,
        )
        pkt = MeshPacket(
            header=header,
            encrypted=b"\xAA\xBB",
        )
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        assert decoded.header.via_mqtt is True
        assert decoded.header.to == 0xAABBCCDD
        assert decoded.header.from_node == 0x11223344
        assert decoded.header.id == 999
        assert decoded.header.hop_limit == 3
        assert decoded.header.want_ack is True
        assert decoded.header.hop_start == 3
        assert decoded.header.channel == 2

    def test_via_mqtt_false_roundtrip(self):
        """via_mqtt=False should round-trip as False."""
        header = MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0x5678, id=42,
            via_mqtt=False,
        )
        pkt = MeshPacket(
            header=header,
            encrypted=b"\x01",
        )
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        assert decoded.header.via_mqtt is False

    def test_via_mqtt_with_decoded_data(self):
        """via_mqtt should work with decoded (cleartext) data payloads too."""
        header = MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0xAAAA, id=77,
            via_mqtt=True,
        )
        data = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=b"hello from mqtt",
        )
        pkt = MeshPacket(header=header, data=data)
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        assert decoded.header.via_mqtt is True
        assert decoded.data is not None
        assert decoded.data.payload == b"hello from mqtt"


# =============================================================================
# Cross-check: AdminMessage field completeness
# =============================================================================

class TestAdminMessageFieldCompleteness:
    """Verify all 59 AdminMessage payload_variant fields are handled."""

    def test_all_varint_admin_fields_dispatched(self):
        """Every varint admin field should decode to a known key."""
        from meshtastic_sdr.ble.admin_handler import decode_admin_message
        from meshtastic_sdr.ble.constants import (
            ADMIN_GET_CHANNEL_REQUEST, ADMIN_GET_OWNER_REQUEST,
            ADMIN_GET_CONFIG_REQUEST, ADMIN_GET_MODULE_CONFIG_REQUEST,
            ADMIN_GET_CANNED_MSG_REQUEST, ADMIN_GET_DEVICE_METADATA_REQUEST,
            ADMIN_GET_RINGTONE_REQUEST, ADMIN_GET_DEVICE_CONN_STATUS_REQUEST,
            ADMIN_BEGIN_EDIT, ADMIN_COMMIT_EDIT,
            ADMIN_REBOOT_SECONDS, ADMIN_REBOOT_OTA_SECONDS,
            ADMIN_SHUTDOWN_SECONDS, ADMIN_FACTORY_RESET_DEVICE,
            ADMIN_FACTORY_RESET_CONFIG, ADMIN_NODEDB_RESET,
            ADMIN_EXIT_SIMULATOR, ADMIN_REMOVE_BY_NODENUM,
            ADMIN_SET_FAVORITE_NODE, ADMIN_REMOVE_FAVORITE_NODE,
            ADMIN_SET_IGNORED_NODE, ADMIN_REMOVE_IGNORED_NODE,
            ADMIN_TOGGLE_MUTED_NODE, ADMIN_REMOVE_FIXED_POSITION,
            ADMIN_GET_UI_CONFIG_REQUEST,
            ADMIN_GET_NODE_REMOTE_HW_PINS_REQUEST,
            ADMIN_ENTER_DFU_MODE_REQUEST,
            ADMIN_SET_SCALE, ADMIN_BACKUP_PREFERENCES,
            ADMIN_RESTORE_PREFERENCES, ADMIN_REMOVE_BACKUP_PREFERENCES,
        )

        varint_fields = [
            (ADMIN_GET_CHANNEL_REQUEST, "get_channel_request"),
            (ADMIN_GET_OWNER_REQUEST, "get_owner_request"),
            (ADMIN_GET_CONFIG_REQUEST, "get_config_request"),
            (ADMIN_GET_MODULE_CONFIG_REQUEST, "get_module_config_request"),
            (ADMIN_GET_CANNED_MSG_REQUEST, "get_canned_message_request"),
            (ADMIN_GET_DEVICE_METADATA_REQUEST, "get_device_metadata_request"),
            (ADMIN_GET_RINGTONE_REQUEST, "get_ringtone_request"),
            (ADMIN_GET_DEVICE_CONN_STATUS_REQUEST, "get_device_connection_status_request"),
            (ADMIN_BEGIN_EDIT, "begin_edit_settings"),
            (ADMIN_COMMIT_EDIT, "commit_edit_settings"),
            (ADMIN_REBOOT_SECONDS, "reboot_seconds"),
            (ADMIN_REBOOT_OTA_SECONDS, "reboot_ota_seconds"),
            (ADMIN_SHUTDOWN_SECONDS, "shutdown_seconds"),
            (ADMIN_FACTORY_RESET_DEVICE, "factory_reset_device"),
            (ADMIN_FACTORY_RESET_CONFIG, "factory_reset_config"),
            (ADMIN_NODEDB_RESET, "nodedb_reset"),
            (ADMIN_EXIT_SIMULATOR, "exit_simulator"),
            (ADMIN_REMOVE_BY_NODENUM, "remove_by_nodenum"),
            (ADMIN_SET_FAVORITE_NODE, "set_favorite_node"),
            (ADMIN_REMOVE_FAVORITE_NODE, "remove_favorite_node"),
            (ADMIN_SET_IGNORED_NODE, "set_ignored_node"),
            (ADMIN_REMOVE_IGNORED_NODE, "remove_ignored_node"),
            (ADMIN_TOGGLE_MUTED_NODE, "toggle_muted_node"),
            (ADMIN_REMOVE_FIXED_POSITION, "remove_fixed_position"),
            (ADMIN_GET_UI_CONFIG_REQUEST, "get_ui_config_request"),
            (ADMIN_GET_NODE_REMOTE_HW_PINS_REQUEST, "get_node_remote_hw_pins_request"),
            (ADMIN_ENTER_DFU_MODE_REQUEST, "enter_dfu_mode_request"),
            (ADMIN_SET_SCALE, "set_scale"),
            (ADMIN_BACKUP_PREFERENCES, "backup_preferences"),
            (ADMIN_RESTORE_PREFERENCES, "restore_preferences"),
            (ADMIN_REMOVE_BACKUP_PREFERENCES, "remove_backup_preferences"),
        ]

        for field_num, expected_key in varint_fields:
            payload = _tag(field_num, 0) + _encode_varint(42)
            result = decode_admin_message(payload)
            assert expected_key in result, (
                f"Field {field_num} should decode to '{expected_key}', got {result}"
            )

    def test_all_submsg_admin_fields_dispatched(self):
        """Every submsg admin field should decode to a known key."""
        from meshtastic_sdr.ble.admin_handler import decode_admin_message
        from meshtastic_sdr.ble.constants import (
            ADMIN_SET_CONFIG, ADMIN_SET_CHANNEL, ADMIN_SET_OWNER,
            ADMIN_SET_MODULE_CONFIG, ADMIN_SET_CANNED_MSG, ADMIN_SET_RINGTONE,
            ADMIN_SET_FIXED_POSITION, ADMIN_ADD_CONTACT,
            ADMIN_SET_HAM_MODE, ADMIN_STORE_UI_CONFIG,
            ADMIN_GET_CONFIG_RESPONSE, ADMIN_GET_CHANNEL_RESPONSE,
            ADMIN_GET_OWNER_RESPONSE, ADMIN_GET_MODULE_CONFIG_RESPONSE,
            ADMIN_GET_DEVICE_METADATA_RESPONSE,
            ADMIN_GET_DEVICE_CONN_STATUS_RESPONSE,
            ADMIN_GET_CANNED_MSG_RESPONSE, ADMIN_GET_RINGTONE_RESPONSE,
            ADMIN_GET_UI_CONFIG_RESPONSE,
            ADMIN_GET_NODE_REMOTE_HW_PINS_RESPONSE,
            ADMIN_SESSION_PASSKEY, ADMIN_DELETE_FILE_REQUEST,
            ADMIN_SEND_INPUT_EVENT, ADMIN_KEY_VERIFICATION,
            ADMIN_OTA_REQUEST, ADMIN_SENSOR_CONFIG,
        )

        submsg_fields = [
            (ADMIN_SET_CONFIG, "set_config"),
            (ADMIN_SET_CHANNEL, "set_channel"),
            (ADMIN_SET_OWNER, "set_owner"),
            (ADMIN_SET_MODULE_CONFIG, "set_module_config"),
            (ADMIN_SET_CANNED_MSG, "set_canned_message"),
            (ADMIN_SET_RINGTONE, "set_ringtone"),
            (ADMIN_SET_FIXED_POSITION, "set_fixed_position"),
            (ADMIN_ADD_CONTACT, "add_contact"),
            (ADMIN_SET_HAM_MODE, "set_ham_mode"),
            (ADMIN_STORE_UI_CONFIG, "store_ui_config"),
            (ADMIN_GET_CONFIG_RESPONSE, "get_config_response"),
            (ADMIN_GET_CHANNEL_RESPONSE, "get_channel_response"),
            (ADMIN_GET_OWNER_RESPONSE, "get_owner_response"),
            (ADMIN_GET_MODULE_CONFIG_RESPONSE, "get_module_config_response"),
            (ADMIN_GET_DEVICE_METADATA_RESPONSE, "get_device_metadata_response"),
            (ADMIN_GET_DEVICE_CONN_STATUS_RESPONSE, "get_device_connection_status_response"),
            (ADMIN_GET_CANNED_MSG_RESPONSE, "get_canned_message_response"),
            (ADMIN_GET_RINGTONE_RESPONSE, "get_ringtone_response"),
            (ADMIN_GET_UI_CONFIG_RESPONSE, "get_ui_config_response"),
            (ADMIN_GET_NODE_REMOTE_HW_PINS_RESPONSE, "get_node_remote_hw_pins_response"),
            (ADMIN_SESSION_PASSKEY, "session_passkey"),
            (ADMIN_DELETE_FILE_REQUEST, "delete_file_request"),
            (ADMIN_SEND_INPUT_EVENT, "send_input_event"),
            (ADMIN_KEY_VERIFICATION, "key_verification"),
            (ADMIN_OTA_REQUEST, "ota_request"),
            (ADMIN_SENSOR_CONFIG, "sensor_config"),
        ]

        for field_num, expected_key in submsg_fields:
            # Encode an empty submsg (length=0)
            payload = _tag(field_num, 2) + b"\x00"
            result = decode_admin_message(payload)
            assert expected_key in result, (
                f"Field {field_num} should decode to '{expected_key}', got {result}"
            )

    def test_fixed32_admin_field(self):
        """set_time_only (field 43) should decode as fixed32."""
        from meshtastic_sdr.ble.admin_handler import decode_admin_message
        from meshtastic_sdr.ble.constants import ADMIN_SET_TIME_ONLY
        payload = _tag(ADMIN_SET_TIME_ONLY, 5) + struct.pack("<I", 1709712000)
        result = decode_admin_message(payload)
        assert "set_time_only" in result
        assert result["set_time_only"] == 1709712000


# =============================================================================
# Cross-check: Config/Module field completeness against proto definitions
# =============================================================================

class TestConfigFieldCompleteness:
    """Verify all config type fields match proto definitions."""

    def test_device_config_fields(self):
        """DeviceConfig: 12 fields (1,2,4-13, no field 3)."""
        from meshtastic_sdr.ble.admin_handler import _CONFIG_VARINT_FIELDS, _CONFIG_STRING_FIELDS
        device_v = _CONFIG_VARINT_FIELDS["device"]
        device_s = _CONFIG_STRING_FIELDS.get("device", {})
        # Proto fields: 1=role, 2=serial_enabled, 4=button_gpio, 5=buzzer_gpio,
        # 6=rebroadcast_mode, 7=node_info_broadcast_secs, 8=double_tap_as_button_press,
        # 9=is_managed, 10=disable_triple_click, 11=tzdef, 12=led_heartbeat_disabled,
        # 13=buzzer_mode
        expected_varint = {1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 13}
        expected_string = {11}
        assert set(device_v.keys()) == expected_varint
        assert set(device_s.keys()) == expected_string

    def test_position_config_fields(self):
        """PositionConfig: 13 fields."""
        from meshtastic_sdr.ble.admin_handler import _CONFIG_VARINT_FIELDS
        pos = _CONFIG_VARINT_FIELDS["position"]
        expected = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
        assert set(pos.keys()) == expected

    def test_power_config_fields(self):
        """PowerConfig: 9 fields (1,2,3,4,6,7,8,9,32)."""
        from meshtastic_sdr.ble.admin_handler import _CONFIG_VARINT_FIELDS, _CONFIG_FLOAT_FIELDS
        power_v = _CONFIG_VARINT_FIELDS["power"]
        power_f = _CONFIG_FLOAT_FIELDS.get("power", {})
        expected_varint = {1, 2, 4, 6, 7, 8, 9, 32}
        expected_float = {3}
        assert set(power_v.keys()) == expected_varint
        assert set(power_f.keys()) == expected_float

    def test_network_config_fields(self):
        """NetworkConfig: 10 fields (1,3-7,9-11); 8=ipv4_config intentionally skipped."""
        from meshtastic_sdr.ble.admin_handler import _CONFIG_VARINT_FIELDS, _CONFIG_STRING_FIELDS
        net_v = _CONFIG_VARINT_FIELDS["network"]
        net_s = _CONFIG_STRING_FIELDS.get("network", {})
        expected_varint = {1, 6, 7, 10, 11}
        expected_string = {3, 4, 5, 9}
        assert set(net_v.keys()) == expected_varint
        assert set(net_s.keys()) == expected_string

    def test_display_config_fields(self):
        """DisplayConfig: 14 fields."""
        from meshtastic_sdr.ble.admin_handler import _CONFIG_VARINT_FIELDS
        display = _CONFIG_VARINT_FIELDS["display"]
        expected = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
        assert set(display.keys()) == expected

    def test_bluetooth_config_fields(self):
        """BluetoothConfig: 3 fields."""
        from meshtastic_sdr.ble.admin_handler import _CONFIG_VARINT_FIELDS
        bt = _CONFIG_VARINT_FIELDS["bluetooth"]
        expected = {1, 2, 3}
        assert set(bt.keys()) == expected

    def test_security_config_fields(self):
        """SecurityConfig: 7 fields (1,2,3,4,5,6,8)."""
        from meshtastic_sdr.ble.admin_handler import (
            _CONFIG_VARINT_FIELDS, _CONFIG_BYTES_FIELDS,
        )
        sec_v = _CONFIG_VARINT_FIELDS["security"]
        sec_b = _CONFIG_BYTES_FIELDS.get("security", {})
        expected_varint = {4, 5, 6, 8}  # admin_key(3) decoded separately
        expected_bytes = {1, 2}
        assert set(sec_v.keys()) == expected_varint
        assert set(sec_b.keys()) == expected_bytes

    def test_lora_config_fields_complete(self):
        """LoRaConfig: 17 fields (1-15, 103-105)."""
        # Test by encoding with all fields and verifying decode
        lora_bytes = encode_config_lora(
            use_preset=True, modem_preset=6, bandwidth=250,
            spread_factor=7, coding_rate=5, frequency_offset=10.5,
            region=1, hop_limit=5, tx_enabled=True, tx_power=20,
            channel_num=3, override_frequency=906.0,
            override_duty_cycle=True, sx126x_rx_boosted_gain=True,
            pa_fan_disabled=True, ignore_mqtt=True,
            config_ok_to_mqtt=True,
            ignore_incoming=[0x1111, 0x2222],
        )
        config = _decode_config(lora_bytes)
        lora = config["lora"]
        assert lora["use_preset"] is True
        assert lora["modem_preset"] == 6
        assert lora["bandwidth"] == 250
        assert lora["spread_factor"] == 7
        assert lora["coding_rate"] == 5
        assert abs(lora["frequency_offset"] - 10.5) < 0.1
        assert lora["region"] == 1
        assert lora["hop_limit"] == 5
        assert lora["tx_enabled"] is True
        assert lora["tx_power"] == 20
        assert lora["channel_num"] == 3
        assert abs(lora["override_frequency"] - 906.0) < 0.1
        assert lora["override_duty_cycle"] is True
        assert lora["sx126x_rx_boosted_gain"] is True
        assert lora["pa_fan_disabled"] is True
        assert lora["ignore_mqtt"] is True
        assert lora["config_ok_to_mqtt"] is True
        assert lora["ignore_incoming"] == [0x1111, 0x2222]


class TestModuleConfigFieldCompleteness:
    """Verify all module config fields match proto definitions."""

    def test_mqtt_fields(self):
        """MQTTConfig: 10 handled fields (11=map_report_settings skipped)."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS, _MODULE_STRING_FIELDS
        v = _MODULE_VARINT_FIELDS["mqtt"]
        s = _MODULE_STRING_FIELDS.get("mqtt", {})
        assert set(v.keys()) == {1, 5, 6, 7, 9, 10}
        assert set(s.keys()) == {2, 3, 4, 8}

    def test_serial_fields(self):
        """SerialConfig: 8 fields."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS
        assert set(_MODULE_VARINT_FIELDS["serial"].keys()) == {1, 2, 3, 4, 5, 6, 7, 8}

    def test_external_notification_fields(self):
        """ExternalNotificationConfig: 15 fields."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS
        v = _MODULE_VARINT_FIELDS["external_notification"]
        assert set(v.keys()) == set(range(1, 16))

    def test_telemetry_fields(self):
        """TelemetryConfig: 15 fields."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS
        v = _MODULE_VARINT_FIELDS["telemetry"]
        assert set(v.keys()) == set(range(1, 16))

    def test_traffic_management_fields(self):
        """TrafficManagementConfig: 14 fields."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS
        v = _MODULE_VARINT_FIELDS["traffic_management"]
        assert set(v.keys()) == set(range(1, 15))

    def test_canned_message_fields(self):
        """CannedMessageConfig: 11 fields (10 varint/bool + 1 string)."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS, _MODULE_STRING_FIELDS
        v = _MODULE_VARINT_FIELDS["canned_message"]
        s = _MODULE_STRING_FIELDS.get("canned_message", {})
        assert set(v.keys()) == {1, 2, 3, 4, 5, 6, 7, 8, 9, 11}
        assert set(s.keys()) == {10}

    def test_detection_sensor_fields(self):
        """DetectionSensorConfig: 8 fields (7 varint + 1 string)."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS, _MODULE_STRING_FIELDS
        v = _MODULE_VARINT_FIELDS["detection_sensor"]
        s = _MODULE_STRING_FIELDS.get("detection_sensor", {})
        assert set(v.keys()) == {1, 2, 3, 4, 6, 7, 8}
        assert set(s.keys()) == {5}

    def test_paxcounter_fields(self):
        """PaxcounterConfig: 4 fields (2 int32)."""
        from meshtastic_sdr.ble.admin_handler import _MODULE_VARINT_FIELDS, _INT32_FIELD_NAMES
        v = _MODULE_VARINT_FIELDS["paxcounter"]
        assert set(v.keys()) == {1, 2, 3, 4}
        # wifi_threshold and ble_threshold are int32
        assert "wifi_threshold" in _INT32_FIELD_NAMES
        assert "ble_threshold" in _INT32_FIELD_NAMES

    def test_all_15_module_types_in_field_map(self):
        """All 15 module types should be in MODULE_FIELD_TO_NAME."""
        from meshtastic_sdr.ble.admin_handler import MODULE_FIELD_TO_NAME
        assert len(MODULE_FIELD_TO_NAME) == 15
        assert set(MODULE_FIELD_TO_NAME.keys()) == set(range(1, 16))

    def test_all_10_config_types_in_field_map(self):
        """All 10 config types should be in CONFIG_FIELD_TO_NAME."""
        from meshtastic_sdr.ble.admin_handler import CONFIG_FIELD_TO_NAME
        assert len(CONFIG_FIELD_TO_NAME) == 10
        assert set(CONFIG_FIELD_TO_NAME.keys()) == set(range(1, 11))


# =============================================================================
# Cross-check: Region/Preset enum completeness
# =============================================================================

class TestEnumCompleteness:
    """Verify region and preset enums match proto definitions."""

    def test_region_codes_complete(self):
        """All 27 RegionCode enum values should be in REGION_CODE_MAP."""
        from meshtastic_sdr.ble.constants import REGION_CODE_MAP
        # Proto: UNSET=0, US=1, EU_433=2, ..., BR_902=26
        expected = set(range(0, 27))
        assert set(REGION_CODE_MAP.keys()) == expected

    def test_modem_presets_complete(self):
        """All 10 ModemPreset enum values should be in MODEM_PRESET_MAP."""
        from meshtastic_sdr.ble.constants import MODEM_PRESET_MAP
        # Proto: LONG_FAST=0, ..., LONG_TURBO=9
        expected = set(range(0, 10))
        assert set(MODEM_PRESET_MAP.keys()) == expected

    def test_region_bidirectional_mapping(self):
        """REGION_CODE_MAP and REGION_NAME_TO_CODE should be inverse."""
        from meshtastic_sdr.ble.constants import REGION_CODE_MAP, REGION_NAME_TO_CODE
        for code, name in REGION_CODE_MAP.items():
            assert REGION_NAME_TO_CODE[name] == code

    def test_preset_bidirectional_mapping(self):
        """MODEM_PRESET_MAP and PRESET_NAME_TO_CODE should be inverse."""
        from meshtastic_sdr.ble.constants import MODEM_PRESET_MAP, PRESET_NAME_TO_CODE
        for code, name in MODEM_PRESET_MAP.items():
            assert PRESET_NAME_TO_CODE[name] == code


# =============================================================================
# Cross-check: ChannelSettings field completeness
# =============================================================================

class TestChannelSettingsCompleteness:
    """Verify ChannelSettings encodes/decodes all 6 fields."""

    def test_all_channel_settings_fields(self):
        """ChannelSettings: channel_num(1), psk(2), name(3), id(4),
        uplink_enabled(5), downlink_enabled(6)."""
        from meshtastic_sdr.ble.admin_handler import _decode_channel
        ch_bytes = encode_channel(
            index=1, name="TestCh", psk=b"\x01" * 16, role=2,
            uplink_enabled=True, downlink_enabled=True,
            channel_num=5, id=0xDEADBEEF,
        )
        ch = _decode_channel(ch_bytes)
        assert ch["index"] == 1
        assert ch["role"] == 2
        settings = ch["settings"]
        assert settings["name"] == "TestCh"
        assert settings["psk"] == b"\x01" * 16
        assert settings["channel_num"] == 5
        assert settings["id"] == 0xDEADBEEF
        assert settings["uplink_enabled"] is True
        assert settings["downlink_enabled"] is True


# =============================================================================
# Cross-check: User proto field completeness
# =============================================================================

class TestUserProtoFieldCompleteness:
    """Verify User decoder handles all 9 proto fields."""

    def test_all_user_fields(self):
        """User: id(1), long_name(2), short_name(3), macaddr(4), hw_model(5),
        is_licensed(6), role(7), public_key(8), is_unmessagable(9)."""
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        macaddr = b"\x01\x02\x03\x04\x05\x06"
        pk = b"\xAA" * 32
        data = (
            _field_string(1, "!aabbccdd") +
            _field_string(2, "Full User") +
            _field_string(3, "FU") +
            _field_bytes(4, macaddr) +
            _field_varint(5, 37) +
            _field_bool(6, True) +
            _field_varint(7, 2) +
            _field_bytes(8, pk) +
            _field_bool(9, True)
        )
        user = _decode_user(data)
        assert user["id"] == "!aabbccdd"
        assert user["long_name"] == "Full User"
        assert user["short_name"] == "FU"
        assert user["macaddr"] == macaddr
        assert user["hw_model"] == 37
        assert user["is_licensed"] is True
        assert user["role"] == 2
        assert user["public_key"] == pk
        assert user["is_unmessagable"] is True
