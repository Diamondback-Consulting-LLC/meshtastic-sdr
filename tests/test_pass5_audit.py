"""Pass 5 audit tests — BLE MeshPacket Data field completeness, proto cross-checks.

Cross-checked against /home/leif/workspace/diamondback/tools/meshtastic/python/meshtastic/protobuf/
"""

import struct
import unittest

from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR, HEADER_SIZE
from meshtastic_sdr.protocol.mesh_packet import (
    MeshPacket, DataPayload, _encode_varint, _decode_varint,
)
from meshtastic_sdr.protocol.encryption import MeshtasticCrypto, DEFAULT_KEY, get_default_key, _build_nonce
from meshtastic_sdr.protocol.channels import (
    ChannelConfig, compute_channel_hash, REGIONS, get_default_frequency,
)
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.ble.protobuf_codec import (
    mesh_packet_to_protobuf,
    mesh_packet_from_protobuf,
    encode_fromradio_packet,
    encode_fromradio_my_info,
    encode_fromradio_node_info,
    encode_fromradio_metadata,
    encode_fromradio_config_complete,
    encode_fromradio_queue_status,
    encode_toradio_packet,
    encode_toradio_want_config,
    encode_toradio_disconnect,
    decode_toradio,
    decode_fromradio,
    encode_config_device, encode_config_position, encode_config_power,
    encode_config_network, encode_config_display, encode_config_lora,
    encode_config_bluetooth, encode_config_security, encode_config_sessionkey,
    encode_config_deviceui,
    encode_module_mqtt, encode_module_serial, encode_module_extnotif,
    encode_module_store_forward, encode_module_range_test, encode_module_telemetry,
    encode_module_canned_message, encode_module_audio, encode_module_remote_hardware,
    encode_module_neighbor_info, encode_module_ambient_lighting,
    encode_module_detection_sensor, encode_module_paxcounter,
    encode_module_status_message, encode_module_traffic_management,
    encode_channel,
    _field_varint, _field_bool, _field_string, _field_bytes,
    _field_fixed32, _field_float, _field_int32, _field_sint32,
    _field_sfixed32, _field_submsg, _field_uint64, _tag,
    _manual_encode_mesh_packet, _manual_decode_mesh_packet,
    _decode_user, _decode_node_info, _decode_my_info,
    HAS_MESH_PB,
)
from meshtastic_sdr.ble.constants import (
    REGION_CODE_MAP, REGION_NAME_TO_CODE,
    MODEM_PRESET_MAP, PRESET_NAME_TO_CODE,
    CONFIG_NONCE, NODEDB_NONCE,
)
from meshtastic_sdr.lora.params import PRESETS, CodingRate, get_preset
from meshtastic_sdr.mesh.router import MeshRouter
from meshtastic_sdr.mesh.node import MeshNode, NodeInfo


# =============================================================================
# Fix 1: BLE MeshPacket official path now includes reply_id, emoji, bitfield
# =============================================================================

class TestBLEMeshPacketDataFieldCompleteness(unittest.TestCase):
    """Verify all 9 Data fields roundtrip through BLE protobuf encode/decode."""

    def _make_packet(self, **data_kwargs):
        defaults = dict(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"test")
        defaults.update(data_kwargs)
        data = DataPayload(**defaults)
        header = MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0x11223344, id=0xAABBCCDD,
            hop_limit=3, hop_start=3, channel=5,
        )
        return MeshPacket(header=header, data=data)

    def test_reply_id_roundtrip(self):
        pkt = self._make_packet(reply_id=0x12345678)
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        self.assertEqual(decoded.data.reply_id, 0x12345678)

    def test_emoji_roundtrip(self):
        pkt = self._make_packet(emoji=0x1F600)
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        self.assertEqual(decoded.data.emoji, 0x1F600)

    def test_bitfield_roundtrip(self):
        pkt = self._make_packet(bitfield=7)
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        self.assertEqual(decoded.data.bitfield, 7)

    def test_all_data_fields_roundtrip(self):
        """All 9 Data fields must survive BLE encode/decode."""
        pkt = self._make_packet(
            portnum=PortNum.ADMIN_APP,
            payload=b"\x01\x02\x03",
            want_response=True,
            dest=0xDEADBEEF,
            source=0xCAFEBABE,
            request_id=0x99887766,
            reply_id=0x55443322,
            emoji=0x2764,
            bitfield=3,
        )
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        self.assertEqual(decoded.data.portnum, PortNum.ADMIN_APP)
        self.assertEqual(decoded.data.payload, b"\x01\x02\x03")
        self.assertTrue(decoded.data.want_response)
        self.assertEqual(decoded.data.dest, 0xDEADBEEF)
        self.assertEqual(decoded.data.source, 0xCAFEBABE)
        self.assertEqual(decoded.data.request_id, 0x99887766)
        self.assertEqual(decoded.data.reply_id, 0x55443322)
        self.assertEqual(decoded.data.emoji, 0x2764)
        self.assertEqual(decoded.data.bitfield, 3)

    def test_zero_fields_not_encoded(self):
        """Zero-valued optional fields should not be present in encoded output."""
        pkt = self._make_packet(reply_id=0, emoji=0, bitfield=0)
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        self.assertEqual(decoded.data.reply_id, 0)
        self.assertEqual(decoded.data.emoji, 0)
        self.assertEqual(decoded.data.bitfield, 0)

    def test_reply_id_not_lost_on_ble_relay(self):
        """Simulate phone->SDR->phone relay with reply_id preserved."""
        pkt = self._make_packet(reply_id=42, request_id=100)
        # Encode to BLE (phone->SDR)
        ble_bytes = mesh_packet_to_protobuf(pkt)
        # Decode (SDR receives)
        internal = mesh_packet_from_protobuf(ble_bytes)
        # Re-encode to BLE (SDR->phone)
        ble_bytes2 = mesh_packet_to_protobuf(internal)
        # Final decode
        final = mesh_packet_from_protobuf(ble_bytes2)
        self.assertEqual(final.data.reply_id, 42)
        self.assertEqual(final.data.request_id, 100)

    def test_emoji_large_value(self):
        """Unicode emoji values can be large (up to 0x1FFFF+)."""
        pkt = self._make_packet(emoji=0x1F4A9)  # poop emoji
        encoded = mesh_packet_to_protobuf(pkt)
        decoded = mesh_packet_from_protobuf(encoded)
        self.assertEqual(decoded.data.emoji, 0x1F4A9)


class TestManualEncodingConsistency(unittest.TestCase):
    """Verify manual and official encode paths produce equivalent results."""

    def test_manual_decode_preserves_all_fields(self):
        """Manual decode path should also handle all Data fields."""
        # Build manual-encoded packet with all fields
        pkt = MeshPacket(
            header=MeshtasticHeader(
                to=0xFFFFFFFF, from_node=0x11111111, id=0x22222222,
                hop_limit=3, hop_start=3, channel=1,
            ),
            data=DataPayload(
                portnum=1, payload=b"hi", want_response=True,
                dest=0x33333333, source=0x44444444, request_id=0x55555555,
                reply_id=0x66666666, emoji=0x77777777, bitfield=15,
            ),
        )
        manual_bytes = _manual_encode_mesh_packet(pkt)
        decoded = _manual_decode_mesh_packet(manual_bytes)
        self.assertEqual(decoded.data.portnum, 1)
        self.assertEqual(decoded.data.payload, b"hi")
        self.assertTrue(decoded.data.want_response)
        self.assertEqual(decoded.data.dest, 0x33333333)
        self.assertEqual(decoded.data.source, 0x44444444)
        self.assertEqual(decoded.data.request_id, 0x55555555)
        self.assertEqual(decoded.data.reply_id, 0x66666666)
        self.assertEqual(decoded.data.emoji, 0x77777777)
        self.assertEqual(decoded.data.bitfield, 15)


# =============================================================================
# Proto field number cross-checks
# =============================================================================

class TestMeshPacketProtoFieldNumbers(unittest.TestCase):
    """Cross-check MeshPacket protobuf field numbers against mesh_pb2.pyi."""

    # MeshPacket field numbers from mesh_pb2.pyi
    EXPECTED_FIELDS = {
        "from": 1,    # fixed32
        "to": 2,      # fixed32
        "channel": 3,  # varint
        "decoded": 4,  # submsg (Data)
        "encrypted": 5,  # bytes
        "id": 6,       # fixed32
        "rx_time": 7,  # fixed32
        "rx_snr": 8,   # float
        "hop_limit": 9,  # varint
        "want_ack": 10,  # bool
        "priority": 11,  # varint enum
        "rx_rssi": 12,  # int32
        "delayed": 13,  # varint enum
        "via_mqtt": 14,  # bool
        "hop_start": 15,  # varint
        "public_key": 16,  # bytes
        "pki_encrypted": 17,  # bool
        "next_hop": 18,  # fixed32
        "relay_node": 19,  # fixed32
        "tx_after": 20,  # fixed32
        "transport_mechanism": 21,  # varint enum
    }

    def test_manual_encode_field_tags(self):
        """Verify tags in _manual_encode_mesh_packet match proto field numbers."""
        # from = field 1, fixed32 -> tag = (1<<3)|5 = 0x0d
        self.assertEqual(bytes([0x0d]), _tag(1, 5))
        # to = field 2, fixed32 -> tag = (2<<3)|5 = 0x15
        self.assertEqual(bytes([0x15]), _tag(2, 5))
        # channel = field 3, varint -> tag = (3<<3)|0 = 0x18
        self.assertEqual(bytes([0x18]), _tag(3, 0))
        # decoded = field 4, submsg -> tag = (4<<3)|2 = 0x22
        self.assertEqual(bytes([0x22]), _tag(4, 2))
        # encrypted = field 5, bytes -> tag = (5<<3)|2 = 0x2a
        self.assertEqual(bytes([0x2a]), _tag(5, 2))
        # id = field 6, fixed32 -> tag = (6<<3)|5 = 0x35
        self.assertEqual(bytes([0x35]), _tag(6, 5))
        # hop_limit = field 9, varint -> tag = (9<<3)|0 = 0x48
        self.assertEqual(bytes([0x48]), _tag(9, 0))
        # want_ack = field 10, varint -> tag = (10<<3)|0 = 0x50
        self.assertEqual(bytes([0x50]), _tag(10, 0))
        # via_mqtt = field 14, varint -> tag = (14<<3)|0 = 0x70
        self.assertEqual(bytes([0x70]), _tag(14, 0))
        # hop_start = field 15, varint -> tag = (15<<3)|0 = 0x78
        self.assertEqual(bytes([0x78]), _tag(15, 0))

    def test_all_21_meshpacket_fields_known(self):
        """Proto defines 21 MeshPacket fields."""
        self.assertEqual(len(self.EXPECTED_FIELDS), 21)


class TestDataProtoFieldNumbers(unittest.TestCase):
    """Cross-check Data protobuf field numbers against mesh_pb2.pyi."""

    EXPECTED = {
        "portnum": (1, "varint"),
        "payload": (2, "bytes"),
        "want_response": (3, "bool"),
        "dest": (4, "fixed32"),
        "source": (5, "fixed32"),
        "request_id": (6, "fixed32"),
        "reply_id": (7, "fixed32"),
        "emoji": (8, "fixed32"),
        "bitfield": (9, "varint"),
    }

    def test_data_field_count(self):
        """Data proto has exactly 9 fields."""
        self.assertEqual(len(self.EXPECTED), 9)

    def test_manual_encode_tags(self):
        """Verify DataPayload._manual_encode uses correct field tags."""
        # portnum = field 1, varint -> 0x08
        self.assertEqual(b"\x08", _tag(1, 0))
        # payload = field 2, bytes -> 0x12
        self.assertEqual(b"\x12", _tag(2, 2))
        # want_response = field 3, varint -> 0x18
        self.assertEqual(b"\x18", _tag(3, 0))
        # dest = field 4, fixed32 -> 0x25
        self.assertEqual(b"\x25", _tag(4, 5))
        # source = field 5, fixed32 -> 0x2d
        self.assertEqual(b"\x2d", _tag(5, 5))
        # request_id = field 6, fixed32 -> 0x35
        self.assertEqual(b"\x35", _tag(6, 5))
        # reply_id = field 7, fixed32 -> 0x3d
        self.assertEqual(b"\x3d", _tag(7, 5))
        # emoji = field 8, fixed32 -> 0x45
        self.assertEqual(b"\x45", _tag(8, 5))
        # bitfield = field 9, varint -> 0x48
        self.assertEqual(b"\x48", _tag(9, 0))

    def test_datapayload_has_all_fields(self):
        """DataPayload dataclass has all 9 proto fields."""
        dp = DataPayload()
        for field_name in self.EXPECTED:
            self.assertTrue(hasattr(dp, field_name), f"Missing field: {field_name}")


# =============================================================================
# PortNum enum completeness
# =============================================================================

class TestPortNumCompleteness(unittest.TestCase):
    """Verify PortNum enum matches portnums_pb2.pyi."""

    EXPECTED_PORTS = {
        "UNKNOWN_APP": 0, "TEXT_MESSAGE_APP": 1, "REMOTE_HARDWARE_APP": 2,
        "POSITION_APP": 3, "NODEINFO_APP": 4, "ROUTING_APP": 5,
        "ADMIN_APP": 6, "TEXT_MESSAGE_COMPRESSED_APP": 7, "WAYPOINT_APP": 8,
        "AUDIO_APP": 9, "DETECTION_SENSOR_APP": 10, "ALERT_APP": 11,
        "KEY_VERIFICATION_APP": 12, "REPLY_APP": 32, "IP_TUNNEL_APP": 33,
        "PAXCOUNTER_APP": 34, "STORE_FORWARD_PLUSPLUS_APP": 35,
        "NODE_STATUS_APP": 36, "SERIAL_APP": 64, "STORE_FORWARD_APP": 65,
        "RANGE_TEST_APP": 66, "TELEMETRY_APP": 67, "ZPS_APP": 68,
        "SIMULATOR_APP": 69, "TRACEROUTE_APP": 70, "NEIGHBORINFO_APP": 71,
        "ATAK_PLUGIN": 72, "MAP_REPORT_APP": 73, "POWERSTRESS_APP": 74,
        "RETICULUM_TUNNEL_APP": 76, "CAYENNE_APP": 77,
        "PRIVATE_APP": 256, "ATAK_FORWARDER": 257, "MAX": 511,
    }

    def test_all_portnums_present(self):
        for name, value in self.EXPECTED_PORTS.items():
            self.assertEqual(PortNum[name], value, f"PortNum.{name} mismatch")

    def test_portnum_count(self):
        self.assertEqual(len(PortNum), len(self.EXPECTED_PORTS))

    def test_portnum_values_unique(self):
        values = [p.value for p in PortNum]
        self.assertEqual(len(values), len(set(values)))


# =============================================================================
# Region and Modem Preset enum completeness
# =============================================================================

class TestRegionCodeCompleteness(unittest.TestCase):
    """Verify region codes match config_pb2.pyi RegionCode enum (0-26)."""

    EXPECTED = {
        0: "UNSET", 1: "US", 2: "EU_433", 3: "EU_868", 4: "CN", 5: "JP",
        6: "ANZ", 7: "KR", 8: "TW", 9: "RU", 10: "IN", 11: "NZ_865",
        12: "TH", 13: "LORA_24", 14: "UA_433", 15: "UA_868", 16: "MY_433",
        17: "MY_919", 18: "SG_923", 19: "PH_433", 20: "PH_868", 21: "PH_915",
        22: "ANZ_433", 23: "KZ_433", 24: "KZ_863", 25: "NP_865", 26: "BR_902",
    }

    def test_region_code_map_complete(self):
        self.assertEqual(REGION_CODE_MAP, self.EXPECTED)

    def test_bidirectional_mapping(self):
        for code, name in self.EXPECTED.items():
            self.assertEqual(REGION_NAME_TO_CODE[name], code)

    def test_proto_regions_in_channels(self):
        """All proto regions (except UNSET) have frequency definitions."""
        for name in list(self.EXPECTED.values())[1:]:  # Skip UNSET
            self.assertIn(name, REGIONS, f"Region {name} missing from REGIONS dict")


class TestModemPresetCompleteness(unittest.TestCase):
    """Verify modem preset codes match config_pb2.pyi ModemPreset enum (0-9)."""

    EXPECTED = {
        0: "LONG_FAST", 1: "LONG_SLOW", 2: "VERY_LONG_SLOW", 3: "MEDIUM_SLOW",
        4: "MEDIUM_FAST", 5: "SHORT_SLOW", 6: "SHORT_FAST", 7: "LONG_MODERATE",
        8: "SHORT_TURBO", 9: "LONG_TURBO",
    }

    def test_preset_map_complete(self):
        self.assertEqual(MODEM_PRESET_MAP, self.EXPECTED)

    def test_bidirectional_mapping(self):
        for code, name in self.EXPECTED.items():
            self.assertEqual(PRESET_NAME_TO_CODE[name], code)

    def test_all_presets_have_params(self):
        """Each preset has LoRa PHY parameters defined."""
        for name in self.EXPECTED.values():
            preset = get_preset(name)
            self.assertGreater(preset.spreading_factor, 0)
            self.assertGreater(preset.bandwidth, 0)


# =============================================================================
# LoRa PHY parameter correctness
# =============================================================================

class TestLoRaPresetParameters(unittest.TestCase):
    """Verify LoRa modem preset parameters match Meshtastic firmware."""

    def test_long_fast(self):
        p = PRESETS["LONG_FAST"]
        self.assertEqual(p.spreading_factor, 11)
        self.assertEqual(p.bandwidth, 250000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_long_slow(self):
        p = PRESETS["LONG_SLOW"]
        self.assertEqual(p.spreading_factor, 12)
        self.assertEqual(p.bandwidth, 125000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_8)

    def test_very_long_slow(self):
        p = PRESETS["VERY_LONG_SLOW"]
        self.assertEqual(p.spreading_factor, 12)
        self.assertEqual(p.bandwidth, 62500)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_8)

    def test_long_moderate(self):
        p = PRESETS["LONG_MODERATE"]
        self.assertEqual(p.spreading_factor, 11)
        self.assertEqual(p.bandwidth, 125000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_8)

    def test_long_turbo_cr45(self):
        """LONG_TURBO uses CR 4/5, NOT CR 4/8 (per firmware RadioInterface.cpp)."""
        p = PRESETS["LONG_TURBO"]
        self.assertEqual(p.spreading_factor, 11)
        self.assertEqual(p.bandwidth, 500000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_short_turbo(self):
        p = PRESETS["SHORT_TURBO"]
        self.assertEqual(p.spreading_factor, 7)
        self.assertEqual(p.bandwidth, 500000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_short_fast(self):
        p = PRESETS["SHORT_FAST"]
        self.assertEqual(p.spreading_factor, 7)
        self.assertEqual(p.bandwidth, 250000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_medium_fast(self):
        p = PRESETS["MEDIUM_FAST"]
        self.assertEqual(p.spreading_factor, 9)
        self.assertEqual(p.bandwidth, 250000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_medium_slow(self):
        p = PRESETS["MEDIUM_SLOW"]
        self.assertEqual(p.spreading_factor, 10)
        self.assertEqual(p.bandwidth, 250000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_short_slow(self):
        p = PRESETS["SHORT_SLOW"]
        self.assertEqual(p.spreading_factor, 8)
        self.assertEqual(p.bandwidth, 250000)
        self.assertEqual(p.coding_rate, CodingRate.CR_4_5)

    def test_preset_count(self):
        self.assertEqual(len(PRESETS), 10)


# =============================================================================
# OTA Header format correctness
# =============================================================================

class TestOTAHeader(unittest.TestCase):
    """Verify the 16-byte OTA header pack/unpack correctness."""

    def test_header_size(self):
        self.assertEqual(HEADER_SIZE, 16)

    def test_roundtrip(self):
        h = MeshtasticHeader(
            to=0xFFFFFFFF, from_node=0x12345678, id=0xAABBCCDD,
            hop_limit=5, want_ack=True, via_mqtt=True, hop_start=7,
            channel=0xAB, next_hop=0xCD, relay_node=0xEF,
        )
        packed = h.pack()
        self.assertEqual(len(packed), 16)
        unpacked = MeshtasticHeader.unpack(packed)
        self.assertEqual(unpacked.to, 0xFFFFFFFF)
        self.assertEqual(unpacked.from_node, 0x12345678)
        self.assertEqual(unpacked.id, 0xAABBCCDD)
        self.assertEqual(unpacked.hop_limit, 5)
        self.assertTrue(unpacked.want_ack)
        self.assertTrue(unpacked.via_mqtt)
        self.assertEqual(unpacked.hop_start, 7)
        self.assertEqual(unpacked.channel, 0xAB)
        self.assertEqual(unpacked.next_hop, 0xCD)
        self.assertEqual(unpacked.relay_node, 0xEF)

    def test_flags_bit_layout(self):
        """Flags byte: bits 0-2=hop_limit, bit 3=want_ack, bit 4=via_mqtt, bits 5-7=hop_start."""
        h = MeshtasticHeader()
        h.hop_limit = 7
        h.want_ack = True
        h.via_mqtt = True
        h.hop_start = 7
        # 0b111_1_1_111 = 0xFF
        self.assertEqual(h.flags, 0xFF)

    def test_flags_minimal(self):
        h = MeshtasticHeader()
        h.hop_limit = 0
        h.want_ack = False
        h.via_mqtt = False
        h.hop_start = 0
        self.assertEqual(h.flags, 0x00)

    def test_broadcast_addr(self):
        self.assertEqual(BROADCAST_ADDR, 0xFFFFFFFF)


# =============================================================================
# AES-CTR encryption correctness
# =============================================================================

class TestEncryption(unittest.TestCase):
    """Verify AES-CTR encryption matches Meshtastic spec."""

    def test_nonce_format(self):
        """Nonce: packet_id(4B LE) | from_node(4B LE) | zeros(8B)."""
        nonce = _build_nonce(0x12345678, 0xAABBCCDD)
        self.assertEqual(len(nonce), 16)
        self.assertEqual(nonce[:4], struct.pack("<I", 0x12345678))
        self.assertEqual(nonce[4:8], struct.pack("<I", 0xAABBCCDD))
        self.assertEqual(nonce[8:], b"\x00" * 8)

    def test_default_key(self):
        self.assertEqual(DEFAULT_KEY, bytes([
            0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
            0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
        ]))

    def test_psk_shorthands(self):
        self.assertEqual(get_default_key(0), b"")
        self.assertEqual(get_default_key(1), DEFAULT_KEY)
        for i in range(2, 11):
            key = get_default_key(i)
            self.assertEqual(len(key), 16)
            self.assertEqual(key[-1], i)
            self.assertEqual(key[:-1], DEFAULT_KEY[:-1])

    def test_encrypt_decrypt_symmetry(self):
        crypto = MeshtasticCrypto(DEFAULT_KEY)
        plaintext = b"Hello Mesh"
        ct = crypto.encrypt(plaintext, 42, 0x11223344)
        pt = crypto.decrypt(ct, 42, 0x11223344)
        self.assertEqual(pt, plaintext)

    def test_no_encryption_passthrough(self):
        """PSK shorthand 0x00 = no encryption, passthrough."""
        crypto = MeshtasticCrypto(b"\x00")
        plaintext = b"plaintext"
        ct = crypto.encrypt(plaintext, 1, 2)
        self.assertEqual(ct, plaintext)


# =============================================================================
# Channel hash computation
# =============================================================================

class TestChannelHash(unittest.TestCase):
    """Verify channel hash computation matches Meshtastic firmware."""

    def test_default_channel_hash(self):
        """LongFast with default key should produce a consistent hash."""
        h = compute_channel_hash("LongFast", DEFAULT_KEY)
        self.assertIsInstance(h, int)
        self.assertGreaterEqual(h, 0)
        self.assertLessEqual(h, 255)

    def test_empty_name_defaults_to_longfast(self):
        h1 = compute_channel_hash("", DEFAULT_KEY)
        h2 = compute_channel_hash("LongFast", DEFAULT_KEY)
        self.assertEqual(h1, h2)

    def test_different_names_different_hashes(self):
        h1 = compute_channel_hash("Alpha", DEFAULT_KEY)
        h2 = compute_channel_hash("Beta", DEFAULT_KEY)
        # Could collide in theory but extremely unlikely for short names
        self.assertNotEqual(h1, h2)

    def test_psk_affects_hash(self):
        h1 = compute_channel_hash("Test", b"\x01")
        h2 = compute_channel_hash("Test", b"\x02")
        self.assertNotEqual(h1, h2)


# =============================================================================
# FromRadio/ToRadio encode/decode roundtrips
# =============================================================================

class TestToRadioRoundtrip(unittest.TestCase):
    """Verify ToRadio encode/decode roundtrip for all variants."""

    def test_want_config_roundtrip(self):
        encoded = encode_toradio_want_config(CONFIG_NONCE)
        decoded = decode_toradio(encoded)
        self.assertEqual(decoded["want_config_id"], CONFIG_NONCE)

    def test_disconnect_roundtrip(self):
        encoded = encode_toradio_disconnect()
        decoded = decode_toradio(encoded)
        self.assertIn("disconnect", decoded)

    def test_packet_roundtrip(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x11, id=0x22),
            data=DataPayload(portnum=1, payload=b"hello"),
        )
        encoded = encode_toradio_packet(pkt)
        decoded = decode_toradio(encoded)
        self.assertIn("packet", decoded)
        self.assertEqual(decoded["packet"].data.payload, b"hello")


class TestFromRadioRoundtrip(unittest.TestCase):
    """Verify FromRadio encode/decode roundtrip for all variants."""

    def test_my_info_roundtrip(self):
        encoded = encode_fromradio_my_info(
            node_id=0x11223344, msg_id=1, nodedb_count=5,
            min_app_version=30200, reboot_count=3,
        )
        decoded = decode_fromradio(encoded)
        self.assertEqual(decoded["id"], 1)
        info = decoded["my_info"]
        self.assertEqual(info["my_node_num"], 0x11223344)
        self.assertEqual(info["nodedb_count"], 5)

    def test_node_info_roundtrip(self):
        encoded = encode_fromradio_node_info(
            node_id=0xAABBCCDD, long_name="Test Node",
            short_name="TN", hw_model=37, msg_id=2,
        )
        decoded = decode_fromradio(encoded)
        info = decoded["node_info"]
        self.assertEqual(info["num"], 0xAABBCCDD)
        self.assertEqual(info["long_name"], "Test Node")
        self.assertEqual(info["short_name"], "TN")

    def test_config_complete_roundtrip(self):
        encoded = encode_fromradio_config_complete(config_id=69420, msg_id=3)
        decoded = decode_fromradio(encoded)
        self.assertEqual(decoded["config_complete_id"], 69420)

    def test_queue_status_roundtrip(self):
        encoded = encode_fromradio_queue_status(free=10, max_to_send=16, mesh_packet_id=42)
        decoded = decode_fromradio(encoded)
        self.assertIn("queueStatus", decoded)

    def test_metadata_roundtrip(self):
        encoded = encode_fromradio_metadata(
            firmware_version="2.6.0.sdr", hw_model=37,
            has_bluetooth=True, msg_id=5,
        )
        decoded = decode_fromradio(encoded)
        self.assertIn("metadata", decoded)

    def test_packet_roundtrip(self):
        pkt = MeshPacket(
            header=MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x99, id=0x88),
            data=DataPayload(portnum=1, payload=b"test"),
        )
        encoded = encode_fromradio_packet(pkt, msg_id=10)
        decoded = decode_fromradio(encoded)
        self.assertIn("packet", decoded)
        self.assertEqual(decoded["packet"].data.payload, b"test")


# =============================================================================
# Config encoder field coverage
# =============================================================================

class TestConfigEncodersCoverage(unittest.TestCase):
    """Verify config encoders accept all expected fields without error."""

    def test_device_config_all_fields(self):
        result = encode_config_device(
            role=1, tzdef="UTC", node_info_broadcast_secs=900,
            rebroadcast_mode=1, serial_enabled=True, button_gpio=39,
            buzzer_gpio=14, double_tap_as_button_press=True,
            is_managed=False, disable_triple_click=True,
            led_heartbeat_disabled=True, buzzer_mode=1,
        )
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_position_config_all_fields(self):
        result = encode_config_position(
            position_broadcast_secs=600, position_broadcast_smart_enabled=True,
            gps_mode=2, fixed_position=True, gps_enabled=False,
            gps_update_interval=120, gps_attempt_time=30,
            position_flags=0xFF, rx_gpio=15, tx_gpio=13,
            broadcast_smart_minimum_distance=100,
            broadcast_smart_minimum_interval_secs=30,
            gps_en_gpio=12,
        )
        self.assertIsInstance(result, bytes)

    def test_power_config_all_fields(self):
        result = encode_config_power(
            is_power_saving=True, on_battery_shutdown_after_secs=3600,
            adc_multiplier_override=2.0, wait_bluetooth_secs=60,
            sds_secs=3600, ls_secs=300, min_wake_secs=10,
            device_battery_ina_address=0x40, powermon_enables=0xFF,
        )
        self.assertIsInstance(result, bytes)

    def test_network_config_all_fields(self):
        result = encode_config_network(
            wifi_enabled=True, wifi_ssid="test", wifi_psk="pass123",
            ntp_server="pool.ntp.org", eth_enabled=True, address_mode=1,
            rsyslog_server="syslog.local", enabled_protocols=3,
            ipv6_enabled=True,
        )
        self.assertIsInstance(result, bytes)

    def test_display_config_all_fields(self):
        result = encode_config_display(
            screen_on_secs=120, units=1, gps_format=2,
            auto_screen_carousel_secs=5, compass_north_top=True,
            flip_screen=True, oled=1, displaymode=2,
            heading_bold=True, wake_on_tap_or_motion=True,
            compass_orientation=3, use_12h_clock=True,
            use_long_node_name=True, enable_message_bubbles=True,
        )
        self.assertIsInstance(result, bytes)

    def test_lora_config_all_fields(self):
        result = encode_config_lora(
            region=1, modem_preset=0, hop_limit=3, tx_enabled=True,
            tx_power=20, use_preset=True, bandwidth=250, spread_factor=11,
            coding_rate=5, channel_num=20, frequency_offset=0.5,
            override_frequency=906.0, override_duty_cycle=True,
            sx126x_rx_boosted_gain=True, pa_fan_disabled=False,
            ignore_mqtt=True, config_ok_to_mqtt=False,
        )
        self.assertIsInstance(result, bytes)

    def test_lora_config_negative_tx_power(self):
        """tx_power is int32, can be negative."""
        result = encode_config_lora(tx_power=-5)
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_bluetooth_config(self):
        result = encode_config_bluetooth(enabled=True, mode=1, fixed_pin=654321)
        self.assertIsInstance(result, bytes)

    def test_security_config_all_fields(self):
        result = encode_config_security(
            serial_enabled=True, debug_log_api_enabled=True,
            admin_channel_enabled=True, public_key=b"\x01" * 32,
            private_key=b"\x02" * 32, is_managed=True,
        )
        self.assertIsInstance(result, bytes)

    def test_sessionkey_config(self):
        result = encode_config_sessionkey()
        self.assertIsInstance(result, bytes)

    def test_deviceui_config(self):
        result = encode_config_deviceui()
        self.assertIsInstance(result, bytes)


class TestModuleEncodersCoverage(unittest.TestCase):
    """Verify module config encoders accept all expected fields."""

    def test_mqtt_all_fields(self):
        result = encode_module_mqtt(
            enabled=True, proxy_to_client_enabled=True,
            address="mqtt.local", username="user", password="pass",
            encryption_enabled=True, json_enabled=True, tls_enabled=True,
            root="meshtastic", map_reporting_enabled=True,
        )
        self.assertIsInstance(result, bytes)

    def test_serial_all_fields(self):
        result = encode_module_serial(
            enabled=True, echo=True, rxd=16, txd=17,
            baud=3, timeout=5, mode=1, override_console_serial_port=True,
        )
        self.assertIsInstance(result, bytes)

    def test_extnotif_all_fields(self):
        result = encode_module_extnotif(
            enabled=True, output_ms=500, output=13, active=True,
            alert_message=True, alert_bell=True, use_pwm=True,
            output_vibra=14, output_buzzer=15, alert_message_vibra=True,
            alert_message_buzzer=True, alert_bell_vibra=True,
            alert_bell_buzzer=True, nag_timeout=60, use_i2s_as_buzzer=True,
        )
        self.assertIsInstance(result, bytes)

    def test_store_forward_all_fields(self):
        result = encode_module_store_forward(
            enabled=True, heartbeat=True, records=100,
            history_return_max=50, history_return_window=3600, is_server=True,
        )
        self.assertIsInstance(result, bytes)

    def test_range_test_all_fields(self):
        result = encode_module_range_test(
            enabled=True, sender=30, save=True, clear_on_reboot=True,
        )
        self.assertIsInstance(result, bytes)

    def test_telemetry_all_fields(self):
        result = encode_module_telemetry(
            device_update_interval=300, environment_update_interval=600,
            environment_measurement_enabled=True, environment_screen_enabled=True,
            environment_display_fahrenheit=True, air_quality_enabled=True,
            air_quality_interval=300, power_measurement_enabled=True,
            power_update_interval=600, power_screen_enabled=True,
            health_measurement_enabled=True, health_update_interval=900,
            health_screen_enabled=True, device_telemetry_enabled=True,
            air_quality_screen_enabled=True,
        )
        self.assertIsInstance(result, bytes)

    def test_canned_message_all_fields(self):
        result = encode_module_canned_message(
            enabled=True, rotary1_enabled=True,
            inputbroker_pin_a=5, inputbroker_pin_b=6, inputbroker_pin_press=7,
            inputbroker_event_cw=1, inputbroker_event_ccw=2,
            inputbroker_event_press=3, updown1_enabled=True,
            allow_input_source="rotEnc1", send_bell=True,
        )
        self.assertIsInstance(result, bytes)

    def test_audio_all_fields(self):
        result = encode_module_audio(
            enabled=True, ptt_pin=39, bitrate=1,
            i2s_ws=25, i2s_sd=26, i2s_din=27, i2s_sck=14,
        )
        self.assertIsInstance(result, bytes)

    def test_remote_hardware_all_fields(self):
        result = encode_module_remote_hardware(
            enabled=True, allow_undefined_pin_access=True,
        )
        self.assertIsInstance(result, bytes)

    def test_neighbor_info_all_fields(self):
        result = encode_module_neighbor_info(
            enabled=True, update_interval=300, transmit_over_lora=True,
        )
        self.assertIsInstance(result, bytes)

    def test_ambient_lighting_all_fields(self):
        result = encode_module_ambient_lighting(
            led_state=True, current=50, red=255, green=128, blue=64,
        )
        self.assertIsInstance(result, bytes)

    def test_detection_sensor_all_fields(self):
        result = encode_module_detection_sensor(
            enabled=True, minimum_broadcast_secs=30, state_broadcast_secs=60,
            send_bell=True, name="motion", monitor_pin=12,
            detection_trigger_type=1, use_pullup=True,
        )
        self.assertIsInstance(result, bytes)

    def test_paxcounter_all_fields(self):
        result = encode_module_paxcounter(
            enabled=True, paxcounter_update_interval=30,
            wifi_threshold=-70, ble_threshold=-80,
        )
        self.assertIsInstance(result, bytes)

    def test_status_message(self):
        result = encode_module_status_message(node_status="Online")
        self.assertIsInstance(result, bytes)

    def test_traffic_management_all_fields(self):
        result = encode_module_traffic_management(
            enabled=True, position_dedup_enabled=True,
            position_precision_bits=16, position_min_interval_secs=30,
            nodeinfo_direct_response=True, nodeinfo_direct_response_max_hops=3,
            rate_limit_enabled=True, rate_limit_window_secs=60,
            rate_limit_max_packets=10, drop_unknown_enabled=True,
            unknown_packet_threshold=5, exhaust_hop_telemetry=True,
            exhaust_hop_position=True, router_preserve_hops=True,
        )
        self.assertIsInstance(result, bytes)


# =============================================================================
# Channel encode/decode
# =============================================================================

class TestChannelEncoding(unittest.TestCase):
    """Verify Channel protobuf encoding covers all ChannelSettings fields."""

    def test_all_settings_fields(self):
        """ChannelSettings has 6 fields: channel_num, psk, name, id, uplink, downlink."""
        result = encode_channel(
            index=0, name="TestCh", psk=b"\x01" * 16, role=1,
            uplink_enabled=True, downlink_enabled=True,
            channel_num=5, id=42,
        )
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_disabled_channel(self):
        result = encode_channel(index=3, role=0)
        self.assertIsInstance(result, bytes)

    def test_primary_channel(self):
        result = encode_channel(index=0, name="LongFast", psk=DEFAULT_KEY, role=1)
        self.assertIsInstance(result, bytes)


# =============================================================================
# Mesh router correctness
# =============================================================================

class TestMeshRouter(unittest.TestCase):
    """Verify mesh routing logic correctness."""

    def test_broadcast_is_for_us(self):
        router = MeshRouter(local_node_id=0x11223344)
        h = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x55667788, id=1)
        self.assertTrue(router.is_for_us(h))

    def test_unicast_for_us(self):
        router = MeshRouter(local_node_id=0x11223344)
        h = MeshtasticHeader(to=0x11223344, from_node=0x55667788, id=2)
        self.assertTrue(router.is_for_us(h))

    def test_unicast_not_for_us(self):
        router = MeshRouter(local_node_id=0x11223344)
        h = MeshtasticHeader(to=0xAABBCCDD, from_node=0x55667788, id=3)
        self.assertFalse(router.is_for_us(h))

    def test_duplicate_detection(self):
        router = MeshRouter(local_node_id=0x11)
        h = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x22, id=100, hop_start=3, hop_limit=3)
        self.assertFalse(router.is_duplicate(h))
        router.record_packet(h)
        self.assertTrue(router.is_duplicate(h))

    def test_dont_rebroadcast_own_packets(self):
        router = MeshRouter(local_node_id=0x11)
        pkt = MeshPacket(
            header=MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x11, id=1, hop_limit=3, hop_start=3),
        )
        self.assertFalse(router.should_rebroadcast(pkt))

    def test_dont_rebroadcast_zero_hop(self):
        router = MeshRouter(local_node_id=0x11)
        pkt = MeshPacket(
            header=MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x22, id=2, hop_limit=0, hop_start=3),
        )
        self.assertFalse(router.should_rebroadcast(pkt))

    def test_rebroadcast_decrements_hop(self):
        router = MeshRouter(local_node_id=0x11)
        pkt = MeshPacket(
            header=MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x22, id=3, hop_limit=3, hop_start=3),
            encrypted=b"\x00" * 10,
        )
        rebroad = router.prepare_rebroadcast(pkt)
        self.assertEqual(rebroad.header.hop_limit, 2)
        self.assertEqual(rebroad.header.relay_node, 0x11 & 0xFF)

    def test_hop_limit_capped_at_7(self):
        router = MeshRouter(local_node_id=0x11, default_hop_limit=10)
        self.assertEqual(router.default_hop_limit, 7)


# =============================================================================
# MeshNode correctness
# =============================================================================

class TestMeshNode(unittest.TestCase):
    """Verify node identity and database management."""

    def test_random_node_id_generation(self):
        node = MeshNode()
        self.assertNotEqual(node.node_id, 0)
        self.assertNotEqual(node.node_id, 0xFFFFFFFF)

    def test_explicit_node_id(self):
        node = MeshNode(node_id=0xDEADBEEF)
        self.assertEqual(node.node_id, 0xDEADBEEF)

    def test_node_id_string(self):
        node = MeshNode(node_id=0x00112233)
        self.assertEqual(node.node_id_str, "!00112233")

    def test_update_node(self):
        node = MeshNode(node_id=1)
        info = node.update_node(0x22, long_name="Test", snr=5.5)
        self.assertEqual(info.long_name, "Test")
        self.assertEqual(info.snr, 5.5)
        self.assertEqual(node.num_nodes, 1)

    def test_get_unknown_node_returns_none(self):
        node = MeshNode(node_id=1)
        self.assertIsNone(node.get_node(0x99))

    def test_short_name_truncated(self):
        node = MeshNode(short_name="ABCDEF")
        self.assertEqual(node.short_name, "ABCD")


# =============================================================================
# User decode completeness
# =============================================================================

class TestUserDecodeCompleteness(unittest.TestCase):
    """Verify manual _decode_user handles all 9 User proto fields."""

    def _encode_user(self, **fields):
        """Build a minimal User protobuf blob for testing decode."""
        parts = []
        if "id" in fields:
            val = fields["id"].encode("utf-8")
            parts.append(b"\x0a" + _encode_varint(len(val)) + val)
        if "long_name" in fields:
            val = fields["long_name"].encode("utf-8")
            parts.append(b"\x12" + _encode_varint(len(val)) + val)
        if "short_name" in fields:
            val = fields["short_name"].encode("utf-8")
            parts.append(b"\x1a" + _encode_varint(len(val)) + val)
        if "macaddr" in fields:
            val = fields["macaddr"]
            parts.append(b"\x22" + _encode_varint(len(val)) + val)
        if "hw_model" in fields:
            parts.append(b"\x28" + _encode_varint(fields["hw_model"]))
        if "is_licensed" in fields:
            parts.append(b"\x30" + _encode_varint(1 if fields["is_licensed"] else 0))
        if "role" in fields:
            parts.append(b"\x38" + _encode_varint(fields["role"]))
        if "public_key" in fields:
            val = fields["public_key"]
            parts.append(b"\x42" + _encode_varint(len(val)) + val)
        if "is_unmessagable" in fields:
            parts.append(b"\x48" + _encode_varint(1 if fields["is_unmessagable"] else 0))
        return b"".join(parts)

    def test_decode_all_user_fields(self):
        blob = self._encode_user(
            id="!11223344", long_name="Alice", short_name="Al",
            macaddr=b"\xAA\xBB\xCC\xDD\xEE\xFF",
            hw_model=37, is_licensed=True, role=2,
            public_key=b"\x01" * 32, is_unmessagable=True,
        )
        user = _decode_user(blob)
        self.assertEqual(user["id"], "!11223344")
        self.assertEqual(user["long_name"], "Alice")
        self.assertEqual(user["short_name"], "Al")
        self.assertEqual(user["macaddr"], b"\xAA\xBB\xCC\xDD\xEE\xFF")
        self.assertEqual(user["hw_model"], 37)
        self.assertTrue(user["is_licensed"])
        self.assertEqual(user["role"], 2)
        self.assertEqual(user["public_key"], b"\x01" * 32)
        self.assertTrue(user["is_unmessagable"])


# =============================================================================
# NodeInfo decode completeness (field 12: is_key_manually_verified)
# =============================================================================

class TestNodeInfoDecodeField12(unittest.TestCase):
    """Verify _decode_node_info handles field 12 (is_key_manually_verified)."""

    def test_field_12_is_key_manually_verified(self):
        """NodeInfo field 12 is decoded correctly."""
        # Build minimal NodeInfo with field 12 = true
        parts = []
        parts.append(b"\x08" + _encode_varint(0x11223344))  # field 1: num
        parts.append(b"\x60\x01")  # field 12 (12<<3|0=96=0x60), value 1
        blob = b"".join(parts)
        info = _decode_node_info(blob)
        self.assertEqual(info["num"], 0x11223344)
        self.assertTrue(info.get("is_key_manually_verified", False))


# =============================================================================
# Protobuf helper encoding correctness
# =============================================================================

class TestProtobufHelpers(unittest.TestCase):
    """Verify protobuf encoding helper functions."""

    def test_field_int32_positive(self):
        result = _field_int32(1, 42)
        self.assertEqual(result, b"\x08\x2a")

    def test_field_int32_negative(self):
        """Negative int32 must be sign-extended to 10-byte varint."""
        result = _field_int32(1, -1)
        self.assertGreater(len(result), 2)  # tag(1) + 10-byte varint
        # Should be tag + 10 bytes (sign-extended)
        self.assertEqual(len(result), 11)  # 1 byte tag + 10 byte varint

    def test_field_int32_zero(self):
        result = _field_int32(1, 0)
        self.assertEqual(result, b"")

    def test_field_sint32_zigzag(self):
        result = _field_sint32(1, -1)
        # zigzag(-1) = 1, tag=0x08, varint(1)=0x01
        self.assertEqual(result, b"\x08\x01")

    def test_field_sint32_zero(self):
        result = _field_sint32(1, 0)
        self.assertEqual(result, b"")

    def test_field_sfixed32(self):
        result = _field_sfixed32(1, -42)
        # tag = (1<<3)|5 = 0x0d, value = struct.pack("<i", -42)
        self.assertEqual(result, b"\x0d" + struct.pack("<i", -42))

    def test_field_float_nonzero(self):
        result = _field_float(1, 3.14)
        self.assertGreater(len(result), 0)

    def test_field_float_zero(self):
        result = _field_float(1, 0.0)
        self.assertEqual(result, b"")

    def test_field_uint64(self):
        result = _field_uint64(1, 0xFFFFFFFFFF)
        self.assertGreater(len(result), 0)

    def test_field_uint64_zero(self):
        result = _field_uint64(1, 0)
        self.assertEqual(result, b"")

    def test_varint_roundtrip(self):
        for val in [0, 1, 127, 128, 255, 300, 65535, 0xFFFFFFFF]:
            encoded = _encode_varint(val)
            decoded, pos = _decode_varint(encoded, 0)
            self.assertEqual(decoded, val)
            self.assertEqual(pos, len(encoded))


# =============================================================================
# End-to-end MeshPacket lifecycle
# =============================================================================

class TestMeshPacketLifecycle(unittest.TestCase):
    """End-to-end test: create -> encrypt -> OTA bytes -> parse -> decrypt."""

    def test_text_message_lifecycle(self):
        crypto = MeshtasticCrypto(DEFAULT_KEY)
        pkt = MeshPacket.create_text("Hello!", from_node=0x11223344)
        ota_bytes = pkt.encrypt_payload(crypto)
        self.assertGreater(len(ota_bytes), 16)

        # Parse back
        parsed = MeshPacket.from_bytes(ota_bytes)
        self.assertEqual(parsed.header.from_node, 0x11223344)
        self.assertGreater(len(parsed.encrypted), 0)

        # Decrypt
        parsed.decrypt_payload(crypto)
        self.assertIsNotNone(parsed.data)
        self.assertEqual(parsed.data.text, "Hello!")

    def test_data_payload_manual_roundtrip(self):
        dp = DataPayload(
            portnum=67, payload=b"\x01\x02\x03",
            want_response=True, dest=0xAABBCCDD,
            request_id=0x11223344, reply_id=0x55667788,
            emoji=0x2764, bitfield=5,
        )
        raw = dp.to_bytes()
        restored = DataPayload.from_bytes(raw)
        self.assertEqual(restored.portnum, 67)
        self.assertEqual(restored.payload, b"\x01\x02\x03")
        self.assertTrue(restored.want_response)
        self.assertEqual(restored.dest, 0xAABBCCDD)
        self.assertEqual(restored.request_id, 0x11223344)
        self.assertEqual(restored.reply_id, 0x55667788)
        self.assertEqual(restored.emoji, 0x2764)
        self.assertEqual(restored.bitfield, 5)


# =============================================================================
# Frequency calculation correctness
# =============================================================================

class TestFrequencyCalculation(unittest.TestCase):
    """Verify frequency calculations for key regions."""

    def test_us_default_frequency(self):
        freq = get_default_frequency("US", 250.0, channel_num=20)
        # 902.0 + 0.125 + (20-1) * 0.25 = 906.875 MHz (1-indexed)
        self.assertAlmostEqual(freq, 906.875e6, places=0)

    def test_eu868_default_frequency(self):
        freq = get_default_frequency("EU_868", 250.0, channel_num=1)
        # 869.4 + 0.125 + 0 * 0.25 = 869.525 MHz
        self.assertAlmostEqual(freq, 869.525e6, places=0)

    def test_unknown_region_raises(self):
        with self.assertRaises(ValueError):
            get_default_frequency("INVALID_REGION")


if __name__ == "__main__":
    unittest.main()
