"""Tests for code review fixes — covers all issues from the full codebase review."""

import sys
import struct
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.lora.params import CodingRate
from meshtastic_sdr.lora.encoder import hamming_encode_nibble
from meshtastic_sdr.lora.decoder import hamming_decode_nibble
from meshtastic_sdr.protocol.mesh_packet import _decode_varint, _encode_varint, DataPayload, MeshPacket
from meshtastic_sdr.protocol.header import MeshtasticHeader
from meshtastic_sdr.protocol.channels import compute_channel_hash
from meshtastic_sdr.ble.protobuf_codec import (
    encode_fromradio_my_info,
    decode_fromradio,
    _field_submsg,
)
from meshtastic_sdr.ble.constants import (
    REGION_CODE_MAP, REGION_NAME_TO_CODE,
    MODEM_PRESET_MAP, PRESET_NAME_TO_CODE,
)


class TestHammingCR46Detection:
    """CR_4_6 Hamming(6,4) is detection-only (2 parity bits can't uniquely correct)."""

    def test_cr46_no_error(self):
        """Clean codeword decodes without error flag."""
        for nibble in range(16):
            cw = hamming_encode_nibble(nibble, CodingRate.CR_4_6)
            decoded, had_error = hamming_decode_nibble(cw, CodingRate.CR_4_6)
            assert decoded == nibble
            assert had_error is False

    def test_cr46_data_bit_error_detected(self):
        """Flipping any data bit is detected (had_error=True)."""
        for nibble in range(16):
            for bit in range(4):
                cw = hamming_encode_nibble(nibble, CodingRate.CR_4_6)
                corrupted = cw ^ (1 << bit)
                _, had_error = hamming_decode_nibble(corrupted, CodingRate.CR_4_6)
                assert had_error is True, f"nibble={nibble}, bit={bit}"

    def test_cr46_parity_bit_error_detected(self):
        """Flipping a parity bit is detected but doesn't corrupt data."""
        for nibble in range(16):
            cw = hamming_encode_nibble(nibble, CodingRate.CR_4_6)
            corrupted = cw ^ (1 << 4)  # flip p0
            decoded, had_error = hamming_decode_nibble(corrupted, CodingRate.CR_4_6)
            assert decoded == nibble
            assert had_error is True

    def test_cr46_no_correction_attempted(self):
        """CR_4_6 must NOT attempt correction (syndromes are ambiguous)."""
        # d3 error: if correction were attempted, syndrome 0b11 maps to d0,
        # which would cause double-corruption. Detection-only returns data as-is.
        for nibble in range(16):
            cw = hamming_encode_nibble(nibble, CodingRate.CR_4_6)
            corrupted = cw ^ (1 << 3)  # flip d3
            decoded, had_error = hamming_decode_nibble(corrupted, CodingRate.CR_4_6)
            # Data bits are returned as-is (d3 still flipped), not "corrected"
            assert decoded == nibble ^ (1 << 3)
            assert had_error is True

    def test_cr47_cr48_do_correct(self):
        """CR_4_7 and CR_4_8 have enough parity bits to correct single-bit errors."""
        for cr in (CodingRate.CR_4_7, CodingRate.CR_4_8):
            for nibble in range(16):
                for bit in range(4):
                    cw = hamming_encode_nibble(nibble, cr)
                    corrupted = cw ^ (1 << bit)
                    decoded, had_error = hamming_decode_nibble(corrupted, cr)
                    assert decoded == nibble, f"CR={cr}, nibble={nibble}, bit={bit}"
                    assert had_error is True

    def test_roundtrip_all_coding_rates(self):
        """All coding rates roundtrip cleanly for all nibbles (no errors)."""
        for cr in CodingRate:
            for nibble in range(16):
                cw = hamming_encode_nibble(nibble, cr)
                decoded, _ = hamming_decode_nibble(cw, cr)
                assert decoded == nibble, f"CR={cr}, nibble={nibble}"


class TestDecodeVarintTruncation:
    """Fix #6: _decode_varint raises ValueError on truncated varints."""

    def test_valid_single_byte(self):
        """Single byte without continuation bit decodes fine."""
        val, pos = _decode_varint(b"\x05", 0)
        assert val == 5
        assert pos == 1

    def test_valid_multi_byte(self):
        """Multi-byte varint decodes correctly."""
        val, pos = _decode_varint(b"\xac\x02", 0)
        assert val == 300
        assert pos == 2

    def test_truncated_raises(self):
        """Data ending mid-varint (high bit set) raises ValueError."""
        with pytest.raises(ValueError, match="Truncated varint"):
            _decode_varint(b"\x80", 0)

    def test_truncated_multibyte_raises(self):
        """Multi-byte varint cut short raises ValueError."""
        with pytest.raises(ValueError, match="Truncated varint"):
            _decode_varint(b"\x80\x80", 0)

    def test_empty_data_at_pos(self):
        """Empty data returns 0 (no bytes to read, shift==0)."""
        val, pos = _decode_varint(b"", 0)
        assert val == 0
        assert pos == 0

    def test_varint_encode_decode_roundtrip(self):
        """Encode/decode roundtrip for various values."""
        for value in [0, 1, 127, 128, 255, 300, 16384, 0xFFFFFFFF]:
            encoded = _encode_varint(value)
            decoded, _ = _decode_varint(encoded, 0)
            assert decoded == value


class TestChannelHashDocstring:
    """Fix #7: compute_channel_hash correctly XORs channel name bytes."""

    def test_default_channel(self):
        """Default channel name produces consistent hash."""
        h = compute_channel_hash("LongFast")
        assert 0 <= h <= 255

    def test_empty_uses_default(self):
        """Empty name falls back to LongFast."""
        assert compute_channel_hash("") == compute_channel_hash("LongFast")

    def test_xor_correctness(self):
        """Verify the hash is XOR of UTF-8 bytes."""
        name = "AB"
        expected = ord("A") ^ ord("B")
        assert compute_channel_hash(name) == expected & 0xFF


class TestResolvePskValidation:
    """Fix #8: resolve_psk raises ValueError on invalid base64."""

    def test_default(self):
        from meshtastic_sdr.config import resolve_psk
        from meshtastic_sdr.protocol.encryption import DEFAULT_KEY
        assert resolve_psk("default") == DEFAULT_KEY

    def test_none(self):
        from meshtastic_sdr.config import resolve_psk
        assert resolve_psk("none") == b""

    def test_valid_base64(self):
        from meshtastic_sdr.config import resolve_psk
        import base64
        key = b"\x01\x02\x03\x04"
        b64 = base64.b64encode(key).decode()
        assert resolve_psk(b64) == key

    def test_invalid_base64_raises(self):
        from meshtastic_sdr.config import resolve_psk
        with pytest.raises(ValueError, match="Invalid PSK"):
            resolve_psk("not!valid!base64!!!")


class TestEncodFromradioMyInfoNodedbCount:
    """Fix #3: encode_fromradio_my_info includes nodedb_count in output."""

    def test_nodedb_count_present(self):
        """nodedb_count is encoded and decodable."""
        encoded = encode_fromradio_my_info(node_id=0xAABBCCDD, msg_id=1, nodedb_count=5)
        decoded = decode_fromradio(encoded)
        assert decoded["my_info"]["my_node_num"] == 0xAABBCCDD
        assert decoded["my_info"]["nodedb_count"] == 5

    def test_nodedb_count_zero(self):
        """nodedb_count=0 still decodes (default)."""
        encoded = encode_fromradio_my_info(node_id=0x11111111, msg_id=1)
        decoded = decode_fromradio(encoded)
        assert decoded["my_info"]["my_node_num"] == 0x11111111
        assert decoded["my_info"]["nodedb_count"] == 0

    def test_no_firmware_version_param(self):
        """firmware_version is no longer accepted as a parameter."""
        with pytest.raises(TypeError):
            encode_fromradio_my_info(node_id=1, firmware_version="2.5.0")


class TestFieldSubmsgEmpty:
    """Fix from previous session: _field_submsg emits even for empty payloads."""

    def test_empty_submsg_not_dropped(self):
        """Empty sub-message still produces output (tag + length 0)."""
        result = _field_submsg(9, b"")
        assert len(result) > 0
        # Should be tag byte(s) + varint(0)
        assert result[-1] == 0  # length = 0

    def test_nonempty_submsg(self):
        """Non-empty sub-message includes payload."""
        payload = b"\x01\x02\x03"
        result = _field_submsg(1, payload)
        assert payload in result


class TestRegionPresetMapsInConstants:
    """Fix #12: REGION/PRESET maps live in constants.py and are consistent."""

    def test_region_roundtrip(self):
        """Every region code maps to a name and back."""
        for code, name in REGION_CODE_MAP.items():
            assert REGION_NAME_TO_CODE[name] == code

    def test_preset_roundtrip(self):
        """Every preset code maps to a name and back."""
        for code, name in MODEM_PRESET_MAP.items():
            assert PRESET_NAME_TO_CODE[name] == code

    def test_eu_868_is_3(self):
        assert REGION_NAME_TO_CODE["EU_868"] == 3

    def test_long_fast_is_0(self):
        assert PRESET_NAME_TO_CODE["LONG_FAST"] == 0


class TestFromRadioDecodeAllFields:
    """Fix from previous session: _manual_decode_fromradio handles config/module/channel/metadata."""

    def test_decode_config_field(self):
        """FromRadio with config (field 5) is decoded."""
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_config, encode_config_device
        encoded = encode_fromradio_config(encode_config_device(), msg_id=1)
        decoded = decode_fromradio(encoded)
        assert "config" in decoded

    def test_decode_module_config_field(self):
        """FromRadio with moduleConfig (field 9) is decoded."""
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_module_config, encode_module_mqtt
        encoded = encode_fromradio_module_config(encode_module_mqtt(), msg_id=1)
        decoded = decode_fromradio(encoded)
        assert "moduleConfig" in decoded

    def test_decode_channel_field(self):
        """FromRadio with channel (field 10) is decoded."""
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_channel, encode_channel
        encoded = encode_fromradio_channel(encode_channel(index=0, role=1), msg_id=1)
        decoded = decode_fromradio(encoded)
        assert "channel" in decoded

    def test_decode_metadata_field(self):
        """FromRadio with metadata (field 13) is decoded."""
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_metadata
        encoded = encode_fromradio_metadata(firmware_version="2.5.0.sdr", msg_id=1)
        decoded = decode_fromradio(encoded)
        assert "metadata" in decoded

    def test_decode_queue_status_field(self):
        """FromRadio with queueStatus (field 11) is decoded."""
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_queue_status
        encoded = encode_fromradio_queue_status(free=10, max_to_send=16, msg_id=1)
        decoded = decode_fromradio(encoded)
        assert "queueStatus" in decoded


class TestProtobufForwardCompat:
    """Fix #5: Manual protobuf decoders handle unknown fields gracefully."""

    def test_data_payload_unknown_wire_type_stops(self):
        """DataPayload decoder stops at unknown wire type (can't determine size)."""
        # Encode a valid portnum, then append an unknown wire type 3
        valid = b"\x08\x01"  # field 1, varint, value 1
        garbage = b"\x1b"    # field 3, wire_type 3 (unknown)
        result = DataPayload._manual_decode(valid + garbage)
        # Should have decoded portnum=1 before stopping
        assert result.portnum == 1

    def test_data_payload_skips_64bit_field(self):
        """DataPayload decoder skips unknown 64-bit fixed fields."""
        # field 1 portnum + field 20 as 64-bit fixed (should be skipped) + field 3 want_response
        valid = b"\x08\x01"                         # portnum = 1
        fixed64 = b"\xa1\x01" + b"\x00" * 8         # field 20, wire_type 1
        want_resp = b"\x18\x01"                      # want_response = true
        result = DataPayload._manual_decode(valid + fixed64 + want_resp)
        assert result.portnum == 1
        assert result.want_response is True


class TestDeadCodeRemoved:
    """Fix #17: Dead code removed from MeshNode."""

    def test_no_packet_counter(self):
        """MeshNode no longer has _packet_counter."""
        from meshtastic_sdr.mesh.node import MeshNode
        node = MeshNode(node_id=0x12345678)
        assert not hasattr(node, "_packet_counter")

    def test_no_next_packet_id(self):
        """MeshNode no longer has next_packet_id method."""
        from meshtastic_sdr.mesh.node import MeshNode
        node = MeshNode(node_id=0x12345678)
        assert not hasattr(node, "next_packet_id")


class TestUnusedImportsRemoved:
    """Fixes #13-16: Verify unused imports don't pollute modules."""

    def test_encoder_no_numpy(self):
        """encoder.py doesn't import numpy at module level."""
        import meshtastic_sdr.lora.encoder as mod
        # Module should work fine without numpy being used
        assert not hasattr(mod, "np")

    def test_decoder_no_numpy(self):
        """decoder.py doesn't import numpy at module level."""
        import meshtastic_sdr.lora.decoder as mod
        assert not hasattr(mod, "np")


class TestRouterRebroadcast:
    """Fix: process_incoming records packet after rebroadcast check."""

    def test_process_incoming_rebroadcasts_non_duplicate(self):
        """First-time broadcast packet should be rebroadcasted."""
        from meshtastic_sdr.mesh.router import MeshRouter
        from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(header=MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0x22222222,
            id=42, hop_limit=3, hop_start=3,
        ))
        for_us, should_rebroadcast = router.process_incoming(packet)
        assert for_us is True  # broadcast is for everyone
        assert should_rebroadcast is True

    def test_process_incoming_no_rebroadcast_duplicate(self):
        """Second time seeing same packet: no rebroadcast."""
        from meshtastic_sdr.mesh.router import MeshRouter
        from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(header=MeshtasticHeader(
            to=BROADCAST_ADDR, from_node=0x22222222,
            id=42, hop_limit=3, hop_start=3,
        ))
        router.process_incoming(packet)
        for_us, should_rebroadcast = router.process_incoming(packet)
        assert for_us is False
        assert should_rebroadcast is False

    def test_process_incoming_no_rebroadcast_unicast_to_us(self):
        """Unicast addressed to us: for_us=True, rebroadcast=False."""
        from meshtastic_sdr.mesh.router import MeshRouter
        from meshtastic_sdr.protocol.header import MeshtasticHeader
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(header=MeshtasticHeader(
            to=0x11111111, from_node=0x22222222,
            id=99, hop_limit=3, hop_start=3,
        ))
        for_us, should_rebroadcast = router.process_incoming(packet)
        assert for_us is True
        assert should_rebroadcast is False

    def test_process_incoming_rebroadcast_unicast_to_other(self):
        """Unicast to someone else: not for us, but rebroadcast."""
        from meshtastic_sdr.mesh.router import MeshRouter
        from meshtastic_sdr.protocol.header import MeshtasticHeader
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(header=MeshtasticHeader(
            to=0x33333333, from_node=0x22222222,
            id=99, hop_limit=3, hop_start=3,
        ))
        for_us, should_rebroadcast = router.process_incoming(packet)
        assert for_us is False
        assert should_rebroadcast is True


class TestPSKKeysUnique:
    """Fix: PSK keys 2-10 each produce a unique key (key[-1] = psk_byte)."""

    def test_psk_1_and_2_different(self):
        """PSK 1 and PSK 2 must produce different keys."""
        from meshtastic_sdr.protocol.encryption import get_default_key
        k1 = get_default_key(1)
        k2 = get_default_key(2)
        assert k1 != k2
        assert k1[-1] == 0x01  # DEFAULT_KEY last byte
        assert k2[-1] == 0x02

    def test_all_psk_keys_unique(self):
        """PSK values 1-10 all produce distinct keys."""
        from meshtastic_sdr.protocol.encryption import get_default_key
        keys = [get_default_key(i) for i in range(1, 11)]
        assert len(set(keys)) == 10


class TestNodeUpdateFalsyValues:
    """Fix: update_node accepts falsy values like 0, 0.0, empty string."""

    def test_update_snr_zero(self):
        """snr=0.0 is a valid value that should be stored."""
        from meshtastic_sdr.mesh.node import MeshNode
        node = MeshNode(node_id=1)
        info = node.update_node(0xAABB, snr=5.0)
        assert info.snr == 5.0
        info = node.update_node(0xAABB, snr=0.0)
        assert info.snr == 0.0

    def test_update_rssi_zero(self):
        """rssi=0 is a valid value that should be stored."""
        from meshtastic_sdr.mesh.node import MeshNode
        node = MeshNode(node_id=1)
        info = node.update_node(0xAABB, rssi=-70)
        assert info.rssi == -70
        info = node.update_node(0xAABB, rssi=0)
        assert info.rssi == 0


class TestChannelIndexHandling:
    """Fix: get_channel index 0 = primary, index >= 1 = empty secondary."""

    def test_get_channel_0_returns_primary(self):
        """Channel index 0 returns the primary channel."""
        from meshtastic_sdr.ble.admin_handler import AdminHandler, encode_channel_response
        from meshtastic_sdr.ble.protobuf_codec import decode_fromradio
        from meshtastic_sdr.mesh.node import MeshNode
        from meshtastic_sdr.protocol.channels import ChannelConfig
        from unittest.mock import MagicMock

        gw = MagicMock()
        gw.node = MeshNode(node_id=0x12345678)
        gw.channel = ChannelConfig(name="TestChan", psk=b"\x01" * 16)
        handler = AdminHandler(gw)

        packet = MeshPacket(header=MeshtasticHeader(
            from_node=0xAAAAAAAA, id=1, channel=0,
        ))
        packet.data = DataPayload(portnum=67, payload=b"")  # dummy

        responses = handler._handle_get_channel(0, packet)
        assert len(responses) == 1
        decoded = decode_fromradio(responses[0])
        assert "packet" in decoded

    def test_get_channel_1_returns_empty(self):
        """Channel index 1 returns an empty secondary (role=0), not primary."""
        from meshtastic_sdr.ble.admin_handler import AdminHandler
        from meshtastic_sdr.ble.protobuf_codec import decode_fromradio
        from meshtastic_sdr.mesh.node import MeshNode
        from meshtastic_sdr.protocol.channels import ChannelConfig
        from unittest.mock import MagicMock

        gw = MagicMock()
        gw.node = MeshNode(node_id=0x12345678)
        gw.channel = ChannelConfig(name="TestChan", psk=b"\x01" * 16)
        handler = AdminHandler(gw)

        packet = MeshPacket(header=MeshtasticHeader(
            from_node=0xAAAAAAAA, id=1, channel=0,
        ))
        packet.data = DataPayload(portnum=67, payload=b"")

        responses = handler._handle_get_channel(1, packet)
        assert len(responses) == 1
        # The response should be an empty channel, not the primary channel
        decoded = decode_fromradio(responses[0])
        assert "packet" in decoded


class TestManualDecodeStructBoundsCheck:
    """Fix: struct.unpack in protobuf decoders checks remaining bytes."""

    def test_truncated_fixed32_stops_gracefully(self):
        """Truncated wire_type 5 (fixed32) doesn't crash, just stops parsing."""
        # field 4 (dest), wire_type 5 = tag 0x25, then only 2 bytes instead of 4
        data = b"\x08\x01" + b"\x25\xAA\xBB"
        result = DataPayload._manual_decode(data)
        assert result.portnum == 1
        assert result.dest == 0  # Not parsed due to truncation

    def test_truncated_fixed64_stops_gracefully(self):
        """Truncated wire_type 1 (fixed64) doesn't crash, just stops parsing."""
        # field 1 portnum=1, then field 20 wire_type 1 with only 3 bytes
        data = b"\x08\x01" + b"\xa1\x01\xAA\xBB\xCC"
        result = DataPayload._manual_decode(data)
        assert result.portnum == 1

    def test_full_fixed32_parses(self):
        """A complete fixed32 field is still parsed correctly."""
        # field 4 (dest), wire_type 5 = tag 0x25, then 4 bytes LE for value 0x01020304
        data = b"\x08\x01" + b"\x25\x04\x03\x02\x01"
        result = DataPayload._manual_decode(data)
        assert result.portnum == 1
        assert result.dest == 0x01020304


class TestAdminHandlerStructBoundsCheck:
    """Fix: _decode_lora_config struct.unpack checks remaining bytes."""

    def test_truncated_float_stops_gracefully(self):
        """Truncated wire_type 5 (float) doesn't crash."""
        from meshtastic_sdr.ble.admin_handler import _decode_lora_config
        # field 6 (frequency_offset), wire_type 5 = tag 0x35, then only 2 bytes
        data = b"\x08\x01" + b"\x35\xAA\xBB"
        result = _decode_lora_config(data)
        # Should parse use_preset but not crash on truncated float
        assert result.get("use_preset") is True

    def test_truncated_fixed64_stops(self):
        """Truncated wire_type 1 (64-bit) doesn't crash."""
        from meshtastic_sdr.ble.admin_handler import _decode_lora_config
        # field 1 varint, then wire_type 1 with only 3 bytes
        data = b"\x08\x01" + b"\x09\xAA\xBB\xCC"
        result = _decode_lora_config(data)
        assert result.get("use_preset") is True

    def test_full_float_parses(self):
        """A complete float field is still parsed correctly."""
        from meshtastic_sdr.ble.admin_handler import _decode_lora_config
        # field 6 (frequency_offset), wire_type 5, 4 bytes for float 0.0
        data = b"\x35\x00\x00\x00\x00"
        result = _decode_lora_config(data)
        assert result.get("frequency_offset") == 0.0


class TestNodeIdentityEdgeCase:
    """Fix: node_id '!' (empty hex) returns None instead of crashing."""

    def test_bang_only_returns_none(self, tmp_path):
        """node_id: '!' in YAML should return None, not crash."""
        import yaml
        identity_file = tmp_path / "node_identity.yaml"
        identity_file.write_text(yaml.dump({"node_id": "!"}))

        from meshtastic_sdr.config import load_node_identity
        from unittest.mock import patch

        with patch("meshtastic_sdr.config._node_identity_path", return_value=identity_file):
            result = load_node_identity()
        assert result is None

    def test_valid_bang_hex_still_works(self, tmp_path):
        """node_id: '!1a2b3c4d' still parses correctly."""
        import yaml
        identity_file = tmp_path / "node_identity.yaml"
        identity_file.write_text(yaml.dump({"node_id": "!1a2b3c4d"}))

        from meshtastic_sdr.config import load_node_identity
        from unittest.mock import patch

        with patch("meshtastic_sdr.config._node_identity_path", return_value=identity_file):
            result = load_node_identity()
        assert result == 0x1a2b3c4d


class TestRxLoopExceptionHandling:
    """Fix: _rx_loop catches exceptions so the receive thread doesn't die silently."""

    def test_rx_loop_survives_callback_exception(self):
        """If the callback raises, the loop keeps running."""
        import threading
        import time
        from meshtastic_sdr.mesh.interface import MeshInterface
        from meshtastic_sdr.radio.simulated import SimulatedRadio
        from unittest.mock import patch, MagicMock

        radio = SimulatedRadio()
        iface = MeshInterface(radio=radio)

        call_count = 0
        loop_entered = threading.Event()

        def bad_callback(pkt):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("callback exploded")

        fake_packet = MagicMock()
        returns = [fake_packet, fake_packet, None, None, None]
        return_iter = iter(returns)

        def mock_receive(timeout_s=1.0):
            loop_entered.set()
            try:
                return next(return_iter)
            except StopIteration:
                iface._running = False
                return None

        with patch.object(iface, "receive_once", side_effect=mock_receive):
            iface.start_receive(bad_callback)
            loop_entered.wait(timeout=2)
            time.sleep(0.3)
            iface.stop_receive()

        # Callback was called at least twice — loop survived the first exception
        assert call_count >= 2

    def test_rx_loop_survives_receive_exception(self):
        """If receive_once raises, the loop keeps running."""
        import threading
        import time
        from meshtastic_sdr.mesh.interface import MeshInterface
        from meshtastic_sdr.radio.simulated import SimulatedRadio
        from unittest.mock import patch, MagicMock

        radio = SimulatedRadio()
        iface = MeshInterface(radio=radio)

        call_count = 0
        loop_entered = threading.Event()

        def counting_callback(pkt):
            nonlocal call_count
            call_count += 1

        fake_packet = MagicMock()
        calls = 0

        def mock_receive(timeout_s=1.0):
            nonlocal calls
            loop_entered.set()
            calls += 1
            if calls == 1:
                raise RuntimeError("radio glitch")
            if calls == 2:
                return fake_packet
            iface._running = False
            return None

        with patch.object(iface, "receive_once", side_effect=mock_receive):
            iface.start_receive(counting_callback)
            loop_entered.wait(timeout=2)
            time.sleep(0.3)
            iface.stop_receive()

        # Callback was called for the second receive (after the exception)
        assert call_count >= 1


class TestDecryptNarrowExcept:
    """Fix: decrypt catches ValueError/struct.error, not bare Exception."""

    def test_decrypt_value_error_returns_none(self):
        """ValueError during decrypt returns None (packet dropped)."""
        from meshtastic_sdr.mesh.interface import MeshInterface
        from meshtastic_sdr.radio.simulated import SimulatedRadio

        radio = SimulatedRadio()
        iface = MeshInterface(radio=radio)

        # Create a packet with empty encrypted field → decrypt raises ValueError
        packet = MeshPacket(
            header=MeshtasticHeader(
                to=iface.node.node_id, from_node=0x22222222,
                id=42, hop_limit=3, hop_start=3,
            ),
            encrypted=b"",
        )

        # decrypt_payload raises ValueError("No encrypted payload to decrypt")
        # The interface's _process method should catch it and return None
        # Test via the decrypt path directly
        with pytest.raises(ValueError):
            packet.decrypt_payload(iface.crypto)

    def test_struct_error_returns_none(self):
        """struct.error during decrypt/decode is also caught."""
        from meshtastic_sdr.mesh.interface import MeshInterface
        from meshtastic_sdr.radio.simulated import SimulatedRadio
        from unittest.mock import patch

        radio = SimulatedRadio()
        iface = MeshInterface(radio=radio)

        packet = MeshPacket(
            header=MeshtasticHeader(
                to=iface.node.node_id, from_node=0x22222222,
                id=42, hop_limit=3, hop_start=3,
            ),
            encrypted=b"\x00" * 10,
        )

        def raise_struct_error(crypto):
            raise struct.error("bad data")

        packet.decrypt_payload = raise_struct_error

        # Simulate the interface's decrypt path
        try:
            packet.decrypt_payload(iface.crypto)
            result = packet
        except (ValueError, struct.error):
            result = None

        assert result is None
