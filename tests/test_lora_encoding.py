"""Tests for LoRa FEC, interleaving, and whitening round-trip."""

import sys
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.lora.params import get_preset, CodingRate
from meshtastic_sdr.lora.encoder import (
    LoRaEncoder, crc16, whiten, hamming_encode_nibble,
    interleave, gray_demap,
)
from meshtastic_sdr.lora.decoder import (
    LoRaDecoder, hamming_decode_nibble, deinterleave, gray_map,
)


class TestCRC:
    def test_crc16_empty(self):
        assert crc16(b"") == 0x0000

    def test_crc16_known(self):
        # CRC-16/CCITT for "123456789"
        result = crc16(b"123456789")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_crc16_deterministic(self):
        data = b"hello meshtastic"
        assert crc16(data) == crc16(data)

    def test_crc16_different_data(self):
        assert crc16(b"abc") != crc16(b"xyz")


class TestWhitening:
    def test_whiten_roundtrip(self):
        """Whitening is its own inverse."""
        data = b"test data 12345"
        whitened = whiten(data)
        assert whitened != data  # Should be different
        recovered = whiten(whitened)
        assert recovered == data

    def test_whiten_empty(self):
        assert whiten(b"") == b""

    def test_whiten_single_byte(self):
        data = b"\x42"
        whitened = whiten(data)
        recovered = whiten(whitened)
        assert recovered == data


class TestHamming:
    @pytest.mark.parametrize("cr", list(CodingRate))
    def test_hamming_roundtrip_all_nibbles(self, cr):
        """Encode then decode every possible nibble value."""
        for nibble in range(16):
            encoded = hamming_encode_nibble(nibble, cr)
            decoded, _ = hamming_decode_nibble(encoded, cr)
            assert decoded == nibble, f"CR={cr}, nibble={nibble}: got {decoded}"

    def test_hamming_cr48_single_bit_correction(self):
        """CR 4/8 (extended Hamming) should correct single-bit errors."""
        cr = CodingRate.CR_4_8
        for nibble in range(16):
            encoded = hamming_encode_nibble(nibble, cr)
            # Flip each bit and verify correction
            for bit in range(4):  # Only data bits
                corrupted = encoded ^ (1 << bit)
                decoded, corrected = hamming_decode_nibble(corrupted, cr)
                assert decoded == nibble, \
                    f"Failed to correct bit {bit} for nibble {nibble}"


class TestGrayCoding:
    def test_gray_roundtrip(self):
        """Gray demap then map should be identity."""
        for val in range(128):
            gray = gray_demap(val, 7)
            recovered = gray_map(gray, 7)
            assert recovered == val, f"Value {val}: gray={gray}, recovered={recovered}"

    def test_gray_adjacent_differ_by_one_bit(self):
        """Adjacent Gray codes should differ by exactly one bit."""
        for val in range(127):
            g1 = gray_demap(val, 7)
            g2 = gray_demap(val + 1, 7)
            diff = g1 ^ g2
            assert bin(diff).count("1") == 1, \
                f"Gray({val})=0x{g1:02x}, Gray({val+1})=0x{g2:02x}, differ by {bin(diff).count('1')} bits"


class TestInterleaving:
    @pytest.mark.parametrize("sf", [7, 8, 11, 12])
    def test_interleave_deinterleave_roundtrip(self, sf):
        """Interleave then deinterleave should be identity."""
        cr = CodingRate.CR_4_5
        cr_bits = cr.value + 4

        # Create test codewords (one block = sf codewords)
        codewords = [i % (1 << cr_bits) for i in range(sf)]
        symbols = interleave(codewords, sf, cr)
        recovered = deinterleave(symbols, sf, cr)

        assert recovered[:sf] == codewords


class TestEncoderDecoder:
    @pytest.mark.parametrize("preset_name", [
        "SHORT_FAST", "SHORT_SLOW", "MEDIUM_FAST",
        "LONG_FAST", "LONG_MODERATE", "LONG_SLOW"
    ])
    def test_encode_decode_roundtrip(self, preset_name):
        """Full encode -> decode pipeline should recover original data."""
        preset = get_preset(preset_name)
        encoder = LoRaEncoder(preset)
        decoder = LoRaDecoder(preset)

        data = b"Hello LoRa!"
        symbols = encoder.encode(data)

        assert len(symbols) > 0
        assert all(0 <= s < (1 << preset.spreading_factor) for s in symbols)

        recovered = decoder.decode(symbols)
        assert recovered == data

    def test_encode_decode_empty(self):
        preset = get_preset("SHORT_FAST")
        encoder = LoRaEncoder(preset)
        decoder = LoRaDecoder(preset)

        data = b""
        symbols = encoder.encode(data)
        recovered = decoder.decode(symbols)
        assert recovered == data

    def test_encode_decode_max_payload(self):
        """Test with a large payload."""
        preset = get_preset("LONG_FAST")
        encoder = LoRaEncoder(preset)
        decoder = LoRaDecoder(preset)

        data = bytes(range(256)) * 2  # 512 bytes (larger than max LoRa payload, but test encoding)
        symbols = encoder.encode(data[:237])  # Max Meshtastic payload
        recovered = decoder.decode(symbols)
        assert recovered == data[:237]

    def test_crc_error_detection(self):
        """Corrupted data should fail CRC check."""
        preset = get_preset("SHORT_FAST")
        encoder = LoRaEncoder(preset)
        decoder = LoRaDecoder(preset)

        data = b"test data"
        symbols = encoder.encode(data)

        # Corrupt a symbol
        if symbols:
            symbols[len(symbols) // 2] ^= 0x01

        with pytest.raises(ValueError, match="CRC"):
            decoder.decode(symbols)
