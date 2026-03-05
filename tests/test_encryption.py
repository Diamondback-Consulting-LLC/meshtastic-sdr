"""Tests for Meshtastic AES-CTR encryption/decryption."""

import sys
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.protocol.encryption import (
    MeshtasticCrypto, DEFAULT_KEY, get_default_key, _build_nonce,
)


class TestDefaultKeys:
    def test_default_key_is_16_bytes(self):
        assert len(DEFAULT_KEY) == 16

    def test_default_key_starts_with_d4f1(self):
        assert DEFAULT_KEY[0] == 0xD4
        assert DEFAULT_KEY[1] == 0xF1

    def test_get_default_key_0_is_empty(self):
        assert get_default_key(0) == b""

    def test_get_default_key_1_is_default(self):
        assert get_default_key(1) == DEFAULT_KEY

    def test_get_default_key_2_through_10(self):
        for i in range(2, 11):
            key = get_default_key(i)
            assert len(key) == 16
            assert key[-1] == i
            # First 15 bytes should match default
            assert key[:-1] == DEFAULT_KEY[:-1]

    def test_get_default_key_invalid(self):
        with pytest.raises(ValueError):
            get_default_key(11)


class TestNonce:
    def test_nonce_length(self):
        nonce = _build_nonce(0x12345678, 0xDEADBEEF)
        assert len(nonce) == 16

    def test_nonce_structure(self):
        nonce = _build_nonce(0x01020304, 0x05060708)
        # Little-endian: packet_id then from_node, then 8 zero bytes
        assert nonce == b"\x04\x03\x02\x01\x08\x07\x06\x05" + b"\x00" * 8


class TestEncryptDecrypt:
    def test_roundtrip_default_key(self):
        crypto = MeshtasticCrypto()
        plaintext = b"Hello Meshtastic!"
        packet_id = 0x12345678
        from_node = 0xDEADBEEF

        ciphertext = crypto.encrypt(plaintext, packet_id, from_node)
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)

        recovered = crypto.decrypt(ciphertext, packet_id, from_node)
        assert recovered == plaintext

    def test_roundtrip_custom_key_16(self):
        key = bytes(range(16))
        crypto = MeshtasticCrypto(key)

        plaintext = b"custom key test"
        ct = crypto.encrypt(plaintext, 1, 2)
        pt = crypto.decrypt(ct, 1, 2)
        assert pt == plaintext

    def test_roundtrip_custom_key_32(self):
        key = bytes(range(32))
        crypto = MeshtasticCrypto(key)

        plaintext = b"AES-256 test"
        ct = crypto.encrypt(plaintext, 100, 200)
        pt = crypto.decrypt(ct, 100, 200)
        assert pt == plaintext

    def test_different_nonce_different_ciphertext(self):
        crypto = MeshtasticCrypto()
        plaintext = b"same message"

        ct1 = crypto.encrypt(plaintext, 1, 100)
        ct2 = crypto.encrypt(plaintext, 2, 100)
        assert ct1 != ct2

    def test_wrong_key_produces_garbage(self):
        crypto1 = MeshtasticCrypto(bytes(16))
        crypto2 = MeshtasticCrypto(bytes(b"\xFF" * 16))

        plaintext = b"secret message"
        ct = crypto1.encrypt(plaintext, 1, 1)
        wrong_pt = crypto2.decrypt(ct, 1, 1)
        assert wrong_pt != plaintext

    def test_wrong_nonce_produces_garbage(self):
        crypto = MeshtasticCrypto()
        plaintext = b"secret message"

        ct = crypto.encrypt(plaintext, 1, 1)
        wrong_pt = crypto.decrypt(ct, 2, 1)  # Wrong packet_id
        assert wrong_pt != plaintext

    def test_psk_shorthand_byte(self):
        crypto = MeshtasticCrypto(b"\x01")
        assert crypto.key == DEFAULT_KEY

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            MeshtasticCrypto(b"\x00" * 7)

    def test_empty_plaintext(self):
        crypto = MeshtasticCrypto()
        ct = crypto.encrypt(b"", 1, 1)
        assert ct == b""
        pt = crypto.decrypt(b"", 1, 1)
        assert pt == b""
