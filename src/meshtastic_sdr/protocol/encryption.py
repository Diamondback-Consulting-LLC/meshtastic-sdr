"""Meshtastic AES-CTR encryption/decryption.

Meshtastic uses AES-128-CTR or AES-256-CTR depending on key length.
The nonce is constructed from the packet ID and sender node ID.

Nonce: packet_id (4B LE) || from_node (4B LE) || 0x00000000 (4B) || 0x00000000 (4B)
(16 bytes total for AES-CTR counter block)

Default PSK: 0x01 = well-known key:
  {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
   0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}

Reference: meshtastic/firmware/src/mesh/CryptoEngine.cpp
"""

import struct
from Crypto.Cipher import AES


# The well-known default Meshtastic key (PSK=0x01)
DEFAULT_KEY = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])

# Extended default keys for PSK values 2-10 (default key with last byte = psk_byte)
def get_default_key(psk_byte: int) -> bytes:
    """Get a default key for PSK shorthand values 0-10.

    0 = no encryption
    1 = default key
    2-10 = default key with last byte set to psk_byte
    """
    if psk_byte == 0:
        return b""
    if psk_byte == 1:
        return DEFAULT_KEY
    if 2 <= psk_byte <= 10:
        key = bytearray(DEFAULT_KEY)
        key[-1] = psk_byte
        return bytes(key)
    raise ValueError(f"PSK shorthand must be 0-10, got {psk_byte}")


def _build_nonce(packet_id: int, from_node: int) -> bytes:
    """Build the 16-byte AES-CTR nonce/counter block.

    Format: packet_id (4B LE) | from_node (4B LE) | 0x00000000 | 0x00000000
    """
    return struct.pack("<II", packet_id, from_node) + b"\x00" * 8


class MeshtasticCrypto:
    """Handles Meshtastic packet encryption and decryption."""

    def __init__(self, key: bytes | None = None):
        """Initialize with an encryption key.

        Args:
            key: AES key (16 bytes for AES-128, 32 bytes for AES-256).
                 If None or 1 byte, uses default key mapping.
        """
        if key is None or key == b"\x01":
            self.key = DEFAULT_KEY
        elif len(key) == 1:
            self.key = get_default_key(key[0])
        elif len(key) in (16, 32):
            self.key = key
        else:
            raise ValueError(f"Key must be 16 or 32 bytes, got {len(key)}")

    def encrypt(self, plaintext: bytes, packet_id: int, from_node: int) -> bytes:
        """Encrypt payload using AES-CTR.

        Args:
            plaintext: Raw payload bytes to encrypt
            packet_id: Packet ID (used in nonce)
            from_node: Sender node ID (used in nonce)

        Returns:
            Encrypted bytes (same length as plaintext)
        """
        if not self.key:
            return plaintext

        nonce = _build_nonce(packet_id, from_node)
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=b"", initial_value=nonce)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, packet_id: int, from_node: int) -> bytes:
        """Decrypt payload using AES-CTR.

        AES-CTR is symmetric: decrypt == encrypt with same nonce.
        """
        if not self.key:
            return ciphertext

        nonce = _build_nonce(packet_id, from_node)
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=b"", initial_value=nonce)
        return cipher.decrypt(ciphertext)
