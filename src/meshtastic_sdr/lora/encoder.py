"""LoRa encoder: data bytes -> symbols.

TX pipeline: data -> CRC-16 append -> whitening (LFSR) -> Hamming FEC ->
diagonal interleaving -> Gray demapping -> symbols.

Reference: gr-lora_sdr (EPFL), LoRaPHY (MATLAB)
"""

from .params import ModemPreset, CodingRate


# LoRa whitening sequence (LFSR: x^8 + x^6 + x^5 + x^4 + 1, seed=0xFF)
# Left-shift (MSB-first) to match SX1276/SX1262 hardware and gr-lora_sdr.
def _generate_whitening_sequence(length: int) -> bytes:
    lfsr = 0xFF
    seq = []
    for _ in range(length):
        seq.append(lfsr)
        feedback = ((lfsr >> 7) ^ (lfsr >> 5) ^ (lfsr >> 4) ^ (lfsr >> 3)) & 1
        lfsr = ((lfsr << 1) | feedback) & 0xFF
    return bytes(seq)


# Pre-generate a long whitening sequence
_WHITENING_SEQ = _generate_whitening_sequence(512)


def crc16(data: bytes) -> int:
    """LoRa CRC-16/CCITT (poly 0x1021, init 0x0000)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return crc


def whiten(data: bytes) -> bytes:
    seq = _WHITENING_SEQ[:len(data)]
    return bytes(a ^ b for a, b in zip(data, seq))


def hamming_encode_nibble(nibble: int, cr: CodingRate) -> int:
    """Encode a 4-bit nibble with Hamming FEC.

    CR 4/5: adds 1 parity bit (even parity)
    CR 4/6: Hamming(6,4) — 2 parity bits
    CR 4/7: Hamming(7,4) — 3 parity bits
    CR 4/8: Hamming(8,4) — 4 parity bits (extended Hamming, SECDED)
    """
    d = [(nibble >> i) & 1 for i in range(4)]  # d0..d3

    if cr == CodingRate.CR_4_5:
        p0 = d[0] ^ d[1] ^ d[2] ^ d[3]
        return nibble | (p0 << 4)

    # Hamming parity bits
    p0 = d[0] ^ d[1] ^ d[3]  # positions 1,2,4
    p1 = d[0] ^ d[2] ^ d[3]  # positions 1,3,4
    p2 = d[1] ^ d[2] ^ d[3]  # positions 2,3,4

    if cr == CodingRate.CR_4_6:
        return nibble | (p0 << 4) | (p1 << 5)

    if cr == CodingRate.CR_4_7:
        return nibble | (p0 << 4) | (p1 << 5) | (p2 << 6)

    # CR 4/8: extended Hamming with overall parity
    p3 = d[0] ^ d[1] ^ d[2] ^ d[3] ^ p0 ^ p1 ^ p2
    return nibble | (p0 << 4) | (p1 << 5) | (p2 << 6) | (p3 << 7)


def interleave(codewords: list[int], sf: int, cr: CodingRate) -> list[int]:
    """Diagonal interleaver: maps codewords to symbols.

    Input: list of codewords (each cr_denom bits wide)
    Output: list of symbols (each sf bits wide)

    The interleaver works on blocks of sf codewords producing cr_denom symbols.
    """
    cr_bits = cr.value + 4  # 5, 6, 7, or 8
    symbols = []

    # Process in blocks of sf codewords
    for block_start in range(0, len(codewords), sf):
        block = codewords[block_start:block_start + sf]
        # Pad block to sf if needed
        while len(block) < sf:
            block.append(0)

        # Diagonal interleave: each output symbol takes one bit from each codeword
        for j in range(cr_bits):
            symbol = 0
            for i in range(sf):
                bit = (block[i] >> ((j + i) % cr_bits)) & 1
                symbol |= bit << i
            symbols.append(symbol)

    return symbols


def gray_demap(symbol: int, sf: int) -> int:
    """Gray demapping (encoding): binary -> Gray code."""
    return symbol ^ (symbol >> 1)


class LoRaEncoder:
    """Encodes payload bytes into LoRa symbols."""

    def __init__(self, preset: ModemPreset):
        self.sf = preset.spreading_factor
        self.cr = preset.coding_rate
        self.bw = preset.bandwidth

    def encode(self, data: bytes, add_crc: bool = True, explicit_header: bool = True) -> list[int]:
        """Encode data bytes into a list of LoRa symbols.

        Returns a list of integer symbols, each in range [0, 2^SF).

        In explicit header mode, the first 5 nibbles (encoded at CR 4/8) carry
        PHY header metadata: payload byte count, coding rate, CRC flag. This
        lets the decoder know the exact payload size and trim interleaver padding.
        """
        payload = bytearray(data)

        if add_crc:
            crc_val = crc16(bytes(payload))
            payload.append(crc_val & 0xFF)
            payload.append((crc_val >> 8) & 0xFF)

        # Whitening
        whitened = whiten(bytes(payload))
        total_bytes = len(whitened)

        # Split whitened bytes into nibbles (LSN first)
        data_nibbles = []
        for byte in whitened:
            data_nibbles.append(byte & 0x0F)
            data_nibbles.append((byte >> 4) & 0x0F)

        all_symbols = []

        if explicit_header:
            # PHY Header (5 nibbles): payload length, CR, CRC flag, checksum
            header_nibbles = [
                total_bytes & 0x0F,
                (total_bytes >> 4) & 0x0F,
                (self.cr.value & 0x03) | ((1 if add_crc else 0) << 2),
                0,  # header checksum nibble 0
                0,  # header checksum nibble 1
            ]
            chk = (header_nibbles[0] + header_nibbles[1] + header_nibbles[2]) & 0xFF
            header_nibbles[3] = chk & 0x0F
            header_nibbles[4] = (chk >> 4) & 0x0F

            header_codewords = [hamming_encode_nibble(n, CodingRate.CR_4_8) for n in header_nibbles]
            header_symbols = interleave(header_codewords, self.sf, CodingRate.CR_4_8)
            all_symbols.extend(header_symbols)

        # Encode ALL data nibbles at configured CR
        if data_nibbles:
            payload_codewords = [hamming_encode_nibble(n, self.cr) for n in data_nibbles]
            payload_symbols = interleave(payload_codewords, self.sf, self.cr)
            all_symbols.extend(payload_symbols)

        # Gray demapping
        mask = (1 << self.sf) - 1
        all_symbols = [gray_demap(s, self.sf) & mask for s in all_symbols]

        return all_symbols
