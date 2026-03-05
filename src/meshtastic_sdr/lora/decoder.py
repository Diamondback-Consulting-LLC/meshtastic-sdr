"""LoRa decoder: symbols -> data bytes.

RX pipeline: symbols -> Gray mapping -> deinterleaving -> Hamming decode ->
dewhitening -> CRC verify -> data.

Reference: gr-lora_sdr (EPFL), LoRaPHY (MATLAB)
"""

from .params import ModemPreset, CodingRate
from .encoder import crc16, whiten, _WHITENING_SEQ


def gray_map(symbol: int, sf: int) -> int:
    """Gray mapping (decoding): Gray code -> binary."""
    mask = symbol
    result = symbol
    while mask > 0:
        mask >>= 1
        result ^= mask
    return result


def hamming_decode_nibble(codeword: int, cr: CodingRate) -> tuple[int, bool]:
    """Decode a Hamming-encoded codeword to a 4-bit nibble.

    Returns (nibble, corrected) where corrected indicates if an error was fixed.
    """
    d = [(codeword >> i) & 1 for i in range(4)]

    if cr == CodingRate.CR_4_5:
        # Just parity check
        p0 = (codeword >> 4) & 1
        parity = d[0] ^ d[1] ^ d[2] ^ d[3] ^ p0
        return codeword & 0x0F, parity != 0

    p = [(codeword >> (4 + i)) & 1 for i in range(cr.value)]

    # Syndrome calculation
    s0 = d[0] ^ d[1] ^ d[3] ^ p[0]
    s1 = d[0] ^ d[2] ^ d[3] ^ p[1]

    if cr == CodingRate.CR_4_6:
        # Hamming(6,4): only 2 parity bits → 3 non-zero syndromes for 6 bit
        # positions. Syndromes are ambiguous (d0/d3, d1/p0, d2/p1) so
        # correction is unreliable and can cause double-corruption.
        # Detection only — return data bits as-is, flag the error.
        syndrome = s0 | (s1 << 1)
        return codeword & 0x0F, syndrome != 0

    s2 = d[1] ^ d[2] ^ d[3] ^ p[2]
    syndrome = s0 | (s1 << 1) | (s2 << 2)

    nibble = codeword & 0x0F

    if syndrome != 0:
        # Error position lookup for Hamming(7,4)
        # Syndrome -> bit position mapping
        error_pos_map = {
            0b001: 4,  # p0
            0b010: 5,  # p1
            0b011: 0,  # d0
            0b100: 6,  # p2
            0b101: 1,  # d1
            0b110: 2,  # d2
            0b111: 3,  # d3
        }
        if syndrome in error_pos_map:
            pos = error_pos_map[syndrome]
            if pos < 4:
                nibble ^= (1 << pos)

    if cr == CodingRate.CR_4_8:
        # Extended Hamming: check overall parity for SECDED
        overall = 0
        for i in range(8):
            overall ^= (codeword >> i) & 1
        # If syndrome != 0 and overall == 0: double error (uncorrectable)

    return nibble, syndrome != 0


def deinterleave(symbols: list[int], sf: int, cr: CodingRate) -> list[int]:
    """Reverse diagonal interleaver: symbols -> codewords.

    Input: list of symbols (each sf bits wide)
    Output: list of codewords (each cr_denom bits wide)
    """
    cr_bits = cr.value + 4
    codewords = []

    # Process in blocks of cr_bits symbols producing sf codewords
    for block_start in range(0, len(symbols), cr_bits):
        block = symbols[block_start:block_start + cr_bits]
        while len(block) < cr_bits:
            block.append(0)

        for i in range(sf):
            codeword = 0
            for j in range(cr_bits):
                bit = (block[j] >> i) & 1
                codeword |= bit << ((j + i) % cr_bits)
            codewords.append(codeword)

    return codewords


class LoRaDecoder:
    """Decodes LoRa symbols back into payload bytes."""

    def __init__(self, preset: ModemPreset):
        self.sf = preset.spreading_factor
        self.cr = preset.coding_rate
        self.bw = preset.bandwidth

    def decode(self, symbols: list[int], has_crc: bool = True,
               explicit_header: bool = True) -> bytes:
        """Decode a list of LoRa symbols back into data bytes.

        Args:
            symbols: List of integer symbols in [0, 2^SF)
            has_crc: Whether CRC-16 is appended
            explicit_header: Whether explicit header mode is used

        Returns:
            Decoded payload bytes

        Raises:
            ValueError: If CRC check fails
        """
        mask = (1 << self.sf) - 1

        # Gray mapping (reverse of demapping)
        mapped = [gray_map(s & mask, self.sf) for s in symbols]

        total_bytes = None

        # Split into header and data symbol groups
        if explicit_header:
            # Header uses 8 symbols (CR 4/8, cr_bits=8)
            header_sym_count = 8
            header_symbols = mapped[:header_sym_count]
            data_symbols = mapped[header_sym_count:]

            # Decode header to get payload length
            header_codewords = deinterleave(header_symbols, self.sf, CodingRate.CR_4_8)
            header_nibbles = []
            for cw in header_codewords[:5]:
                nibble, _ = hamming_decode_nibble(cw, CodingRate.CR_4_8)
                header_nibbles.append(nibble)

            total_bytes = header_nibbles[0] | (header_nibbles[1] << 4)
        else:
            data_symbols = mapped

        # Deinterleave and decode data nibbles
        nibbles = []
        if data_symbols:
            data_codewords = deinterleave(data_symbols, self.sf, self.cr)
            for cw in data_codewords:
                nibble, _ = hamming_decode_nibble(cw, self.cr)
                nibbles.append(nibble)

        # Trim to expected number of nibbles (removes interleaver padding)
        if total_bytes is not None:
            expected_nibbles = total_bytes * 2
            nibbles = nibbles[:expected_nibbles]

        # Reassemble nibbles into bytes (LSN first)
        data = bytearray()
        for i in range(0, len(nibbles) - 1, 2):
            byte = (nibbles[i] & 0x0F) | ((nibbles[i + 1] & 0x0F) << 4)
            data.append(byte)

        # Dewhiten
        dewhitened = bytearray(whiten(bytes(data)))

        if has_crc and len(dewhitened) >= 2:
            payload = bytes(dewhitened[:-2])
            received_crc = dewhitened[-2] | (dewhitened[-1] << 8)
            computed_crc = crc16(payload)
            if received_crc != computed_crc:
                raise ValueError(
                    f"CRC mismatch: received 0x{received_crc:04X}, "
                    f"computed 0x{computed_crc:04X}"
                )
            return payload

        return bytes(dewhitened)
