"""LoRa CSS (Chirp Spread Spectrum) modulator.

Generates IQ samples from LoRa symbols using chirp modulation.
Reference: EPFL LoRa reverse engineering, gr-lora_sdr
"""

import numpy as np
from .params import ModemPreset


# Meshtastic sync word (different from LoRaWAN 0x34 or private 0x12)
MESHTASTIC_SYNC_WORD = 0x2B


class LoRaModulator:
    """Converts LoRa symbols into baseband IQ samples."""

    def __init__(self, preset: ModemPreset, sample_rate: int | None = None):
        self.sf = preset.spreading_factor
        self.bw = preset.bandwidth
        self.preamble_len = preset.preamble_length
        self.N = 2 ** self.sf  # Samples per symbol at Nyquist rate
        self.sample_rate = sample_rate or self.bw
        self.oversample = self.sample_rate // self.bw

        # Pre-compute base chirps
        self._base_upchirp = self._generate_chirp(up=True)
        self._base_downchirp = self._generate_chirp(up=False)

    def _generate_chirp(self, up: bool = True) -> np.ndarray:
        """Generate a base chirp (upchirp or downchirp).

        The chirp sweeps from -BW/2 to +BW/2 (upchirp) over one symbol period.
        Phase: phi(t) = 2*pi * (BW/(2*T) * t^2 + (-BW/2) * t)
        Discrete: phi[n] = 2*pi * (n^2/(2*N) - n/2) for upchirp
        """
        N = self.N
        n = np.arange(N * self.oversample)

        if up:
            phase = 2 * np.pi * (n ** 2 / (2 * N * self.oversample ** 2)
                                  - n / (2 * self.oversample))
        else:
            phase = -2 * np.pi * (n ** 2 / (2 * N * self.oversample ** 2)
                                   - n / (2 * self.oversample))

        return np.exp(1j * phase).astype(np.complex64)

    def _modulate_symbol(self, symbol: int) -> np.ndarray:
        """Modulate a single symbol by cyclically shifting the base upchirp."""
        shift = symbol * self.oversample
        return np.roll(self._base_upchirp, -shift)

    def _encode_sync_word(self, sync_word: int) -> np.ndarray:
        """Encode the sync word as two chirps with specific offsets.

        The sync word byte is split into two nibbles, each mapped to a chirp
        with a cyclic shift proportional to the nibble value.
        """
        # Split sync word into high and low nibbles
        high_nibble = (sync_word >> 4) & 0x0F
        low_nibble = sync_word & 0x0F

        # Scale nibbles to symbol space: value * N/16 (maps 4-bit value to SF-bit space)
        sym1 = (high_nibble * self.N) // 16
        sym2 = (low_nibble * self.N) // 16

        chirp1 = self._modulate_symbol(sym1)
        chirp2 = self._modulate_symbol(sym2)
        return np.concatenate([chirp1, chirp2])

    def modulate(self, symbols: list[int],
                 sync_word: int = MESHTASTIC_SYNC_WORD) -> np.ndarray:
        """Modulate a complete LoRa frame into IQ samples.

        Frame structure:
        1. Preamble: N upchirps (default 16 for Meshtastic)
        2. Sync word: 2 chirps encoding the sync word
        3. SFD: 2.25 downchirps
        4. Data: modulated payload symbols

        Args:
            symbols: List of data symbols (each in [0, 2^SF))
            sync_word: Sync word byte (0x2B for Meshtastic)

        Returns:
            Complex baseband IQ samples (np.complex64)
        """
        parts = []
        samples_per_symbol = self.N * self.oversample

        # 1. Preamble: upchirps
        for _ in range(self.preamble_len):
            parts.append(self._base_upchirp.copy())

        # 2. Sync word
        parts.append(self._encode_sync_word(sync_word))

        # 3. SFD: 2.25 downchirps
        parts.append(self._base_downchirp.copy())
        parts.append(self._base_downchirp.copy())
        quarter = samples_per_symbol // 4
        parts.append(self._base_downchirp[:quarter].copy())

        # 4. Data symbols
        for sym in symbols:
            parts.append(self._modulate_symbol(sym & ((1 << self.sf) - 1)))

        return np.concatenate(parts)

    def upchirp(self) -> np.ndarray:
        """Return a copy of the base upchirp for external use."""
        return self._base_upchirp.copy()

    def downchirp(self) -> np.ndarray:
        """Return a copy of the base downchirp for external use."""
        return self._base_downchirp.copy()
