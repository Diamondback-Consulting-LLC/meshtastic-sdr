"""LoRa packet framing: assembles and parses complete LoRa frames.

Combines the encoder, modulator, demodulator, and decoder into a
complete packet TX/RX chain.
"""

import numpy as np
from .params import ModemPreset
from .encoder import LoRaEncoder
from .decoder import LoRaDecoder
from .modulator import LoRaModulator, MESHTASTIC_SYNC_WORD
from .demodulator import LoRaDemodulator


class LoRaPacket:
    """Assembles and parses complete LoRa packets."""

    def __init__(self, preset: ModemPreset, sample_rate: int | None = None):
        self.preset = preset
        self.sample_rate = sample_rate
        self.encoder = LoRaEncoder(preset)
        self.decoder = LoRaDecoder(preset)
        self.modulator = LoRaModulator(preset, sample_rate)
        self.demodulator = LoRaDemodulator(preset, sample_rate)

    def build(self, payload: bytes, sync_word: int = MESHTASTIC_SYNC_WORD) -> np.ndarray:
        """Build a complete LoRa frame from payload bytes.

        payload -> encode (FEC, interleave, etc.) -> modulate (CSS chirps) -> IQ samples

        Args:
            payload: Raw payload bytes to transmit
            sync_word: Sync word (0x2B for Meshtastic)

        Returns:
            Complex baseband IQ samples ready for transmission
        """
        symbols = self.encoder.encode(payload)
        iq_samples = self.modulator.modulate(symbols, sync_word=sync_word)
        return iq_samples

    def parse(self, samples: np.ndarray,
              sync_word: int = MESHTASTIC_SYNC_WORD) -> bytes | None:
        """Parse IQ samples into payload bytes.

        IQ samples -> demodulate (dechirp + FFT) -> decode (deinterleave, FEC, etc.) -> payload

        Args:
            samples: Complex baseband IQ samples
            sync_word: Expected sync word

        Returns:
            Decoded payload bytes, or None if no valid frame found

        Raises:
            ValueError: If CRC check fails
        """
        symbols = self.demodulator.demodulate(samples, sync_word=sync_word)
        if symbols is None or len(symbols) == 0:
            return None

        return self.decoder.decode(symbols)

    def estimate_airtime_ms(self, payload_length: int) -> float:
        return self.preset.airtime_ms(payload_length)
