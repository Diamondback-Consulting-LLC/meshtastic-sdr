"""LoRa CSS demodulator.

Detects preamble, synchronizes, and extracts symbols from IQ samples.
Uses dechirp + FFT method for symbol detection.
Reference: EPFL LoRa reverse engineering, gr-lora_sdr
"""

import numpy as np
from .params import ModemPreset
from .modulator import MESHTASTIC_SYNC_WORD


class LoRaDemodulator:
    """Extracts LoRa symbols from baseband IQ samples."""

    def __init__(self, preset: ModemPreset, sample_rate: int | None = None):
        self.sf = preset.spreading_factor
        self.bw = preset.bandwidth
        self.preamble_len = preset.preamble_length
        self.N = 2 ** self.sf
        self.sample_rate = sample_rate or self.bw
        self.oversample = self.sample_rate // self.bw

        self._samples_per_symbol = self.N * self.oversample

        # Pre-compute reference chirps
        self._ref_downchirp = self._generate_ref_chirp(down=True)
        self._ref_upchirp = self._generate_ref_chirp(down=False)

    def _generate_ref_chirp(self, down: bool = True) -> np.ndarray:
        N = self.N
        n = np.arange(N * self.oversample)
        sign = -1 if down else 1
        phase = sign * 2 * np.pi * (n ** 2 / (2 * N * self.oversample ** 2)
                                      - n / (2 * self.oversample))
        return np.exp(1j * phase).astype(np.complex64)

    def _dechirp_and_detect(self, samples: np.ndarray) -> int:
        """Dechirp a symbol-length block and detect the symbol via FFT.

        Multiply by conjugate downchirp, take FFT, find peak -> symbol value.
        """
        sps = self._samples_per_symbol
        if len(samples) < sps:
            samples = np.pad(samples, (0, sps - len(samples)))

        # Dechirp: multiply by conjugate of downchirp (= upchirp conjugate for downchirp ref)
        dechirped = samples[:sps] * self._ref_downchirp

        # If oversampled, decimate before FFT
        if self.oversample > 1:
            dechirped = dechirped.reshape(-1, self.oversample).mean(axis=1)

        # FFT and find peak
        spectrum = np.abs(np.fft.fft(dechirped, n=self.N))
        symbol = int(np.argmax(spectrum))

        return symbol

    def _detect_preamble(self, samples: np.ndarray, threshold: float = 0.7,
                         min_chirps: int = 4) -> int | None:
        """Detect preamble by looking for consecutive matching dechirp peaks.

        Slides through samples looking for consecutive symbols that all decode
        to the same value (indicating unmodulated upchirps).

        Returns the sample offset where the preamble starts, or None.
        """
        sps = self._samples_per_symbol
        if len(samples) < sps * min_chirps:
            return None

        max_offset = len(samples) - sps * min_chirps
        step = sps // 4  # Quarter-symbol stepping for detection

        for offset in range(0, max_offset, step):
            # Check for consecutive symbols with the same detected value
            values = []
            for i in range(min_chirps):
                start = offset + i * sps
                end = start + sps
                if end > len(samples):
                    break
                chunk = samples[start:end]

                # Dechirp and check peak strength
                dechirped = chunk * self._ref_downchirp
                if self.oversample > 1:
                    dechirped = dechirped.reshape(-1, self.oversample).mean(axis=1)

                spectrum = np.abs(np.fft.fft(dechirped, n=self.N))
                peak_idx = int(np.argmax(spectrum))
                peak_val = spectrum[peak_idx]
                mean_val = np.mean(spectrum)

                values.append(peak_idx)

            if len(values) >= min_chirps:
                # All preamble chirps should decode to same value (ideally 0)
                if all(v == values[0] for v in values):
                    return offset

        return None

    def _estimate_cfo(self, preamble_samples: np.ndarray) -> float:
        """Estimate carrier frequency offset from preamble chirps.

        The preamble upchirps should all dechirp to bin 0. Any offset
        indicates a CFO that shifts the peak.
        """
        sps = self._samples_per_symbol
        offsets = []

        num_chirps = min(8, len(preamble_samples) // sps)
        for i in range(num_chirps):
            start = i * sps
            chunk = preamble_samples[start:start + sps]
            sym = self._dechirp_and_detect(chunk)
            # The detected symbol represents fractional frequency offset
            if sym > self.N // 2:
                sym -= self.N
            offsets.append(sym)

        if not offsets:
            return 0.0

        # Average CFO estimate in bins
        avg_offset = np.mean(offsets)
        # Convert bin offset to Hz
        cfo_hz = avg_offset * self.bw / self.N
        return float(cfo_hz)

    def demodulate(self, samples: np.ndarray,
                   sync_word: int = MESHTASTIC_SYNC_WORD) -> list[int] | None:
        """Demodulate IQ samples to extract LoRa symbols.

        Detects preamble, verifies sync word, finds SFD, then extracts
        data symbols.

        Args:
            samples: Complex baseband IQ samples
            sync_word: Expected sync word (0x2B for Meshtastic)

        Returns:
            List of detected symbols, or None if no valid frame found
        """
        sps = self._samples_per_symbol

        # Detect preamble
        preamble_offset = self._detect_preamble(samples)
        if preamble_offset is None:
            return None

        # Skip preamble chirps
        pos = preamble_offset + self.preamble_len * sps

        if pos + 2 * sps > len(samples):
            return None

        # Verify sync word
        expected_high = ((sync_word >> 4) & 0x0F) * self.N // 16
        expected_low = (sync_word & 0x0F) * self.N // 16

        detected_high = self._dechirp_and_detect(samples[pos:pos + sps])
        detected_low = self._dechirp_and_detect(samples[pos + sps:pos + 2 * sps])

        # Allow some tolerance for sync word detection
        tolerance = max(1, self.N // 32)
        high_ok = abs(detected_high - expected_high) <= tolerance or \
                  abs(detected_high - expected_high + self.N) <= tolerance or \
                  abs(detected_high - expected_high - self.N) <= tolerance
        low_ok = abs(detected_low - expected_low) <= tolerance or \
                 abs(detected_low - expected_low + self.N) <= tolerance or \
                 abs(detected_low - expected_low - self.N) <= tolerance

        if not (high_ok and low_ok):
            return None

        pos += 2 * sps

        # Skip SFD (2.25 downchirps)
        sfd_len = int(2.25 * sps)
        pos += sfd_len

        if pos >= len(samples):
            return []

        # Extract data symbols
        symbols = []
        while pos + sps <= len(samples):
            sym = self._dechirp_and_detect(samples[pos:pos + sps])
            symbols.append(sym)
            pos += sps

        return symbols

    def demodulate_aligned(self, samples: np.ndarray) -> list[int]:
        """Demodulate pre-aligned data samples (no preamble/sync detection).

        Use when the data portion has already been isolated.
        """
        sps = self._samples_per_symbol
        symbols = []
        pos = 0
        while pos + sps <= len(samples):
            sym = self._dechirp_and_detect(samples[pos:pos + sps])
            symbols.append(sym)
            pos += sps
        return symbols
