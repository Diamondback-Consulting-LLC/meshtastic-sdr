"""Simulated radio backend for testing without hardware.

Provides an in-memory loopback: TX samples go into a buffer,
RX reads from it. Optionally adds AWGN noise.
"""

import threading
import numpy as np
from .base import RadioBackend


class SimulatedRadio(RadioBackend):
    """In-memory loopback radio for development and testing."""

    def __init__(self, snr_db: float | None = None):
        """Initialize simulated radio.

        Args:
            snr_db: If set, adds AWGN noise at this SNR level.
                    None = no noise (clean loopback).
        """
        self.snr_db = snr_db
        self._buffer = np.array([], dtype=np.complex64)
        self._lock = threading.Lock()
        self._frequency = 906.875e6
        self._sample_rate = 250000
        self._bandwidth = 250000
        self._tx_gain = 30
        self._rx_gain = 30

    def configure(self, frequency: float, sample_rate: int, bandwidth: int,
                  tx_gain: int = 30, rx_gain: int = 30) -> None:
        self._frequency = frequency
        self._sample_rate = sample_rate
        self._bandwidth = bandwidth
        self._tx_gain = tx_gain
        self._rx_gain = rx_gain

    def transmit(self, iq_samples: np.ndarray) -> None:
        samples = iq_samples.astype(np.complex64)

        if self.snr_db is not None:
            # Add AWGN noise
            signal_power = np.mean(np.abs(samples) ** 2)
            noise_power = signal_power / (10 ** (self.snr_db / 10))
            noise = np.sqrt(noise_power / 2) * (
                np.random.randn(len(samples)) + 1j * np.random.randn(len(samples))
            )
            samples = (samples + noise).astype(np.complex64)

        with self._lock:
            self._buffer = np.concatenate([self._buffer, samples])

    def receive(self, num_samples: int) -> np.ndarray:
        with self._lock:
            if len(self._buffer) >= num_samples:
                result = self._buffer[:num_samples]
                self._buffer = self._buffer[num_samples:]
                return result.copy()
            else:
                result = self._buffer.copy()
                self._buffer = np.array([], dtype=np.complex64)
                # Pad with zeros (silence) if not enough samples
                if len(result) < num_samples:
                    padding = np.zeros(num_samples - len(result), dtype=np.complex64)
                    result = np.concatenate([result, padding])
                return result

    def receive_available(self) -> np.ndarray:
        """Receive all available samples without blocking."""
        with self._lock:
            result = self._buffer.copy()
            self._buffer = np.array([], dtype=np.complex64)
            return result

    @property
    def samples_available(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def device_name(self) -> str:
        return "Simulated"

    def close(self) -> None:
        with self._lock:
            self._buffer = np.array([], dtype=np.complex64)
