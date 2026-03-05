"""Abstract radio backend interface.

Defines the common API that all radio backends (BladeRF, SoapySDR, simulated) must implement.
"""

from abc import ABC, abstractmethod
import numpy as np


class RadioBackend(ABC):
    """Abstract base class for radio hardware backends."""

    @abstractmethod
    def configure(self, frequency: float, sample_rate: int, bandwidth: int,
                  tx_gain: int = 30, rx_gain: int = 30) -> None:
        """Configure the radio parameters.

        Args:
            frequency: Center frequency in Hz
            sample_rate: Sample rate in samples/sec
            bandwidth: RF bandwidth in Hz
            tx_gain: Transmit gain in dB
            rx_gain: Receive gain in dB
        """

    @abstractmethod
    def transmit(self, iq_samples: np.ndarray) -> None:
        """Transmit IQ samples.

        Args:
            iq_samples: Complex baseband samples (np.complex64)
        """

    @abstractmethod
    def receive(self, num_samples: int) -> np.ndarray:
        """Receive IQ samples.

        Args:
            num_samples: Number of complex samples to receive

        Returns:
            Complex baseband samples (np.complex64)
        """

    @property
    def device_name(self) -> str:
        """Human-readable device/board name."""
        return "Unknown"

    @abstractmethod
    def close(self) -> None:
        """Release hardware resources."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
