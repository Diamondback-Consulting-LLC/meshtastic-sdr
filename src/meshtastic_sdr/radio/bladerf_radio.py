"""BladeRF x40 radio backend.

Uses the official Nuand bladerf Python bindings for hardware control.
SC16_Q11 sample format (12-bit I/Q packed as int16).

The BladeRF x40 is full-duplex at the RF level (independent TX/RX paths on
the LMS6002D), so sync_tx and sync_rx can be called from separate threads.
However, for same-frequency LoRa operation, the TX signal drowns RX — callers
must discard RX samples captured during TX.

Requires: bladerf package (pip install bladerf)
"""

import threading
import numpy as np
from .base import RadioBackend

try:
    import bladerf._bladerf as _bladerf
    HAS_BLADERF = True
except ImportError:
    HAS_BLADERF = False


# SC16_Q11 scaling: 11 fractional bits -> max value 2047
SC16_Q11_SCALE = 2047.0


def complex64_to_sc16q11(samples: np.ndarray) -> np.ndarray:
    """Convert complex64 IQ samples to SC16_Q11 interleaved int16 format."""
    i_samples = np.real(samples) * SC16_Q11_SCALE
    q_samples = np.imag(samples) * SC16_Q11_SCALE
    i_int16 = np.clip(i_samples, -2048, 2047).astype(np.int16)
    q_int16 = np.clip(q_samples, -2048, 2047).astype(np.int16)
    interleaved = np.empty(2 * len(samples), dtype=np.int16)
    interleaved[0::2] = i_int16
    interleaved[1::2] = q_int16
    return interleaved


def sc16q11_to_complex64(interleaved: np.ndarray) -> np.ndarray:
    """Convert SC16_Q11 interleaved int16 to complex64 IQ samples."""
    i_samples = interleaved[0::2].astype(np.float32) / SC16_Q11_SCALE
    q_samples = interleaved[1::2].astype(np.float32) / SC16_Q11_SCALE
    return (i_samples + 1j * q_samples).astype(np.complex64)


class BladeRFRadio(RadioBackend):
    """BladeRF x40 SDR radio backend."""

    # Buffer sizes must be multiples of 1024
    NUM_BUFFERS = 16
    BUFFER_SIZE = 8192  # samples per buffer
    NUM_TRANSFERS = 8

    def __init__(self, device_str: str = "", xb200: str = "auto",
                 xb200_filter: str = "auto_1db"):
        """Initialize BladeRF device.

        Args:
            device_str: BladeRF device identifier string (empty = first device)
            xb200: XB-200 transverter handling: "auto" | "true" | "false"
            xb200_filter: XB-200 filter bank: auto_1db, auto_3db, custom, 50m, 144m, 222m
        """
        if not HAS_BLADERF:
            raise ImportError(
                "bladerf package not installed. Install with: pip install bladerf"
            )

        self._dev = _bladerf.BladeRF(device_str)
        self._tx_channel = _bladerf.CHANNEL_TX(0)
        self._rx_channel = _bladerf.CHANNEL_RX(0)
        self._configured = False
        self._xb200 = xb200
        self._xb200_filter = xb200_filter
        self._xb200_attached = False

        # TX state tracking — callers use this to know when RX is contaminated
        self._tx_lock = threading.Lock()
        self._tx_active = False
        self._tx_happened = threading.Event()  # Set whenever a TX completes

        # Query board info
        try:
            self._board_name = self._dev.board_name  # e.g. "bladerf1", "bladerf2"
        except Exception:
            self._board_name = "BladeRF"

    @staticmethod
    def _resolve_xb200_filter(name: str):
        """Map filter name string to _bladerf.XB200Filter enum value."""
        mapping = {
            "auto_1db": _bladerf.XB200Filter.AUTO_1DB,
            "auto_3db": _bladerf.XB200Filter.AUTO_3DB,
            "custom": _bladerf.XB200Filter.CUSTOM,
            "50m": _bladerf.XB200Filter.MIX_50M,
            "144m": _bladerf.XB200Filter.MIX_144M,
            "222m": _bladerf.XB200Filter.MIX_222M,
        }
        return mapping.get(name.lower(), _bladerf.XB200Filter.AUTO_1DB)

    def _attach_xb200(self) -> None:
        """Attach XB-200 transverter based on config."""
        if self._xb200 == "false" or self._xb200_attached:
            return

        try:
            self._dev.expansion_attach(_bladerf.XB200)
            xb_filter = self._resolve_xb200_filter(self._xb200_filter)
            self._dev.xb200_set_filterbank(self._tx_channel, xb_filter)
            self._dev.xb200_set_filterbank(self._rx_channel, xb_filter)
            self._xb200_attached = True
        except Exception:
            if self._xb200 == "true":
                raise
            # "auto" mode: silently continue without XB-200

    # Friendly display names for known board identifiers
    BOARD_NAMES = {
        "bladerf1": "BladeRF x40",
        "bladerf2": "BladeRF 2.0",
    }

    @property
    def device_name(self) -> str:
        return self.BOARD_NAMES.get(self._board_name, self._board_name)

    def configure(self, frequency: float, sample_rate: int, bandwidth: int,
                  tx_gain: int = 30, rx_gain: int = 30) -> None:
        # Attach XB-200 before frequency/gain setup
        self._attach_xb200()

        # BladeRF min bandwidth is 1.5 MHz; we'll set it to at least that
        # and rely on software filtering for narrower LoRa bandwidths
        rf_bandwidth = max(1500000, bandwidth)

        # Configure TX
        self._dev.set_frequency(self._tx_channel, int(frequency))
        self._dev.set_sample_rate(self._tx_channel, sample_rate)
        self._dev.set_bandwidth(self._tx_channel, rf_bandwidth)
        self._dev.set_gain(self._tx_channel, tx_gain)

        # Configure RX
        self._dev.set_frequency(self._rx_channel, int(frequency))
        self._dev.set_sample_rate(self._rx_channel, sample_rate)
        self._dev.set_bandwidth(self._rx_channel, rf_bandwidth)
        self._dev.set_gain(self._rx_channel, rx_gain)

        # Setup sync config for both channels
        self._dev.sync_config(
            layout=_bladerf.ChannelLayout.RX_X1,
            fmt=_bladerf.Format.SC16_Q11,
            num_buffers=self.NUM_BUFFERS,
            buffer_size=self.BUFFER_SIZE,
            num_transfers=self.NUM_TRANSFERS,
            stream_timeout=3500,
        )
        self._dev.sync_config(
            layout=_bladerf.ChannelLayout.TX_X1,
            fmt=_bladerf.Format.SC16_Q11,
            num_buffers=self.NUM_BUFFERS,
            buffer_size=self.BUFFER_SIZE,
            num_transfers=self.NUM_TRANSFERS,
            stream_timeout=3500,
        )

        self._dev.enable_module(self._tx_channel, True)
        self._dev.enable_module(self._rx_channel, True)
        self._configured = True

    def transmit(self, iq_samples: np.ndarray) -> None:
        if not self._configured:
            raise RuntimeError("Radio not configured. Call configure() first.")

        sc16 = complex64_to_sc16q11(iq_samples)

        # Pad to multiple of 1024 samples (2048 int16 values)
        pad_unit = 1024 * 2  # int16 values per 1024 complex samples
        remainder = len(sc16) % pad_unit
        if remainder:
            sc16 = np.pad(sc16, (0, pad_unit - remainder))

        with self._tx_lock:
            self._tx_active = True
        try:
            self._dev.sync_tx(sc16.tobytes(), len(sc16) // 2)
        finally:
            with self._tx_lock:
                self._tx_active = False
                self._tx_happened.set()

    def receive(self, num_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("Radio not configured. Call configure() first.")

        # Round up to multiple of 1024
        aligned = ((num_samples + 1023) // 1024) * 1024
        buf = bytearray(aligned * 4)  # 4 bytes per sample (2x int16)
        self._dev.sync_rx(buf, aligned)

        interleaved = np.frombuffer(buf, dtype=np.int16)
        samples = sc16q11_to_complex64(interleaved)
        return samples[:num_samples]

    @property
    def tx_active(self) -> bool:
        with self._tx_lock:
            return self._tx_active

    def check_and_clear_tx_happened(self) -> bool:
        happened = self._tx_happened.is_set()
        if happened:
            self._tx_happened.clear()
        return happened

    def flush_rx(self) -> None:
        """Read and discard one buffer of RX samples after TX contamination."""
        if not self._configured:
            return
        buf = bytearray(self.BUFFER_SIZE * 4)
        try:
            self._dev.sync_rx(buf, self.BUFFER_SIZE)
        except Exception:
            pass

    def close(self) -> None:
        if self._configured:
            self._dev.enable_module(self._tx_channel, False)
            self._dev.enable_module(self._rx_channel, False)
            self._configured = False
        self._dev.close()
