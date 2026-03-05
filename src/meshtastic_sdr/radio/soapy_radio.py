"""SoapySDR radio backend — universal SDR hardware support.

Supports any device with a SoapySDR driver: HackRF, LimeSDR, PlutoSDR,
USRP, Airspy, RTL-SDR (RX only), and BladeRF (as alternative to native driver).

Uses CF32 sample format — SoapySDR handles conversion from each device's
native format (CS16, CU8, CS8, etc.) transparently.

Requires: SoapySDR Python bindings (system package, not pip).
  Ubuntu/Debian: sudo apt install python3-soapysdr
  Plus driver for your device, e.g.: sudo apt install soapysdr-module-bladerf
"""

import logging
import numpy as np
from .base import RadioBackend

try:
    import SoapySDR
    from SoapySDR import SOAPY_SDR_TX, SOAPY_SDR_RX, SOAPY_SDR_CF32
    HAS_SOAPY = True
except ImportError:
    HAS_SOAPY = False

logger = logging.getLogger(__name__)


# Known driver keys -> friendly display names
_DRIVER_NAMES = {
    "bladerf": "BladeRF",
    "hackrf": "HackRF One",
    "rtlsdr": "RTL-SDR",
    "lime": "LimeSDR",
    "plutosdr": "PlutoSDR",
    "uhd": "USRP",
    "airspy": "Airspy",
    "airspyhf": "Airspy HF+",
    "sdrplay": "SDRplay",
    "redpitaya": "Red Pitaya",
    "remote": "SoapyRemote",
}


def _parse_device_string(device_str: str) -> dict:
    """Parse a SoapySDR device string into a kwargs dict.

    Accepts: "driver=hackrf", "driver=lime,serial=abc", or "".
    """
    if not device_str:
        return {}
    args = {}
    for item in device_str.split(","):
        item = item.strip()
        if "=" in item:
            key, val = item.split("=", 1)
            args[key.strip()] = val.strip()
    return args


class SoapyRadio(RadioBackend):
    """Universal SDR radio backend via SoapySDR.

    Works with any SDR that has a SoapySDR driver module installed.
    TX/RX capabilities are auto-detected from the device.
    """

    def __init__(self, device_str: str = "", channel: int = 0):
        """Initialize SoapySDR device.

        Args:
            device_str: SoapySDR device identification string.
                        Examples: "driver=hackrf", "driver=lime,serial=abc", "".
                        Empty string uses the first available device.
            channel: RF channel index (0 for most devices).
        """
        if not HAS_SOAPY:
            raise ImportError(
                "SoapySDR Python bindings not installed. "
                "Install via system package (e.g., sudo apt install python3-soapysdr) "
                "and the driver module for your SDR."
            )

        args = _parse_device_string(device_str)
        try:
            self._dev = SoapySDR.Device(args)
        except Exception as e:
            available = SoapySDR.Device.enumerate()
            if not available:
                raise RuntimeError("No SoapySDR devices found") from e
            drivers = [d.get("driver", "?") for d in available]
            raise RuntimeError(
                f"Failed to open SoapySDR device ({device_str or 'auto'}): {e}. "
                f"Available drivers: {', '.join(drivers)}"
            ) from e

        self._channel = channel
        self._rx_stream = None
        self._tx_stream = None
        self._configured = False

        # Query device capabilities
        self._driver_key = self._dev.getDriverKey()
        self._hw_key = self._dev.getHardwareKey()
        self._hw_info = self._dev.getHardwareInfo()
        self._has_tx = self._dev.getNumChannels(SOAPY_SDR_TX) > channel
        self._has_rx = self._dev.getNumChannels(SOAPY_SDR_RX) > channel

        if not self._has_rx:
            raise RuntimeError(
                f"SoapySDR device {self._driver_key} has no RX channel {channel}"
            )

        logger.info("SoapySDR: %s (%s), TX=%s, RX=%s",
                     self._driver_key, self._hw_key, self._has_tx, self._has_rx)

    @property
    def device_name(self) -> str:
        name = _DRIVER_NAMES.get(self._driver_key.lower(), self._driver_key)
        serial = self._hw_info.get("serial", "")
        if serial and len(serial) > 4:
            return f"{name} ({serial[:8]})"
        return name

    @property
    def has_tx(self) -> bool:
        """Whether this device supports transmit."""
        return self._has_tx

    @property
    def driver_key(self) -> str:
        """SoapySDR driver key (e.g., 'hackrf', 'lime')."""
        return self._driver_key

    def configure(self, frequency: float, sample_rate: int, bandwidth: int,
                  tx_gain: int = 30, rx_gain: int = 30) -> None:
        # Tear down existing streams before reconfiguring
        self._close_streams()

        # Many devices have minimum bandwidth; clamp to 1.5 MHz floor
        rf_bandwidth = max(1500000, bandwidth)

        # Configure RX
        self._dev.setSampleRate(SOAPY_SDR_RX, self._channel, float(sample_rate))
        self._dev.setFrequency(SOAPY_SDR_RX, self._channel, float(frequency))
        self._dev.setBandwidth(SOAPY_SDR_RX, self._channel, float(rf_bandwidth))
        self._dev.setGain(SOAPY_SDR_RX, self._channel, float(rx_gain))

        self._rx_stream = self._dev.setupStream(
            SOAPY_SDR_RX, SOAPY_SDR_CF32, [self._channel]
        )
        self._dev.activateStream(self._rx_stream)

        # Configure TX (if device supports it)
        if self._has_tx:
            self._dev.setSampleRate(SOAPY_SDR_TX, self._channel, float(sample_rate))
            self._dev.setFrequency(SOAPY_SDR_TX, self._channel, float(frequency))
            self._dev.setBandwidth(SOAPY_SDR_TX, self._channel, float(rf_bandwidth))
            self._dev.setGain(SOAPY_SDR_TX, self._channel, float(tx_gain))

            self._tx_stream = self._dev.setupStream(
                SOAPY_SDR_TX, SOAPY_SDR_CF32, [self._channel]
            )
            self._dev.activateStream(self._tx_stream)

        self._configured = True
        logger.info("SoapySDR configured: %.3f MHz, %d sps, BW=%d Hz, "
                     "TX gain=%d dB, RX gain=%d dB",
                     frequency / 1e6, sample_rate, rf_bandwidth, tx_gain, rx_gain)

    def transmit(self, iq_samples: np.ndarray) -> None:
        if not self._configured:
            raise RuntimeError("Radio not configured. Call configure() first.")
        if self._tx_stream is None:
            raise RuntimeError(
                f"Device '{self._driver_key}' does not support TX. "
                "Use a TX-capable SDR (BladeRF, HackRF, LimeSDR, PlutoSDR, USRP)."
            )

        samples = iq_samples.astype(np.complex64)
        total = len(samples)
        offset = 0

        while offset < total:
            chunk = samples[offset:]
            sr = self._dev.writeStream(
                self._tx_stream, [chunk], len(chunk), timeoutUs=5000000
            )
            if sr.ret > 0:
                offset += sr.ret
            elif sr.ret == SoapySDR.SOAPY_SDR_TIMEOUT:
                logger.warning("TX timeout at sample %d/%d", offset, total)
                raise RuntimeError(
                    f"TX timeout: only sent {offset}/{total} samples"
                )
            elif sr.ret == SoapySDR.SOAPY_SDR_UNDERFLOW:
                logger.debug("TX underflow at sample %d/%d (recoverable)", offset, total)
                # Underflow is recoverable — continue sending
            else:
                raise RuntimeError(
                    f"TX error at sample {offset}/{total}: "
                    f"{SoapySDR.errToStr(sr.ret)}"
                )

    def receive(self, num_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("Radio not configured. Call configure() first.")
        if self._rx_stream is None:
            raise RuntimeError("RX stream not initialized")

        result = np.zeros(num_samples, dtype=np.complex64)
        offset = 0
        # Per-chunk timeout: 500ms. Total budget is bounded by the caller
        # (typically ~1s of samples from MeshInterface._rx_loop).
        timeout_us = 500000

        while offset < num_samples:
            remaining = num_samples - offset
            buff = np.zeros(remaining, dtype=np.complex64)
            sr = self._dev.readStream(
                self._rx_stream, [buff], remaining, timeoutUs=timeout_us
            )
            if sr.ret > 0:
                result[offset:offset + sr.ret] = buff[:sr.ret]
                offset += sr.ret
            elif sr.ret == SoapySDR.SOAPY_SDR_TIMEOUT:
                # Return what we have — unfilled portion is zeros
                break
            elif sr.ret == SoapySDR.SOAPY_SDR_OVERFLOW:
                logger.debug("RX overflow — samples were dropped")
                # Overflow means we're reading too slowly; skip and continue
                continue
            else:
                logger.error("RX error: %s", SoapySDR.errToStr(sr.ret))
                break

        return result

    def _close_streams(self) -> None:
        """Deactivate and close any active streams."""
        if self._rx_stream is not None:
            try:
                self._dev.deactivateStream(self._rx_stream)
                self._dev.closeStream(self._rx_stream)
            except Exception:
                pass
            self._rx_stream = None

        if self._tx_stream is not None:
            try:
                self._dev.deactivateStream(self._tx_stream)
                self._dev.closeStream(self._tx_stream)
            except Exception:
                pass
            self._tx_stream = None

    def close(self) -> None:
        self._close_streams()
        self._configured = False

    @staticmethod
    def enumerate_devices() -> list[dict]:
        """List all available SoapySDR devices.

        Returns list of dicts with 'driver', 'label', 'serial', 'device_str' keys.
        """
        if not HAS_SOAPY:
            return []
        try:
            results = SoapySDR.Device.enumerate()
        except Exception:
            return []
        devices = []
        for r in results:
            driver = r.get("driver", "unknown")
            devices.append({
                "driver": driver,
                "label": r.get("label", _DRIVER_NAMES.get(driver, driver)),
                "serial": r.get("serial", ""),
                "device_str": ", ".join(f"{k}={v}" for k, v in r.items()),
            })
        return devices
