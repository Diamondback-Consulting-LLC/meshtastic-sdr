"""Tests for SoapySDR radio backend — uses mock SoapySDR to test without hardware."""

import sys
import types
import pytest
import numpy as np

sys.path.insert(0, "src")


# --- Mock SoapySDR module ---

class MockStreamResult:
    """Simulates SoapySDR stream read/write result."""
    def __init__(self, ret=0, flags=0, timeNs=0):
        self.ret = ret
        self.flags = flags
        self.timeNs = timeNs


class MockDevice:
    """Simulates a SoapySDR.Device with configurable capabilities."""

    _enumerate_results = []

    def __init__(self, args=None):
        self._args = args or {}
        self._driver = self._args.get("driver", "mock")
        self._channels_tx = 1
        self._channels_rx = 1
        self._frequency = {0: 0.0, 1: 0.0}  # direction -> freq
        self._sample_rate = {0: 0.0, 1: 0.0}
        self._bandwidth = {0: 0.0, 1: 0.0}
        self._gain = {0: 0.0, 1: 0.0}
        self._streams = {}
        self._stream_counter = 0
        self._active_streams = set()
        self._tx_buffer = []
        self._rx_data = np.array([], dtype=np.complex64)

        if self._driver == "rtlsdr":
            self._channels_tx = 0
        elif self._driver == "fail":
            raise RuntimeError("Simulated device failure")

    @classmethod
    def enumerate(cls, args=None):
        return cls._enumerate_results

    def getDriverKey(self):
        return self._driver

    def getHardwareKey(self):
        return f"{self._driver}-hw"

    def getHardwareInfo(self):
        return {"serial": "MOCK12345678", "driver": self._driver}

    def getNumChannels(self, direction):
        if direction == 0:  # TX
            return self._channels_tx
        return self._channels_rx

    def setSampleRate(self, direction, channel, rate):
        self._sample_rate[direction] = rate

    def setFrequency(self, direction, channel, freq):
        self._frequency[direction] = freq

    def setBandwidth(self, direction, channel, bw):
        self._bandwidth[direction] = bw

    def setGain(self, direction, channel, gain):
        self._gain[direction] = gain

    def setupStream(self, direction, fmt, channels=None):
        self._stream_counter += 1
        stream_id = self._stream_counter
        self._streams[stream_id] = {"direction": direction, "fmt": fmt}
        return stream_id

    def activateStream(self, stream, flags=0, timeNs=0, numElems=0):
        self._active_streams.add(stream)

    def deactivateStream(self, stream, flags=0, timeNs=0):
        self._active_streams.discard(stream)

    def closeStream(self, stream):
        self._streams.pop(stream, None)
        self._active_streams.discard(stream)

    def readStream(self, stream, buffs, numElems, timeoutUs=0):
        if len(self._rx_data) == 0:
            return MockStreamResult(ret=-1)  # TIMEOUT

        n = min(numElems, len(self._rx_data))
        buffs[0][:n] = self._rx_data[:n]
        self._rx_data = self._rx_data[n:]
        return MockStreamResult(ret=n)

    def writeStream(self, stream, buffs, numElems, flags=0, timeNs=0, timeoutUs=0):
        data = buffs[0][:numElems].copy()
        self._tx_buffer.append(data)
        return MockStreamResult(ret=numElems)

    def getStreamMTU(self, stream):
        return 65536

    def inject_rx_data(self, samples):
        """Test helper: inject samples for readStream to return."""
        self._rx_data = np.concatenate([self._rx_data, samples.astype(np.complex64)])


def _install_mock_soapy():
    """Install a mock SoapySDR module into sys.modules."""
    mock_module = types.ModuleType("SoapySDR")
    mock_module.Device = MockDevice
    mock_module.SOAPY_SDR_TX = 0
    mock_module.SOAPY_SDR_RX = 1
    mock_module.SOAPY_SDR_CF32 = "CF32"
    mock_module.SOAPY_SDR_TIMEOUT = -1
    mock_module.SOAPY_SDR_STREAM_ERROR = -2
    mock_module.SOAPY_SDR_OVERFLOW = -4
    mock_module.SOAPY_SDR_UNDERFLOW = -7
    mock_module.errToStr = lambda code: f"MOCK_ERROR_{code}"

    sys.modules["SoapySDR"] = mock_module
    return mock_module


# Install mock before importing soapy_radio
_mock_soapy = _install_mock_soapy()

# Force reimport of soapy_radio with mock available
if "meshtastic_sdr.radio.soapy_radio" in sys.modules:
    del sys.modules["meshtastic_sdr.radio.soapy_radio"]

from meshtastic_sdr.radio.soapy_radio import SoapyRadio, _parse_device_string, HAS_SOAPY


# --- Tests ---

class TestParseDeviceString:
    def test_empty_string(self):
        assert _parse_device_string("") == {}

    def test_single_kv(self):
        assert _parse_device_string("driver=hackrf") == {"driver": "hackrf"}

    def test_multiple_kv(self):
        result = _parse_device_string("driver=lime,serial=abc123")
        assert result == {"driver": "lime", "serial": "abc123"}

    def test_whitespace_handling(self):
        result = _parse_device_string("driver = hackrf , serial = abc")
        assert result == {"driver": "hackrf", "serial": "abc"}

    def test_no_equals(self):
        result = _parse_device_string("noequals")
        assert result == {}


class TestSoapyRadioInit:
    def test_opens_default_device(self):
        radio = SoapyRadio()
        assert radio.driver_key == "mock"
        assert radio.has_tx is True
        radio.close()

    def test_opens_with_driver_string(self):
        radio = SoapyRadio(device_str="driver=mock")
        assert radio.driver_key == "mock"
        radio.close()

    def test_rx_only_device(self):
        radio = SoapyRadio(device_str="driver=rtlsdr")
        assert radio.has_tx is False
        assert radio.driver_key == "rtlsdr"
        radio.close()

    def test_device_name_with_serial(self):
        radio = SoapyRadio()
        # Mock returns serial "MOCK12345678"
        assert "MOCK1234" in radio.device_name
        radio.close()

    def test_device_name_known_driver(self):
        radio = SoapyRadio(device_str="driver=hackrf")
        assert "HackRF" in radio.device_name
        radio.close()

    def test_failed_device_raises(self):
        with pytest.raises(RuntimeError, match="No SoapySDR devices found"):
            SoapyRadio(device_str="driver=fail")


class TestSoapyRadioConfigure:
    def test_configure_full_duplex(self):
        radio = SoapyRadio()
        radio.configure(
            frequency=906.875e6,
            sample_rate=250000,
            bandwidth=250000,
            tx_gain=30,
            rx_gain=30,
        )
        assert radio._configured is True
        assert radio._rx_stream is not None
        assert radio._tx_stream is not None
        radio.close()

    def test_configure_rx_only(self):
        radio = SoapyRadio(device_str="driver=rtlsdr")
        radio.configure(
            frequency=906.875e6,
            sample_rate=250000,
            bandwidth=250000,
        )
        assert radio._configured is True
        assert radio._rx_stream is not None
        assert radio._tx_stream is None
        radio.close()

    def test_reconfigure_closes_old_streams(self):
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)
        first_rx = radio._rx_stream
        first_tx = radio._tx_stream

        radio.configure(frequency=915e6, sample_rate=500000, bandwidth=500000)
        # Old streams should be closed, new ones created
        assert radio._rx_stream != first_rx
        assert radio._tx_stream != first_tx
        radio.close()

    def test_bandwidth_floor(self):
        """Bandwidth is clamped to minimum 1.5 MHz."""
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)
        # Check that the device got at least 1.5 MHz bandwidth
        assert radio._dev._bandwidth[1] == 1500000  # RX direction = 1
        radio.close()


class TestSoapyRadioReceive:
    def test_receive_exact_samples(self):
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)

        # Inject test data
        test_data = np.ones(1000, dtype=np.complex64) * (0.5 + 0.5j)
        radio._dev.inject_rx_data(test_data)

        result = radio.receive(1000)
        assert len(result) == 1000
        np.testing.assert_array_almost_equal(result, test_data)
        radio.close()

    def test_receive_partial_pads_zeros(self):
        """When device has fewer samples than requested, remainder is zeros."""
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)

        test_data = np.ones(500, dtype=np.complex64) * 0.5
        radio._dev.inject_rx_data(test_data)

        result = radio.receive(1000)
        assert len(result) == 1000
        # First 500 should be our data
        np.testing.assert_array_almost_equal(result[:500], test_data)
        # Remaining should be zeros
        np.testing.assert_array_equal(result[500:], 0)
        radio.close()

    def test_receive_empty_returns_zeros(self):
        """No data available returns all zeros."""
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)

        result = radio.receive(1000)
        assert len(result) == 1000
        np.testing.assert_array_equal(result, 0)
        radio.close()

    def test_receive_before_configure_raises(self):
        radio = SoapyRadio()
        with pytest.raises(RuntimeError, match="not configured"):
            radio.receive(1000)
        radio.close()


class TestSoapyRadioTransmit:
    def test_transmit_samples(self):
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)

        test_data = np.ones(1000, dtype=np.complex64) * 0.7
        radio.transmit(test_data)

        # Verify data was passed to device
        assert len(radio._dev._tx_buffer) == 1
        np.testing.assert_array_almost_equal(
            radio._dev._tx_buffer[0], test_data
        )
        radio.close()

    def test_transmit_rx_only_raises(self):
        """TX on RX-only device raises RuntimeError."""
        radio = SoapyRadio(device_str="driver=rtlsdr")
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)

        with pytest.raises(RuntimeError, match="does not support TX"):
            radio.transmit(np.ones(100, dtype=np.complex64))
        radio.close()

    def test_transmit_before_configure_raises(self):
        radio = SoapyRadio()
        with pytest.raises(RuntimeError, match="not configured"):
            radio.transmit(np.ones(100, dtype=np.complex64))
        radio.close()


class TestSoapyRadioClose:
    def test_close_deactivates_streams(self):
        radio = SoapyRadio()
        radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)
        assert radio._rx_stream is not None

        radio.close()
        assert radio._rx_stream is None
        assert radio._tx_stream is None
        assert radio._configured is False

    def test_close_idempotent(self):
        radio = SoapyRadio()
        radio.close()
        radio.close()  # Should not raise

    def test_context_manager(self):
        with SoapyRadio() as radio:
            radio.configure(frequency=906e6, sample_rate=250000, bandwidth=250000)
        assert radio._configured is False


class TestSoapyRadioEnumerate:
    def test_enumerate_empty(self):
        MockDevice._enumerate_results = []
        devices = SoapyRadio.enumerate_devices()
        assert devices == []

    def test_enumerate_devices(self):
        MockDevice._enumerate_results = [
            {"driver": "hackrf", "label": "HackRF One", "serial": "abc123"},
            {"driver": "rtlsdr", "label": "RTL-SDR", "serial": "def456"},
        ]
        devices = SoapyRadio.enumerate_devices()
        assert len(devices) == 2
        assert devices[0]["driver"] == "hackrf"
        assert devices[0]["serial"] == "abc123"
        assert devices[1]["driver"] == "rtlsdr"

        # Reset
        MockDevice._enumerate_results = []


class TestSoapyRadioIsRadioBackend:
    def test_implements_radio_backend(self):
        """SoapyRadio is a proper RadioBackend subclass."""
        from meshtastic_sdr.radio.base import RadioBackend
        radio = SoapyRadio()
        assert isinstance(radio, RadioBackend)
        radio.close()
