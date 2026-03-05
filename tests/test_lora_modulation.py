"""Tests for LoRa CSS chirp modulation and demodulation round-trip."""

import sys
import numpy as np
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.lora.params import get_preset, PRESETS, ModemPreset, CodingRate
from meshtastic_sdr.lora.modulator import LoRaModulator
from meshtastic_sdr.lora.demodulator import LoRaDemodulator


class TestModulatorBasics:
    def test_upchirp_length(self):
        preset = get_preset("LONG_FAST")
        mod = LoRaModulator(preset)
        chirp = mod.upchirp()
        assert len(chirp) == 2 ** preset.spreading_factor

    def test_downchirp_length(self):
        preset = get_preset("LONG_FAST")
        mod = LoRaModulator(preset)
        chirp = mod.downchirp()
        assert len(chirp) == 2 ** preset.spreading_factor

    def test_chirp_is_unit_magnitude(self):
        preset = get_preset("SHORT_FAST")
        mod = LoRaModulator(preset)
        chirp = mod.upchirp()
        magnitudes = np.abs(chirp)
        np.testing.assert_allclose(magnitudes, 1.0, atol=1e-5)

    def test_modulate_produces_output(self):
        preset = get_preset("SHORT_FAST")
        mod = LoRaModulator(preset)
        symbols = [0, 1, 2, 3]
        iq = mod.modulate(symbols)
        assert len(iq) > 0
        assert iq.dtype == np.complex64

    def test_frame_structure_length(self):
        """Verify total frame length matches expected structure."""
        preset = get_preset("SHORT_FAST")
        mod = LoRaModulator(preset)
        N = 2 ** preset.spreading_factor
        symbols = [10, 20, 30]

        iq = mod.modulate(symbols)

        # Expected: preamble(16) + sync(2) + SFD(2.25) + data(3)
        expected_symbols = 16 + 2 + 2.25 + 3
        expected_samples = int(expected_symbols * N)
        assert len(iq) == expected_samples


class TestDemodulatorBasics:
    def test_single_symbol_dechirp(self):
        """Verify that a single symbol can be recovered via dechirp+FFT."""
        preset = get_preset("SHORT_FAST")  # SF7 is fast
        mod = LoRaModulator(preset)
        demod = LoRaDemodulator(preset)

        for sym_val in [0, 1, 64, 127]:
            chirp = mod._modulate_symbol(sym_val)
            detected = demod._dechirp_and_detect(chirp)
            assert detected == sym_val, f"Expected {sym_val}, got {detected}"


class TestModDemodRoundTrip:
    @pytest.mark.parametrize("preset_name", ["SHORT_FAST", "SHORT_SLOW"])
    def test_symbols_roundtrip_clean(self, preset_name):
        """Modulate then demodulate symbols — should recover exactly."""
        preset = get_preset(preset_name)
        mod = LoRaModulator(preset)
        demod = LoRaDemodulator(preset)

        N = 2 ** preset.spreading_factor
        # Use a few random symbols
        np.random.seed(42)
        original_symbols = list(np.random.randint(0, N, size=5))

        iq = mod.modulate(original_symbols)
        recovered = demod.demodulate(iq)

        assert recovered is not None, "Demodulator returned None"
        assert len(recovered) >= len(original_symbols)
        # Compare only the first len(original_symbols) symbols
        assert recovered[:len(original_symbols)] == original_symbols

    def test_symbols_roundtrip_with_noise(self):
        """Modulate + add noise, then demodulate — should still recover at high SNR."""
        preset = get_preset("SHORT_FAST")
        mod = LoRaModulator(preset)
        demod = LoRaDemodulator(preset)

        N = 2 ** preset.spreading_factor
        original_symbols = [10, 50, 100]

        iq = mod.modulate(original_symbols)

        # Add noise at 20 dB SNR (should be easily recoverable)
        signal_power = np.mean(np.abs(iq) ** 2)
        noise_power = signal_power / (10 ** (20 / 10))
        noise = np.sqrt(noise_power / 2) * (
            np.random.randn(len(iq)) + 1j * np.random.randn(len(iq))
        )
        noisy_iq = (iq + noise).astype(np.complex64)

        recovered = demod.demodulate(noisy_iq)
        assert recovered is not None
        assert recovered[:len(original_symbols)] == original_symbols


class TestOversampling:
    def test_oversampled_modulation(self):
        """Test modulation with 4x oversampling."""
        preset = get_preset("SHORT_FAST")
        sample_rate = preset.bandwidth * 4
        mod = LoRaModulator(preset, sample_rate=sample_rate)
        demod = LoRaDemodulator(preset, sample_rate=sample_rate)

        symbols = [5, 42, 100]
        iq = mod.modulate(symbols)

        # Should be 4x longer than non-oversampled
        N = 2 ** preset.spreading_factor
        expected_base_samples = (16 + 2 + 2.25 + 3) * N
        assert len(iq) == int(expected_base_samples * 4)

        recovered = demod.demodulate(iq)
        assert recovered is not None
        assert recovered[:len(symbols)] == symbols


class TestPresetTiming:
    def test_long_fast_symbol_duration(self):
        preset = get_preset("LONG_FAST")
        # SF11, 250kHz: symbol = 2^11 / 250000 = 8.192 ms
        expected = 2048 / 250000
        assert abs(preset.symbol_duration_s - expected) < 1e-9

    def test_airtime_positive(self):
        for name, preset in PRESETS.items():
            airtime = preset.airtime_ms(50)
            assert airtime > 0, f"Preset {name} has non-positive airtime"
