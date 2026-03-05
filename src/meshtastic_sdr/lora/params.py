"""LoRa modem presets and timing calculations.

Defines all 10 Meshtastic modem presets with their exact SF/BW/CR parameters,
plus helper functions for symbol duration, airtime estimation, etc.
"""

from dataclasses import dataclass
from enum import Enum


class CodingRate(Enum):
    CR_4_5 = 1  # 4/5
    CR_4_6 = 2  # 4/6
    CR_4_7 = 3  # 4/7
    CR_4_8 = 4  # 4/8


@dataclass(frozen=True)
class ModemPreset:
    name: str
    spreading_factor: int  # 7-12
    bandwidth: int          # Hz (125000, 250000, 500000)
    coding_rate: CodingRate
    preamble_length: int = 16  # Meshtastic standard

    @property
    def cr_denom(self) -> int:
        return self.coding_rate.value + 4

    @property
    def symbol_duration_s(self) -> float:
        return (2 ** self.spreading_factor) / self.bandwidth

    @property
    def symbol_duration_ms(self) -> float:
        return self.symbol_duration_s * 1000

    @property
    def bits_per_symbol(self) -> int:
        return self.spreading_factor

    @property
    def chip_rate(self) -> int:
        return self.bandwidth

    @property
    def num_samples_per_symbol(self) -> int:
        """Number of chips (samples at BW rate) per symbol."""
        return 2 ** self.spreading_factor

    def preamble_duration_s(self) -> float:
        return (self.preamble_length + 4.25) * self.symbol_duration_s

    def payload_symbols(self, payload_bytes: int, has_crc: bool = True,
                        explicit_header: bool = True) -> int:
        """Calculate number of payload symbols (LoRa spec formula)."""
        sf = self.spreading_factor
        cr = self.coding_rate.value  # 1-4
        de = 1 if sf >= 11 else 0  # Low data rate optimization
        h = 0 if explicit_header else 1

        pl = payload_bytes
        crc_bits = 16 if has_crc else 0

        numerator = 8 * pl - 4 * sf + 28 + crc_bits - 20 * h
        denominator = 4 * (sf - 2 * de)

        n_payload = 8 + max(0, ((numerator + denominator - 1) // denominator)) * (cr + 4)
        return n_payload

    def airtime_s(self, payload_bytes: int, has_crc: bool = True,
                  explicit_header: bool = True) -> float:
        t_preamble = self.preamble_duration_s()
        n_payload = self.payload_symbols(payload_bytes, has_crc, explicit_header)
        t_payload = n_payload * self.symbol_duration_s
        return t_preamble + t_payload

    def airtime_ms(self, payload_bytes: int, **kwargs) -> float:
        return self.airtime_s(payload_bytes, **kwargs) * 1000


# All 10 Meshtastic modem presets
PRESETS = {
    "SHORT_TURBO": ModemPreset("SHORT_TURBO", 7, 500000, CodingRate.CR_4_5),
    "SHORT_FAST": ModemPreset("SHORT_FAST", 7, 250000, CodingRate.CR_4_5),
    "SHORT_SLOW": ModemPreset("SHORT_SLOW", 8, 250000, CodingRate.CR_4_5),
    "MEDIUM_FAST": ModemPreset("MEDIUM_FAST", 9, 250000, CodingRate.CR_4_5),
    "MEDIUM_SLOW": ModemPreset("MEDIUM_SLOW", 10, 250000, CodingRate.CR_4_5),
    "LONG_TURBO": ModemPreset("LONG_TURBO", 11, 500000, CodingRate.CR_4_5),
    "LONG_FAST": ModemPreset("LONG_FAST", 11, 250000, CodingRate.CR_4_5),
    "LONG_MODERATE": ModemPreset("LONG_MODERATE", 11, 125000, CodingRate.CR_4_8),
    "LONG_SLOW": ModemPreset("LONG_SLOW", 12, 125000, CodingRate.CR_4_8),
    "VERY_LONG_SLOW": ModemPreset("VERY_LONG_SLOW", 12, 62500, CodingRate.CR_4_8),
}

DEFAULT_PRESET = "LONG_FAST"


def get_preset(name: str) -> ModemPreset:
    key = name.upper().replace(" ", "_").replace("-", "_")
    if key not in PRESETS:
        raise ValueError(f"Unknown preset '{name}'. Available: {list(PRESETS.keys())}")
    return PRESETS[key]
