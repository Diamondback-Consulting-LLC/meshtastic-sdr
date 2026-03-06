"""Meshtastic channel configuration and region frequency management.

Handles channel hash computation, PSK handling, and frequency calculation
for all 27 Meshtastic regions.
"""

import json
from dataclasses import dataclass, field

from .encryption import DEFAULT_KEY, get_default_key


@dataclass
class RegionConfig:
    name: str
    freq_start: float   # MHz
    freq_end: float      # MHz
    num_channels: int
    max_power: int       # dBm
    duty_cycle: float    # 0-100 percent, 0 = no limit

    def channel_frequency(self, channel_num: int, bandwidth_khz: float) -> float:
        """Calculate center frequency for a channel in Hz.

        Formula: freq_start + (BW/2000) + (channel_num * BW/1000)
        All in MHz, returns Hz.
        """
        bw_mhz = bandwidth_khz / 1000.0
        freq_mhz = self.freq_start + (bw_mhz / 2) + (channel_num * bw_mhz)
        return freq_mhz * 1e6


# All 27 Meshtastic region definitions
REGIONS = {
    "US": RegionConfig("US", 902.0, 928.0, 104, 30, 0),
    "EU_433": RegionConfig("EU_433", 433.0, 434.0, 4, 12, 10),
    "EU_868": RegionConfig("EU_868", 869.4, 869.65, 1, 27, 10),
    "CN": RegionConfig("CN", 470.0, 510.0, 160, 19, 0),
    "JP": RegionConfig("JP", 920.8, 927.8, 28, 16, 0),
    "ANZ": RegionConfig("ANZ", 915.0, 928.0, 52, 30, 0),
    "KR": RegionConfig("KR", 920.0, 923.0, 12, 14, 0),
    "TW": RegionConfig("TW", 920.0, 925.0, 20, 27, 0),
    "RU": RegionConfig("RU", 868.7, 869.2, 2, 20, 0),
    "IN": RegionConfig("IN", 865.0, 867.0, 8, 30, 0),
    "NZ_865": RegionConfig("NZ_865", 864.0, 868.0, 16, 36, 0),
    "TH": RegionConfig("TH", 920.0, 925.0, 20, 16, 0),
    "UA_433": RegionConfig("UA_433", 433.0, 434.79, 7, 10, 0),
    "UA_868": RegionConfig("UA_868", 868.0, 868.6, 2, 14, 0),
    "MY_433": RegionConfig("MY_433", 433.0, 435.0, 8, 10, 0),
    "MY_919": RegionConfig("MY_919", 919.0, 924.0, 20, 27, 0),
    "SG_923": RegionConfig("SG_923", 920.0, 925.0, 20, 27, 0),
    "LORA_24": RegionConfig("LORA_24", 2400.0, 2483.5, 6, 10, 0),
    "PH_433": RegionConfig("PH_433", 433.05, 434.79, 7, 10, 0),
    "PH_868": RegionConfig("PH_868", 920.0, 925.0, 20, 16, 0),
    "IL_433": RegionConfig("IL_433", 433.05, 434.79, 7, 10, 0),
    "IL_915": RegionConfig("IL_915", 915.0, 917.0, 8, 14, 0),
    "BR_915": RegionConfig("BR_915", 915.0, 928.0, 52, 30, 0),
    "GH_433": RegionConfig("GH_433", 433.05, 434.79, 7, 10, 0),
    "GH_915": RegionConfig("GH_915", 915.0, 928.0, 52, 30, 0),
    "NG_433": RegionConfig("NG_433", 433.05, 434.79, 7, 10, 0),
    "NG_915": RegionConfig("NG_915", 915.0, 928.0, 52, 30, 0),
    "PH_915": RegionConfig("PH_915", 915.0, 928.0, 52, 21, 0),
    "ANZ_433": RegionConfig("ANZ_433", 433.05, 434.79, 7, 10, 0),
    "KZ_433": RegionConfig("KZ_433", 433.05, 434.79, 7, 10, 0),
    "KZ_863": RegionConfig("KZ_863", 863.0, 870.0, 28, 14, 0),
    "NP_865": RegionConfig("NP_865", 865.0, 867.0, 8, 30, 0),
    "BR_902": RegionConfig("BR_902", 902.0, 907.5, 22, 30, 0),
}

DEFAULT_REGION = "US"


def compute_channel_hash(channel_name: str, psk: bytes = b"") -> int:
    """Compute the channel hash byte for the OTA header.

    XOR of all bytes of the UTF-8 encoded channel name AND PSK, masked to 8 bits.
    Matches Meshtastic firmware Channels.cpp and meshtastic-python generate_channel_hash.
    """
    if not channel_name:
        channel_name = "LongFast"  # Default channel name

    h = 0
    for ch in channel_name.encode("utf-8"):
        h ^= ch
    for b in psk:
        h ^= b
    return h & 0xFF


@dataclass
class ChannelConfig:
    """Configuration for a single Meshtastic channel."""

    name: str = ""
    psk: bytes = field(default_factory=lambda: DEFAULT_KEY)
    index: int = 0
    uplink_enabled: bool = False
    downlink_enabled: bool = False

    @classmethod
    def default(cls) -> "ChannelConfig":
        """Create the default channel configuration."""
        return cls(name="LongFast", psk=DEFAULT_KEY, index=0)

    @property
    def display_name(self) -> str:
        return self.name if self.name else "LongFast"

    @property
    def channel_hash(self) -> int:
        return compute_channel_hash(self.display_name, self.psk)

    @classmethod
    def from_psk_shorthand(cls, psk_byte: int, name: str = "",
                           index: int = 0) -> "ChannelConfig":
        """Create channel config from a PSK shorthand (0-10).

        Raises ValueError for out-of-range values.
        """
        if psk_byte < 0 or psk_byte > 10:
            raise ValueError(f"PSK shorthand must be 0-10, got {psk_byte}")
        key = get_default_key(psk_byte)
        return cls(name=name, psk=key, index=index)

    def has_encryption(self) -> bool:
        return len(self.psk) > 0


def get_default_frequency(region: str = DEFAULT_REGION,
                          bandwidth_khz: float = 250.0,
                          channel_num: int = 20) -> float:
    """Get the default frequency in Hz for a region.

    US default: slot 20 at 250 kHz BW -> 907.125 MHz
    """
    if region not in REGIONS:
        raise ValueError(f"Unknown region '{region}'. Available: {list(REGIONS.keys())}")
    return REGIONS[region].channel_frequency(channel_num, bandwidth_khz)


def save_regions_json(path: str) -> None:
    """Save all region definitions to a JSON file."""
    data = {}
    for name, region in REGIONS.items():
        data[name] = {
            "freq_start_mhz": region.freq_start,
            "freq_end_mhz": region.freq_end,
            "num_channels": region.num_channels,
            "max_power_dbm": region.max_power,
            "duty_cycle_percent": region.duty_cycle,
        }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
