#!/usr/bin/env python3
"""Scan across channels/frequencies for Meshtastic traffic.

Usage:
    python examples/scanner.py                # With BladeRF
    python examples/scanner.py --simulate     # Simulated mode
"""

import argparse
import sys

sys.path.insert(0, "src")

from meshtastic_sdr.radio.simulated import SimulatedRadio
from meshtastic_sdr.lora.params import get_preset
from meshtastic_sdr.lora.packet import LoRaPacket
from meshtastic_sdr.protocol.channels import REGIONS


def main():
    parser = argparse.ArgumentParser(description="Scan for Meshtastic traffic")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--region", default="US")
    parser.add_argument("--preset", default="LONG_FAST")
    parser.add_argument("--max-channels", type=int, default=50)
    args = parser.parse_args()

    if args.simulate:
        radio = SimulatedRadio()
    else:
        from meshtastic_sdr.radio.bladerf_radio import BladeRFRadio
        radio = BladeRFRadio()

    preset = get_preset(args.preset)
    region = REGIONS[args.region]
    bw_khz = preset.bandwidth / 1000

    print(f"Scanning {args.region}: {region.freq_start}-{region.freq_end} MHz")
    print(f"Preset: {preset.name} (SF{preset.spreading_factor}/{bw_khz:.0f}kHz)")
    print()

    lora = LoRaPacket(preset, preset.bandwidth)
    active = []

    num_ch = min(region.num_channels, args.max_channels)
    for ch in range(num_ch):
        freq = region.channel_frequency(ch, bw_khz)

        radio.configure(
            frequency=freq,
            sample_rate=preset.bandwidth,
            bandwidth=preset.bandwidth,
        )

        listen_time = preset.preamble_duration_s() * 2
        samples = radio.receive(int(listen_time * preset.bandwidth))

        power = float((abs(samples) ** 2).mean()) if len(samples) > 0 else 0

        status = "ACTIVE" if power > 0.001 else "quiet"
        if power > 0.001:
            active.append((ch, freq))
            print(f"  Ch {ch:3d}: {freq / 1e6:10.3f} MHz  [{status}]  power={power:.6f}")

    print(f"\n{len(active)} active channel(s) found out of {num_ch} scanned.")
    radio.close()


if __name__ == "__main__":
    main()
