#!/usr/bin/env python3
"""Minimal Meshtastic send text example.

Usage:
    python examples/send_text.py "Hello mesh!"              # With BladeRF
    python examples/send_text.py --simulate "Hello mesh!"   # Simulated
"""

import argparse
import sys

sys.path.insert(0, "src")

from meshtastic_sdr.radio.simulated import SimulatedRadio
from meshtastic_sdr.mesh.interface import MeshInterface


def main():
    parser = argparse.ArgumentParser(description="Send a Meshtastic text message")
    parser.add_argument("message", help="Text to send")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--region", default="US")
    parser.add_argument("--preset", default="LONG_FAST")
    args = parser.parse_args()

    if args.simulate:
        radio = SimulatedRadio()
    else:
        from meshtastic_sdr.radio.bladerf_radio import BladeRFRadio
        radio = BladeRFRadio()

    with MeshInterface(radio, preset_name=args.preset, region=args.region) as mesh:
        packet = mesh.send_text(args.message)
        print(f"Sent from {mesh.node.node_id_str}: {args.message!r}")
        print(f"Packet ID: 0x{packet.header.id:08x}")
        print(f"Frequency: {mesh.frequency / 1e6:.3f} MHz")


if __name__ == "__main__":
    main()
