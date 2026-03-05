#!/usr/bin/env python3
"""Minimal Meshtastic receive-and-print example.

Usage:
    python examples/listen.py                  # With BladeRF hardware
    python examples/listen.py --simulate       # Simulated mode
"""

import argparse
import signal
import sys
import time

sys.path.insert(0, "src")

from meshtastic_sdr.radio.simulated import SimulatedRadio
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.mesh.interface import MeshInterface
from meshtastic_sdr.protocol.mesh_packet import MeshPacket


def main():
    parser = argparse.ArgumentParser(description="Listen for Meshtastic messages")
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
        print(f"Listening as {mesh.node.node_id_str} on {mesh.frequency / 1e6:.3f} MHz")

        def on_message(packet: MeshPacket):
            src = f"!{packet.header.from_node:08x}"
            if packet.data and packet.data.text:
                print(f"{src}: {packet.data.text}")
            else:
                print(f"{src}: (non-text packet)")

        mesh.start_receive(on_message)

        signal.signal(signal.SIGINT, lambda *_: (mesh.close(), sys.exit(0)))
        while True:
            time.sleep(1)


if __name__ == "__main__":
    main()
