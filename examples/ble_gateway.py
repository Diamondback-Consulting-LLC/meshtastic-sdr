#!/usr/bin/env python3
"""BLE Gateway example — act as a Meshtastic BLE device for phone connections.

The phone connects to us via BLE, and we transmit/receive over the air
via the BladeRF SDR (or simulated radio for testing).

Usage:
    # Simulated radio (no hardware needed)
    python examples/ble_gateway.py --simulate

    # With BladeRF
    python examples/ble_gateway.py

Requires: pip install meshtastic-sdr[ble-peripheral]
Note: Linux may require root or CAP_NET_ADMIN for BLE advertising.
"""

import asyncio
import sys
import time

sys.path.insert(0, "src")

from meshtastic_sdr.ble.peripheral import BLEGateway
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.mesh.interface import MeshInterface
from meshtastic_sdr.radio.simulated import SimulatedRadio


async def main():
    simulate = "--simulate" in sys.argv
    name = "Meshtastic SDR"

    for i, arg in enumerate(sys.argv):
        if arg == "--name" and i + 1 < len(sys.argv):
            name = sys.argv[i + 1]

    node = MeshNode(long_name=name, short_name="SDR")

    # Set up radio
    if simulate:
        radio = SimulatedRadio()
        print("Using simulated radio (loopback mode)")
    else:
        try:
            from meshtastic_sdr.radio.bladerf_radio import BladeRFRadio
            radio = BladeRFRadio()
        except ImportError:
            print("BladeRF not available. Use --simulate for testing.")
            sys.exit(1)

    interface = MeshInterface(radio=radio, preset_name="SHORT_FAST", node=node)
    interface.configure_radio()

    def on_phone_packet(packet):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] Phone TX: id=0x{packet.header.id:08x}")
        interface._transmit_packet(packet)

    gateway = BLEGateway(node=node, on_packet_from_phone=on_phone_packet)

    print(f"Starting BLE gateway as '{name}'...")
    await gateway.start(name=name)
    print("Gateway running. Connect with the Meshtastic app.")
    print("Press Ctrl+C to stop.\n")

    def on_radio_rx(packet):
        ts = time.strftime("%H:%M:%S")
        src = f"!{packet.header.from_node:08x}"
        print(f"[{ts}] Radio RX from {src} -> phone")
        gateway.queue_packet_for_phone(packet)

    interface.start_receive(on_radio_rx)

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down...")
        await gateway.stop()
        interface.close()


if __name__ == "__main__":
    asyncio.run(main())
