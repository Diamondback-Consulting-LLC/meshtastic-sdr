#!/usr/bin/env python3
"""BLE Tether example — connect to a Meshtastic device and relay messages.

Usage:
    # Scan for devices
    python examples/ble_tether.py scan

    # Connect and listen
    python examples/ble_tether.py listen --address XX:XX:XX:XX:XX:XX

    # Send a message
    python examples/ble_tether.py send --address XX:XX:XX:XX:XX:XX --message "Hello!"

Requires: pip install meshtastic-sdr[ble-central]
"""

import asyncio
import sys
import time

sys.path.insert(0, "src")

from meshtastic_sdr.ble.central import BLECentral
from meshtastic_sdr.transport.ble_device_transport import BLEDeviceTransport
from meshtastic_sdr.mesh.interface import AsyncMeshInterface
from meshtastic_sdr.mesh.node import MeshNode


async def scan():
    print("Scanning for Meshtastic BLE devices (5s)...")
    devices = await BLECentral.scan(timeout=5.0)
    if not devices:
        print("No devices found.")
        return
    for d in devices:
        print(f"  {d['name']:20s}  {d['address']}  RSSI: {d['rssi']}")


async def listen(address):
    central = BLECentral()
    print(f"Connecting to {address}...")
    await central.connect(address)
    print("Connected!")

    config = await central.config_handshake()
    for item in config:
        if "my_info" in item:
            print(f"Device: !{item['my_info']['my_node_num']:08x}")

    print("Listening... (Ctrl+C to stop)\n")
    try:
        while True:
            packet = await central.wait_for_packet(timeout_s=10.0)
            if packet:
                ts = time.strftime("%H:%M:%S")
                src = f"!{packet.header.from_node:08x}"
                if packet.data and packet.data.text:
                    print(f"[{ts}] {src}: {packet.data.text}")
                else:
                    print(f"[{ts}] {src}: ({len(packet.encrypted)}B)")
    except KeyboardInterrupt:
        pass
    finally:
        await central.disconnect()
        print("Disconnected.")


async def send(address, message):
    central = BLECentral()
    print(f"Connecting to {address}...")
    await central.connect(address)

    await central.config_handshake()

    node = MeshNode()
    transport = BLEDeviceTransport(central=central)
    async with AsyncMeshInterface(transport, node=node) as iface:
        pkt = await iface.send_text(message)
        print(f"Sent: {message!r} (id=0x{pkt.header.id:08x})")

    await central.disconnect()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ble_tether.py [scan|listen|send] [--address ADDR] [--message MSG]")
        sys.exit(1)

    action = sys.argv[1]
    address = ""
    message = ""

    for i, arg in enumerate(sys.argv):
        if arg == "--address" and i + 1 < len(sys.argv):
            address = sys.argv[i + 1]
        if arg == "--message" and i + 1 < len(sys.argv):
            message = sys.argv[i + 1]

    if action == "scan":
        asyncio.run(scan())
    elif action == "listen":
        if not address:
            print("Error: --address required")
            sys.exit(1)
        asyncio.run(listen(address))
    elif action == "send":
        if not address or not message:
            print("Error: --address and --message required")
            sys.exit(1)
        asyncio.run(send(address, message))
    else:
        print(f"Unknown action: {action}")
