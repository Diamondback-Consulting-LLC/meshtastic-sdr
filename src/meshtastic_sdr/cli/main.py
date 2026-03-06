"""Meshtastic SDR CLI entry point."""

import argparse
import asyncio
import logging
import sys
import time

from ..radio.simulated import SimulatedRadio
from ..lora.params import PRESETS, DEFAULT_PRESET, get_preset
from ..protocol.channels import ChannelConfig, REGIONS, DEFAULT_REGION, get_default_frequency
from ..protocol.encryption import MeshtasticCrypto
from ..protocol.mesh_packet import MeshPacket
from ..mesh.node import MeshNode
from ..mesh.interface import MeshInterface
from ..config import (
    SDRConfig, NodeConfig, _UNSET, load_config, save_config, merge_cli_args,
    load_node_identity, save_node_identity, resolve_psk,
)


def create_radio(config: SDRConfig):
    """Create radio backend based on SDRConfig."""
    backend = config.radio.backend

    if backend == "simulated":
        return SimulatedRadio()
    elif backend == "soapy":
        try:
            from ..radio.soapy_radio import SoapyRadio
            return SoapyRadio(device_str=config.radio.device)
        except ImportError:
            print("SoapySDR not available. Install python3-soapysdr and a driver module.")
            print("  Ubuntu/Debian: sudo apt install python3-soapysdr soapysdr-module-bladerf")
            sys.exit(1)
        except RuntimeError as e:
            print(f"SoapySDR error: {e}")
            sys.exit(1)
    elif backend == "bladerf":
        try:
            from ..radio.bladerf_radio import BladeRFRadio
            return BladeRFRadio(
                device_str=config.radio.device,
                xb200=config.radio.xb200,
                xb200_filter=config.radio.xb200_filter,
            )
        except ImportError:
            print("BladeRF not available. Use --simulate for simulated mode.")
            sys.exit(1)
    else:
        print(f"Unknown radio backend: {backend!r}")
        print("Supported backends: bladerf, soapy, simulated")
        sys.exit(1)


def create_interface(config: SDRConfig) -> MeshInterface:
    """Create a MeshInterface from SDRConfig."""
    radio = create_radio(config)

    # Resolve node identity
    node_id = None
    if config.node.id:
        node_id_str = config.node.id
        if node_id_str.startswith("!"):
            node_id = int(node_id_str[1:], 16)
        else:
            node_id = int(node_id_str)
    else:
        node_id = load_node_identity()

    # Use radio device name as node name if user hasn't customized it
    long_name = config.node.long_name
    short_name = config.node.short_name
    if long_name == NodeConfig().long_name:
        long_name = radio.device_name
    if short_name == NodeConfig().short_name:
        short_name = radio.device_name[:4]

    node = MeshNode(
        node_id=node_id,
        long_name=long_name,
        short_name=short_name,
    )

    # Persist node ID if it was generated fresh
    if config.node.id is None:
        save_node_identity(node.node_id)

    # Build channel config
    psk = resolve_psk(config.channel.psk)
    channel = ChannelConfig(
        name=config.channel.name,
        psk=psk,
        index=config.channel.index,
    )

    interface = MeshInterface(
        radio=radio,
        preset_name=config.preset,
        region=config.region,
        node=node,
        channel=channel,
        tx_gain=config.radio.tx_gain,
        rx_gain=config.radio.rx_gain,
    )
    interface.configure_radio()
    return interface


def cmd_listen(config: SDRConfig):
    """Listen for and print all received messages."""
    interface = create_interface(config)

    print(f"Listening on {interface.frequency / 1e6:.3f} MHz "
          f"({interface.preset.name}, {interface.region})")
    print(f"Local node: {interface.node.node_id_str}")
    print("Press Ctrl+C to stop.\n")

    def on_packet(packet: MeshPacket):
        ts = time.strftime("%H:%M:%S")
        src = f"!{packet.header.from_node:08x}"
        if packet.data and packet.data.text:
            print(f"[{ts}] {src}: {packet.data.text}")
        elif packet.data:
            from ..protocol.portnums import describe_portnum
            port = describe_portnum(packet.data.portnum)
            print(f"[{ts}] {src}: [{port}] {len(packet.data.payload)}B")
        else:
            print(f"[{ts}] {src}: (encrypted, {len(packet.encrypted)}B)")

    interface.start_receive(on_packet)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        interface.close()


def cmd_send(config: SDRConfig, message: str):
    """Send a text message."""
    interface = create_interface(config)

    print(f"Sending on {interface.frequency / 1e6:.3f} MHz")
    print(f"From: {interface.node.node_id_str}")

    packet = interface.send_text(message)

    print(f"Sent: {message!r}")
    print(f"Packet ID: 0x{packet.header.id:08x}")

    interface.close()


def cmd_info(config: SDRConfig):
    """Show node and channel info."""
    interface = create_interface(config)

    print(f"Node ID:    {interface.node.node_id_str}")
    print(f"Long Name:  {interface.node.long_name}")
    print(f"Short Name: {interface.node.short_name}")
    print(f"Region:     {interface.region}")
    print(f"Preset:     {interface.preset.name}")
    print(f"  SF{interface.preset.spreading_factor} / "
          f"{interface.preset.bandwidth // 1000}kHz / "
          f"CR 4/{interface.preset.cr_denom}")
    print(f"Frequency:  {interface.frequency / 1e6:.3f} MHz")
    print(f"Channel:    {interface.channel.display_name} "
          f"(hash=0x{interface.channel.channel_hash:02x})")
    print(f"Encrypted:  {interface.channel.has_encryption()}")

    interface.close()


def cmd_scan(config: SDRConfig):
    """Scan frequencies for Meshtastic traffic."""
    radio = create_radio(config)

    preset = get_preset(config.preset)
    region_config = REGIONS[config.region]
    bw_khz = preset.bandwidth / 1000

    print(f"Scanning {config.region} region ({region_config.freq_start}-{region_config.freq_end} MHz)")
    print(f"Preset: {preset.name}, BW: {bw_khz:.0f} kHz")
    print()

    from ..lora.packet import LoRaPacket
    lora = LoRaPacket(preset, preset.bandwidth)

    # Scan through channels
    num_channels = min(region_config.num_channels, 50)  # Limit scan
    for ch_num in range(num_channels):
        freq = region_config.channel_frequency(ch_num, bw_khz)
        radio.configure(
            frequency=freq,
            sample_rate=preset.bandwidth,
            bandwidth=preset.bandwidth,
        )

        # Listen briefly on each channel
        listen_time = preset.preamble_duration_s() * 2
        num_samples = int(listen_time * preset.bandwidth)
        samples = radio.receive(num_samples)

        # Check for signal energy
        power = float((abs(samples) ** 2).mean()) if len(samples) > 0 else 0
        if power > 0.001:  # Threshold
            print(f"  Ch {ch_num:3d}: {freq / 1e6:.3f} MHz - signal detected (power={power:.4f})")

    print("\nScan complete.")
    radio.close()


def cmd_init(config: SDRConfig):
    """Interactive config setup wizard."""
    print("meshtastic-sdr configuration wizard\n")

    # Mode
    mode = input(f"Default mode [{config.mode}]: ").strip()
    if mode:
        config.mode = mode

    # Region
    region = input(f"Region [{config.region}]: ").strip()
    if region:
        config.region = region

    # Preset
    preset = input(f"Modem preset [{config.preset}]: ").strip()
    if preset:
        config.preset = preset

    # Node name
    name = input(f"Node name [{config.node.long_name}]: ").strip()
    if name:
        config.node.long_name = name

    short = input(f"Short name [{config.node.short_name}]: ").strip()
    if short:
        config.node.short_name = short[:4]

    # Radio backend
    backend = input(f"Radio backend [{config.radio.backend}]: ").strip()
    if backend:
        config.radio.backend = backend

    # Save
    default_path = "meshtastic-sdr.yaml"
    path = input(f"\nSave to [{default_path}]: ").strip() or default_path
    out = save_config(config, path)
    print(f"Config written to {out}")


def cmd_devices():
    """List available SDR devices."""
    print("Searching for SDR devices...\n")

    # SoapySDR devices
    soapy_found = False
    try:
        from ..radio.soapy_radio import SoapyRadio, HAS_SOAPY
        if HAS_SOAPY:
            devices = SoapyRadio.enumerate_devices()
            if devices:
                soapy_found = True
                print("SoapySDR devices:")
                for d in devices:
                    name = d.get("label", d["driver"])
                    serial = d.get("serial", "")
                    serial_str = f"  serial={serial}" if serial else ""
                    print(f"  {name:20s} driver={d['driver']}{serial_str}")
                    print(f"    config: backend=soapy, device=\"{d['device_str']}\"")
                print()
        else:
            print("SoapySDR: not installed (install python3-soapysdr for multi-SDR support)")
    except ImportError:
        print("SoapySDR: not installed")

    # BladeRF
    bladerf_found = False
    try:
        import bladerf._bladerf as _bladerf
        devs = _bladerf.get_device_list()
        if devs:
            bladerf_found = True
            print("BladeRF devices (native driver):")
            for d in devs:
                serial = getattr(d, "serial", "?")
                print(f"  BladeRF  serial={serial}")
            print()
    except (ImportError, Exception):
        pass

    if not soapy_found and not bladerf_found:
        print("No SDR devices found.")
        print("\nTo use without hardware: meshtastic-sdr --simulate listen")


def main():
    parser = argparse.ArgumentParser(
        prog="meshtastic-sdr",
        description="Meshtastic transceiver using SDR (BladeRF, HackRF, LimeSDR, etc.)",
    )

    # Global options
    parser.add_argument("--config", default=None,
                        help="Path to config YAML file")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v for INFO, -vv for DEBUG)")
    parser.add_argument("--simulate", action="store_true",
                        help="Use simulated radio (no hardware needed)")
    parser.add_argument("--region", default=_UNSET,
                        choices=list(REGIONS.keys()),
                        help="Radio region")
    parser.add_argument("--preset", default=_UNSET,
                        choices=list(PRESETS.keys()),
                        help="Modem preset")
    parser.add_argument("--name", default=_UNSET,
                        help="Node name")
    parser.add_argument("--device", default=_UNSET,
                        help="Device string (BladeRF ID or SoapySDR: driver=hackrf)")

    subparsers = parser.add_subparsers(dest="command")

    # listen command
    sub_listen = subparsers.add_parser("listen", help="Listen for messages")

    # send command
    sub_send = subparsers.add_parser("send", help="Send a text message")
    sub_send.add_argument("message", help="Message text to send")

    # info command
    sub_info = subparsers.add_parser("info", help="Show node info")

    # scan command
    sub_scan = subparsers.add_parser("scan", help="Scan for Meshtastic traffic")

    # init command
    sub_init = subparsers.add_parser("init", help="Interactive config setup wizard")

    # ble-tether command
    sub_ble_tether = subparsers.add_parser("ble-tether",
                                            help="Connect to a Meshtastic device via BLE")
    sub_ble_tether.add_argument("action", nargs="?", default="listen",
                                 choices=["listen", "send", "info", "scan"],
                                 help="Action to perform")
    sub_ble_tether.add_argument("--address", default="",
                                 help="BLE device address (XX:XX:XX:XX:XX:XX)")
    sub_ble_tether.add_argument("--message", default="",
                                 help="Message to send (for 'send' action)")

    # devices command
    sub_devices = subparsers.add_parser("devices",
                                         help="List available SDR devices")

    # ble-gateway command
    sub_ble_gateway = subparsers.add_parser("ble-gateway",
                                             help="Act as BLE gateway for phone connections")

    args = parser.parse_args()

    # Configure logging verbosity
    if args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
    elif args.verbose >= 1:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Load config and merge CLI overrides
    config = load_config(args.config)
    config = merge_cli_args(config, args)

    if args.command == "devices":
        cmd_devices()
        return
    elif args.command == "init":
        cmd_init(config)
    elif args.command == "listen":
        cmd_listen(config)
    elif args.command == "send":
        cmd_send(config, args.message)
    elif args.command == "info":
        cmd_info(config)
    elif args.command == "scan":
        cmd_scan(config)
    elif args.command == "ble-tether":
        cmd_ble_tether(config, args)
    elif args.command == "ble-gateway":
        cmd_ble_gateway(config)
    elif args.command is None:
        # No subcommand: dispatch to configured default mode
        mode = config.mode
        if mode == "ble-gateway":
            cmd_ble_gateway(config)
        elif mode == "ble-tether":
            cmd_ble_tether(config, args)
        elif mode == "listen":
            cmd_listen(config)
        elif mode == "send":
            print("Error: 'send' mode requires a message. Use: meshtastic-sdr send <message>")
            sys.exit(1)
        else:
            print(f"Unknown default mode: {mode}")
            parser.print_help()
    else:
        parser.print_help()


def cmd_ble_tether(config: SDRConfig, args):
    """Connect to a Meshtastic device via BLE and relay messages."""
    async def _run():
        from ..ble.central import BLECentral
        from ..transport.ble_device_transport import BLEDeviceTransport
        from ..mesh.interface import AsyncMeshInterface

        action = getattr(args, "action", "listen")
        address = getattr(args, "address", "") or config.ble.address

        if action == "scan":
            print("Scanning for Meshtastic BLE devices...")
            devices = await BLECentral.scan(timeout=5.0)
            if not devices:
                print("No Meshtastic devices found.")
                return
            for d in devices:
                print(f"  {d['name']:20s} {d['address']}  RSSI: {d['rssi']}")
            return

        if not address:
            print("Error: --address required for this action. Use 'scan' to find devices.")
            sys.exit(1)

        central = BLECentral()
        print(f"Connecting to {address}...")
        await central.connect(address)
        print("Connected. Running config handshake...")

        config_response = await central.config_handshake()
        for item in config_response:
            if "my_info" in item:
                node_num = item["my_info"]["my_node_num"]
                fw = item["my_info"].get("firmware_version", "?")
                print(f"Device node: !{node_num:08x}, firmware: {fw}")

        if action == "info":
            await central.disconnect()
            return

        if action == "send":
            message = getattr(args, "message", "")
            if not message:
                print("Error: --message required for 'send' action.")
                await central.disconnect()
                sys.exit(1)

            node = MeshNode()
            transport = BLEDeviceTransport(central=central)
            async with AsyncMeshInterface(transport, node=node) as iface:
                pkt = await iface.send_text(message)
                print(f"Sent: {message!r} (id=0x{pkt.header.id:08x})")
            return

        # Default: listen
        print("Listening for packets... (Ctrl+C to stop)")
        try:
            while True:
                packet = await central.wait_for_packet(timeout_s=5.0)
                if packet:
                    ts = time.strftime("%H:%M:%S")
                    src = f"!{packet.header.from_node:08x}"
                    if packet.data and packet.data.text:
                        print(f"[{ts}] {src}: {packet.data.text}")
                    elif packet.encrypted:
                        print(f"[{ts}] {src}: ({len(packet.encrypted)}B encrypted)")
                    else:
                        print(f"[{ts}] {src}: (empty packet)")
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await central.disconnect()
            print("Disconnected.")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


def cmd_ble_gateway(config: SDRConfig):
    """Start BLE gateway — advertise as Meshtastic device for phone connections."""
    async def _run():
        from ..ble.peripheral import BLEGateway
        from ..ble.pairing import register_pairing_agent
        from ..protocol.channels import ChannelConfig

        # Register BlueZ pairing agent for Android bonding support
        await register_pairing_agent()

        # Create the SDR interface for radio TX/RX
        interface = create_interface(config)

        def on_phone_packet(packet):
            if packet.header.id == 0:
                return  # Skip empty/malformed packets (e.g. heartbeat artifacts)
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] Phone TX: id=0x{packet.header.id:08x}")
            interface._transmit_packet(packet)

        gateway = BLEGateway(
            node=interface.node,
            channel=interface.channel,
            on_packet_from_phone=on_phone_packet,
            interface=interface,
            config=config,
        )

        # BLE name must match Meshtastic pattern: *_XXXX (last 4 hex of node ID)
        # Android app filters on regex: ^.*_([0-9a-fA-F]{4})$
        node_suffix = f"{interface.node.node_id & 0xFFFF:04x}"
        ble_name = config.ble.gateway_name
        if not ble_name or ble_name == "Meshtastic SDR":
            ble_name = f"Meshtastic_{node_suffix}"
        elif not ble_name.endswith(f"_{node_suffix}"):
            # Ensure custom names also match the pattern
            ble_name = f"{ble_name}_{node_suffix}"

        print(f"Starting BLE gateway as '{ble_name}'...")
        print(f"  Region: {config.region}, Preset: {config.preset}")
        print(f"  Frequency: {interface.frequency / 1e6:.3f} MHz")
        print(f"  Node ID: {interface.node.node_id_str}")
        await gateway.start(name=ble_name)
        print("BLE Gateway running. Waiting for phone connections...")
        print("Press Ctrl+C to stop.\n")

        # Also listen for radio packets and forward to phone
        def on_radio_packet(packet):
            ts = time.strftime("%H:%M:%S")
            src = f"!{packet.header.from_node:08x}"
            print(f"[{ts}] Radio RX from {src} -> forwarding to phone")
            gateway.queue_packet_for_phone(packet)

        interface.start_receive(on_radio_packet)

        # Start telemetry service
        from ..ble.telemetry import TelemetryService
        telemetry = TelemetryService(
            gateway=gateway,
            node_id=interface.node.node_id,
            device_interval=900,
            environment_interval=900,
        )
        telemetry.start()

        # Monitor connection state for console output
        was_connected = False
        try:
            while True:
                await asyncio.sleep(1)
                if gateway._phone_connected and not was_connected:
                    was_connected = True
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}] Phone connected")
                elif not gateway._phone_connected and was_connected:
                    was_connected = False
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}] Phone disconnected")
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            print("\nShutting down...")
            telemetry.stop()
            await gateway.stop()
            interface.close()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
