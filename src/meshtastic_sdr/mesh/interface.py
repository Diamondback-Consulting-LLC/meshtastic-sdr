"""High-level Meshtastic mesh interface.

Provides send_text() / receive() API that ties together all layers:
radio backend, LoRa PHY, Meshtastic protocol, and mesh routing.

Includes both sync MeshInterface (for RadioBackend) and async
AsyncMeshInterface (for TransportBackend).
"""

import asyncio
import struct
import os
import threading
import time
from typing import Callable, Optional

from ..radio.base import RadioBackend
from ..transport.base import TransportBackend
from ..lora.params import ModemPreset, get_preset, DEFAULT_PRESET
from ..lora.packet import LoRaPacket
from ..protocol.header import MeshtasticHeader, BROADCAST_ADDR
from ..protocol.encryption import MeshtasticCrypto
from ..protocol.channels import ChannelConfig, get_default_frequency, DEFAULT_REGION
from ..protocol.mesh_packet import MeshPacket, DataPayload
from ..protocol.portnums import PortNum
from .node import MeshNode
from .router import MeshRouter


class MeshInterface:
    """High-level interface for sending and receiving Meshtastic messages."""

    def __init__(self, radio: RadioBackend, preset_name: str = DEFAULT_PRESET,
                 region: str = DEFAULT_REGION, node: MeshNode | None = None,
                 channel: ChannelConfig | None = None,
                 tx_gain: int = 30, rx_gain: int = 30):
        self.radio = radio
        self.preset = get_preset(preset_name)
        self.region = region
        self.node = node or MeshNode()
        self.channel = channel or ChannelConfig.default()
        self.crypto = MeshtasticCrypto(self.channel.psk)
        self.router = MeshRouter(self.node.node_id)
        self.tx_gain = tx_gain
        self.rx_gain = rx_gain

        # LoRa PHY
        self.sample_rate = self.preset.bandwidth  # Nyquist rate for sim
        self.lora = LoRaPacket(self.preset, self.sample_rate)

        # Frequency
        self.frequency = get_default_frequency(region, self.preset.bandwidth / 1000)

        # RX callback
        self._rx_callback: Callable[[MeshPacket], None] | None = None
        self._rx_thread: threading.Thread | None = None
        self._running = False

    def configure_radio(self) -> None:
        """Configure the radio backend with current settings."""
        self.radio.configure(
            frequency=self.frequency,
            sample_rate=self.sample_rate,
            bandwidth=self.preset.bandwidth,
            tx_gain=self.tx_gain,
            rx_gain=self.rx_gain,
        )

    def send_text(self, text: str, to: int = BROADCAST_ADDR,
                  want_ack: bool = False) -> MeshPacket:
        """Send a text message.

        Args:
            text: Message text (UTF-8)
            to: Destination node ID (default: broadcast)
            want_ack: Request acknowledgment

        Returns:
            The sent MeshPacket
        """
        packet = MeshPacket.create_text(
            text=text,
            from_node=self.node.node_id,
            to=to,
            channel=self.channel.channel_hash,
            hop_limit=self.router.default_hop_limit,
        )
        packet.header.want_ack = want_ack
        packet.header.hop_start = self.router.default_hop_limit

        return self._transmit_packet(packet)

    def send_data(self, payload: bytes, portnum: int,
                  to: int = BROADCAST_ADDR) -> MeshPacket:
        """Send arbitrary data with a specific port number."""
        data = DataPayload(portnum=portnum, payload=payload)
        pkt_id = struct.unpack("<I", os.urandom(4))[0]

        header = MeshtasticHeader(
            to=to,
            from_node=self.node.node_id,
            id=pkt_id,
            hop_limit=self.router.default_hop_limit,
            hop_start=self.router.default_hop_limit,
            channel=self.channel.channel_hash,
        )

        packet = MeshPacket(header=header, data=data)
        return self._transmit_packet(packet)

    def _transmit_packet(self, packet: MeshPacket) -> MeshPacket:
        """Encrypt, encode, modulate, and transmit a packet."""
        # Encrypt the data payload
        ota_bytes = packet.encrypt_payload(self.crypto)

        # LoRa encode + modulate
        iq_samples = self.lora.build(ota_bytes)

        # Transmit
        self.radio.transmit(iq_samples)

        # Record our own packet
        self.router.record_packet(packet.header)

        return packet

    def receive_once(self, timeout_s: float = 10.0) -> MeshPacket | None:
        """Try to receive a single packet.

        Args:
            timeout_s: Maximum time to wait in seconds

        Returns:
            Decoded MeshPacket, or None if timeout
        """
        # Calculate samples needed for one maximum-length packet
        max_airtime = self.preset.airtime_s(237)  # max payload
        preamble_time = self.preset.preamble_duration_s()
        total_time = max(timeout_s, max_airtime + preamble_time)
        num_samples = int(total_time * self.sample_rate)

        samples = self.radio.receive(num_samples)
        if len(samples) == 0:
            return None

        # Try to demodulate
        try:
            ota_bytes = self.lora.parse(samples)
        except ValueError:
            return None

        if ota_bytes is None or len(ota_bytes) < 16:
            return None

        # Parse the packet
        try:
            packet = MeshPacket.from_bytes(ota_bytes)
        except ValueError:
            return None

        # Route the packet
        for_us, should_rebroadcast = self.router.process_incoming(packet)

        if not for_us:
            # Rebroadcast if needed
            if should_rebroadcast:
                rebroad = self.router.prepare_rebroadcast(packet)
                iq = self.lora.build(rebroad.to_bytes())
                self.radio.transmit(iq)
            return None

        # Decrypt
        try:
            packet.decrypt_payload(self.crypto)
        except (ValueError, struct.error):
            return None

        # Update node DB
        self.node.update_node(packet.header.from_node)

        return packet

    def start_receive(self, callback: Callable[[MeshPacket], None]) -> None:
        """Start continuous receive with callback.

        Args:
            callback: Called for each received packet addressed to us
        """
        self._rx_callback = callback
        self._running = True
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    def stop_receive(self) -> None:
        """Stop the continuous receive loop."""
        self._running = False
        if self._rx_thread:
            self._rx_thread.join(timeout=5)
            self._rx_thread = None

    def _rx_loop(self) -> None:
        """Continuous receive loop (runs in background thread)."""
        while self._running:
            try:
                packet = self.receive_once(timeout_s=1.0)
                if packet and self._rx_callback:
                    self._rx_callback(packet)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error("RX loop error: %s", e)
                if not self._running:
                    break

    def close(self) -> None:
        """Shut down the interface."""
        self.stop_receive()
        self.radio.close()

    def __enter__(self):
        self.configure_radio()
        return self

    def __exit__(self, *args):
        self.close()


class AsyncMeshInterface:
    """Async interface for sending and receiving Meshtastic messages via TransportBackend."""

    def __init__(self, transport: TransportBackend, node: MeshNode | None = None,
                 channel: ChannelConfig | None = None):
        self.transport = transport
        self.node = node or MeshNode()
        self.channel = channel or ChannelConfig.default()
        self.router = MeshRouter(self.node.node_id)
        self._rx_task: asyncio.Task | None = None
        self._rx_callback: Callable[[MeshPacket], None] | None = None
        self._running = False

    async def send_text(self, text: str, to: int = BROADCAST_ADDR,
                        want_ack: bool = False) -> MeshPacket:
        """Send a text message via the transport backend."""
        packet = MeshPacket.create_text(
            text=text,
            from_node=self.node.node_id,
            to=to,
            channel=self.channel.channel_hash,
            hop_limit=self.router.default_hop_limit,
        )
        packet.header.want_ack = want_ack
        packet.header.hop_start = self.router.default_hop_limit

        await self.transport.send_packet(packet)
        self.router.record_packet(packet.header)
        return packet

    async def send_data(self, payload: bytes, portnum: int,
                        to: int = BROADCAST_ADDR) -> MeshPacket:
        """Send arbitrary data with a specific port number."""
        data = DataPayload(portnum=portnum, payload=payload)
        pkt_id = struct.unpack("<I", os.urandom(4))[0]

        header = MeshtasticHeader(
            to=to,
            from_node=self.node.node_id,
            id=pkt_id,
            hop_limit=self.router.default_hop_limit,
            hop_start=self.router.default_hop_limit,
            channel=self.channel.channel_hash,
        )

        packet = MeshPacket(header=header, data=data)
        await self.transport.send_packet(packet)
        self.router.record_packet(packet.header)
        return packet

    async def receive_once(self, timeout_s: float = 10.0) -> MeshPacket | None:
        """Try to receive a single packet from the transport."""
        return await self.transport.receive_packet(timeout_s=timeout_s)

    async def start_receive(self, callback: Callable[[MeshPacket], None]) -> None:
        """Start continuous receive with callback."""
        self._rx_callback = callback
        self._running = True
        self._rx_task = asyncio.create_task(self._rx_loop())

    async def stop_receive(self) -> None:
        """Stop the continuous receive loop."""
        self._running = False
        if self._rx_task:
            self._rx_task.cancel()
            try:
                await self._rx_task
            except asyncio.CancelledError:
                pass
            self._rx_task = None

    async def _rx_loop(self) -> None:
        """Continuous receive loop (runs as async task)."""
        while self._running:
            packet = await self.receive_once(timeout_s=1.0)
            if packet and self._rx_callback:
                self._rx_callback(packet)

    async def close(self) -> None:
        """Shut down the interface."""
        await self.stop_receive()
        await self.transport.stop()

    async def __aenter__(self):
        await self.transport.start()
        return self

    async def __aexit__(self, *args):
        await self.close()
