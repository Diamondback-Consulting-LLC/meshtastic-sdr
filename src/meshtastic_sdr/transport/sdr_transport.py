"""SDR transport backend — wraps RadioBackend + LoRa PHY + crypto as TransportBackend.

Bridges the IQ-sample-level RadioBackend to the packet-level TransportBackend
by running encryption, LoRa encoding/decoding, and modulation/demodulation.
"""

import asyncio
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .base import TransportBackend
from ..radio.base import RadioBackend
from ..lora.params import ModemPreset, get_preset, DEFAULT_PRESET
from ..lora.packet import LoRaPacket
from ..protocol.encryption import MeshtasticCrypto
from ..protocol.channels import ChannelConfig, get_default_frequency, DEFAULT_REGION
from ..protocol.header import HEADER_SIZE
from ..protocol.mesh_packet import MeshPacket
from ..mesh.node import MeshNode
from ..mesh.router import MeshRouter


class SDRTransport(TransportBackend):
    """TransportBackend that uses SDR radio + LoRa PHY + Meshtastic crypto."""

    def __init__(self, radio: RadioBackend, preset_name: str = DEFAULT_PRESET,
                 region: str = DEFAULT_REGION, node: MeshNode | None = None,
                 channel: ChannelConfig | None = None):
        self.radio = radio
        self.preset = get_preset(preset_name)
        self.region = region
        self.node = node or MeshNode()
        self.channel = channel or ChannelConfig.default()
        self.crypto = MeshtasticCrypto(self.channel.psk)
        self.router = MeshRouter(self.node.node_id)

        self.sample_rate = self.preset.bandwidth
        self.lora = LoRaPacket(self.preset, self.sample_rate)
        self.frequency = get_default_frequency(region, self.preset.bandwidth / 1000)

        self._executor = ThreadPoolExecutor(max_workers=2)

    async def start(self) -> None:
        self.radio.configure(
            frequency=self.frequency,
            sample_rate=self.sample_rate,
            bandwidth=self.preset.bandwidth,
        )

    async def stop(self) -> None:
        self.radio.close()
        self._executor.shutdown(wait=False)

    async def send_packet(self, packet: MeshPacket) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._send_sync, packet)

    def _send_sync(self, packet: MeshPacket) -> None:
        ota_bytes = packet.encrypt_payload(self.crypto)
        iq_samples = self.lora.build(ota_bytes)
        self.radio.transmit(iq_samples)
        self.router.record_packet(packet.header)

    async def receive_packet(self, timeout_s: float = 10.0) -> Optional[MeshPacket]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, self._receive_sync, timeout_s
        )

    def _receive_sync(self, timeout_s: float) -> Optional[MeshPacket]:
        max_airtime = self.preset.airtime_s(237)
        preamble_time = self.preset.preamble_duration_s()
        total_time = max(timeout_s, max_airtime + preamble_time)
        num_samples = int(total_time * self.sample_rate)

        samples = self.radio.receive(num_samples)
        if len(samples) == 0:
            return None

        try:
            ota_bytes = self.lora.parse(samples)
        except ValueError:
            return None

        if ota_bytes is None or len(ota_bytes) < HEADER_SIZE:
            return None

        try:
            packet = MeshPacket.from_bytes(ota_bytes)
        except ValueError:
            return None

        # Check channel hash matches before attempting decrypt
        if packet.header.channel != self.channel.channel_hash:
            return None

        for_us, should_rebroadcast = self.router.process_incoming(packet)

        if not for_us:
            if should_rebroadcast:
                rebroad = self.router.prepare_rebroadcast(packet)
                iq = self.lora.build(rebroad.to_bytes())
                self.radio.transmit(iq)
            return None

        try:
            packet.decrypt_payload(self.crypto)
        except (ValueError, struct.error):
            return None

        self.node.update_node(packet.header.from_node)
        return packet
