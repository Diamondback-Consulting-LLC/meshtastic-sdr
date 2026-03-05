"""Tests for SDRTransport — verify it works identically to direct MeshInterface."""

import sys
import asyncio
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.radio.simulated import SimulatedRadio
from meshtastic_sdr.transport.sdr_transport import SDRTransport
from meshtastic_sdr.mesh.interface import AsyncMeshInterface
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.protocol.mesh_packet import MeshPacket
from meshtastic_sdr.protocol.header import BROADCAST_ADDR
from meshtastic_sdr.protocol.channels import ChannelConfig


def run_async(coro):
    """Helper to run async tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestSDRTransport:
    def test_send_receive_roundtrip(self):
        """Send a text message via SDRTransport and receive it back."""
        async def _test():
            radio = SimulatedRadio()
            tx_node = MeshNode(node_id=0xAAAAAAAA, long_name="TX Node")
            rx_node = MeshNode(node_id=0xBBBBBBBB, long_name="RX Node")

            tx_transport = SDRTransport(radio, preset_name="SHORT_FAST", node=tx_node)
            rx_transport = SDRTransport(radio, preset_name="SHORT_FAST", node=rx_node)

            await tx_transport.start()

            packet = MeshPacket.create_text(
                text="Hello SDRTransport!",
                from_node=tx_node.node_id,
                channel=tx_transport.channel.channel_hash,
            )
            await tx_transport.send_packet(packet)

            received = await rx_transport.receive_packet(timeout_s=5.0)
            assert received is not None
            assert received.data is not None
            assert received.data.text == "Hello SDRTransport!"
            assert received.header.from_node == tx_node.node_id

            await tx_transport.stop()
            await rx_transport.stop()

        run_async(_test())

    def test_async_mesh_interface_roundtrip(self):
        """AsyncMeshInterface with SDRTransport: send_text and receive."""
        async def _test():
            radio = SimulatedRadio()
            tx_node = MeshNode(node_id=0x11111111)
            rx_node = MeshNode(node_id=0x22222222)

            tx_transport = SDRTransport(radio, preset_name="SHORT_FAST", node=tx_node)
            rx_transport = SDRTransport(radio, preset_name="SHORT_FAST", node=rx_node)

            async with AsyncMeshInterface(tx_transport, node=tx_node) as tx_iface:
                sent = await tx_iface.send_text("Async hello!")

                async with AsyncMeshInterface(rx_transport, node=rx_node) as rx_iface:
                    received = await rx_iface.receive_once(timeout_s=5.0)
                    assert received is not None
                    assert received.data.text == "Async hello!"

        run_async(_test())

    def test_no_packet_returns_none(self):
        """receive_packet returns None when no data is available."""
        async def _test():
            radio = SimulatedRadio()
            transport = SDRTransport(radio, preset_name="SHORT_FAST")
            await transport.start()

            result = await transport.receive_packet(timeout_s=0.1)
            assert result is None

            await transport.stop()

        run_async(_test())

    def test_transport_context_manager(self):
        """TransportBackend async context manager works."""
        async def _test():
            radio = SimulatedRadio()
            transport = SDRTransport(radio, preset_name="SHORT_FAST")

            async with transport:
                packet = MeshPacket.create_text(
                    text="Context manager test",
                    from_node=0xDEADBEEF,
                )
                await transport.send_packet(packet)

        run_async(_test())
