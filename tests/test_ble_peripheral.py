"""Tests for BLE Peripheral (Gateway) — mock BlessServer tests."""

import sys
import asyncio
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.ble.peripheral import BLEGateway
from meshtastic_sdr.ble.constants import SERVICE_UUID, TORADIO_UUID, FROMRADIO_UUID, FROMNUM_UUID
from meshtastic_sdr.ble.protobuf_codec import (
    encode_toradio_packet,
    encode_toradio_want_config,
    decode_fromradio,
)
from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.protocol.channels import ChannelConfig


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class MockCharacteristic:
    """Mock GATT characteristic."""
    def __init__(self, uuid):
        self.uuid = uuid


class MockBlessServer:
    """Mock BLE GATT server."""

    def __init__(self, name="Test"):
        self.name = name
        self.services = {}
        self.characteristics = {}
        self.write_request_func = None
        self.read_request_func = None
        self._started = False
        self._values = {}

    async def add_new_service(self, uuid):
        self.services[uuid] = {}

    async def add_new_characteristic(self, service_uuid, char_uuid, props, value, perms):
        self.characteristics[char_uuid] = {
            "service": service_uuid,
            "props": props,
            "value": value,
            "perms": perms,
        }

    async def start(self):
        self._started = True

    async def stop(self):
        self._started = False

    def update_value(self, service_uuid, char_uuid):
        pass

    def simulate_write(self, char_uuid, data):
        """Simulate a phone writing to a characteristic."""
        if self.write_request_func:
            char = MockCharacteristic(char_uuid)
            self.write_request_func(char, bytearray(data))

    def simulate_read(self, char_uuid):
        """Simulate a phone reading from a characteristic."""
        if self.read_request_func:
            char = MockCharacteristic(char_uuid)
            return bytes(self.read_request_func(char))
        return b""


class TestBLEGateway:
    def test_start_stop(self):
        """Gateway starts and stops cleanly."""
        async def _test():
            node = MeshNode(node_id=0xAAAAAAAA, long_name="Gateway")
            mock_server = MockBlessServer()
            gateway = BLEGateway(node, server=mock_server)

            await gateway.start(name="Test GW")
            assert gateway.is_running
            assert mock_server._started

            await gateway.stop()
            assert not gateway.is_running
            assert not mock_server._started

        run_async(_test())

    def test_config_handshake_via_write(self):
        """Phone writes want_config_id → gateway queues config responses (stage 1)."""
        async def _test():
            node = MeshNode(node_id=0xBBBBBBBB, long_name="SDR GW", short_name="GW")
            mock_server = MockBlessServer()
            gateway = BLEGateway(node, server=mock_server)
            await gateway.start()

            # Phone sends want_config_id (stage 1: config only)
            toradio = encode_toradio_want_config(69420)
            mock_server.simulate_write(TORADIO_UUID, toradio)

            # Stage 1: my_info + metadata + 10 configs + 15 modules + 8 channels + complete = 36
            assert gateway.queue_size == 36

            # Read them back
            responses = []
            while gateway.queue_size > 0:
                data = mock_server.simulate_read(FROMRADIO_UUID)
                if data:
                    responses.append(decode_fromradio(data))

            assert "my_info" in responses[0]
            assert responses[0]["my_info"]["my_node_num"] == 0xBBBBBBBB
            assert "config_complete_id" in responses[-1]
            assert responses[-1]["config_complete_id"] == 69420

        run_async(_test())

    def test_packet_from_phone_callback(self):
        """Phone sends a MeshPacket → on_packet_from_phone callback fires."""
        received_packets = []

        async def _test():
            node = MeshNode(node_id=0xCCCCCCCC)
            mock_server = MockBlessServer()
            gateway = BLEGateway(
                node,
                server=mock_server,
                on_packet_from_phone=lambda pkt: received_packets.append(pkt),
            )
            await gateway.start()

            # Phone sends a text message
            pkt = MeshPacket.create_text(
                text="From phone",
                from_node=0xCCCCCCCC,
            )
            toradio = encode_toradio_packet(pkt)
            mock_server.simulate_write(TORADIO_UUID, toradio)

            assert len(received_packets) == 1
            assert received_packets[0].header.from_node == 0xCCCCCCCC

            await gateway.stop()

        run_async(_test())

    def test_queue_packet_for_phone(self):
        """SDR receives a packet → queued for phone to read via FromRadio."""
        async def _test():
            node = MeshNode(node_id=0xDDDDDDDD)
            mock_server = MockBlessServer()
            gateway = BLEGateway(node, server=mock_server)
            await gateway.start()

            # Simulate receiving a packet from the air
            header = MeshtasticHeader(
                from_node=0xEEEEEEEE,
                to=BROADCAST_ADDR,
                id=0x99887766,
            )
            air_pkt = MeshPacket(header=header, encrypted=b"\x01\x02\x03")
            gateway.queue_packet_for_phone(air_pkt, msg_id=5)

            assert gateway.queue_size == 1

            # Phone reads it
            data = mock_server.simulate_read(FROMRADIO_UUID)
            decoded = decode_fromradio(data)
            assert decoded["id"] == 5
            assert "packet" in decoded
            assert decoded["packet"].header.from_node == 0xEEEEEEEE

            assert gateway.queue_size == 0

            await gateway.stop()

        run_async(_test())

    def test_empty_read_returns_empty(self):
        """Reading FromRadio with nothing queued returns empty bytes."""
        async def _test():
            node = MeshNode(node_id=0x11111111)
            mock_server = MockBlessServer()
            gateway = BLEGateway(node, server=mock_server)
            await gateway.start()

            data = mock_server.simulate_read(FROMRADIO_UUID)
            assert data == b""

            await gateway.stop()

        run_async(_test())
