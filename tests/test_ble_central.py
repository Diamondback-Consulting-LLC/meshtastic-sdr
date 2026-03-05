"""Tests for BLE Central — mock BleakClient tests."""

import sys
import asyncio
import struct
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.ble.central import BLECentral
from meshtastic_sdr.ble.constants import TORADIO_UUID, FROMRADIO_UUID, FROMNUM_UUID
from meshtastic_sdr.ble.protobuf_codec import (
    encode_fromradio_packet,
    encode_fromradio_config_complete,
    encode_fromradio_my_info,
    encode_fromradio_node_info,
    decode_toradio,
    mesh_packet_to_protobuf,
)
from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.transport.ble_device_transport import BLEDeviceTransport


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class MockBleakClient:
    """Mock BLE client that simulates a Meshtastic device."""

    def __init__(self):
        self._connected = False
        self._notify_handlers = {}
        self._written_data = []
        self._read_queue = []  # list of bytes to return from reads
        self._fromnum_counter = 0

    async def connect(self):
        self._connected = True

    async def disconnect(self):
        self._connected = False

    async def start_notify(self, uuid, handler):
        self._notify_handlers[uuid] = handler

    async def stop_notify(self, uuid):
        self._notify_handlers.pop(uuid, None)

    async def write_gatt_char(self, uuid, data, response=False):
        self._written_data.append((uuid, bytes(data)))

        # If writing want_config_id, queue config responses
        decoded = decode_toradio(bytes(data))
        if "want_config_id" in decoded:
            config_id = decoded["want_config_id"]
            self._read_queue.extend([
                encode_fromradio_my_info(0xDE000001, msg_id=1),
                encode_fromradio_node_info(0xDE000001, "Device", "DEV", msg_id=2),
                encode_fromradio_config_complete(config_id, msg_id=3),
            ])

    async def read_gatt_char(self, uuid):
        if self._read_queue:
            return self._read_queue.pop(0)
        return b""

    def trigger_fromnum(self):
        """Simulate a FromNum notification."""
        self._fromnum_counter += 1
        handler = self._notify_handlers.get(FROMNUM_UUID)
        if handler:
            data = struct.pack("<I", self._fromnum_counter)
            handler(None, bytearray(data))


class TestBLECentral:
    def test_connect_disconnect(self):
        """Connect and disconnect via mock client."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)

            assert not central.is_connected
            await central.connect("00:11:22:33:44:55")
            assert central.is_connected
            assert FROMNUM_UUID in mock._notify_handlers

            await central.disconnect()
            assert not central.is_connected

        run_async(_test())

    def test_config_handshake(self):
        """Config handshake returns my_info, node_info, config_complete."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)
            await central.connect("00:11:22:33:44:55")

            responses = await central.config_handshake(config_id=69420)

            assert len(responses) == 3
            assert "my_info" in responses[0]
            assert "node_info" in responses[1]
            assert "config_complete_id" in responses[2]
            assert responses[2]["config_complete_id"] == 69420

        run_async(_test())

    def test_send_packet(self):
        """Sending a packet writes ToRadio to the correct characteristic."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)
            await central.connect("00:11:22:33:44:55")

            packet = MeshPacket.create_text(
                text="BLE test",
                from_node=0xAABBCCDD,
            )
            await central.send_packet(packet)

            assert len(mock._written_data) == 1
            uuid, data = mock._written_data[0]
            assert uuid == TORADIO_UUID

            decoded = decode_toradio(data)
            assert "packet" in decoded
            assert decoded["packet"].header.from_node == 0xAABBCCDD

        run_async(_test())

    def test_wait_for_packet(self):
        """wait_for_packet returns packet after FromNum notification."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)
            await central.connect("00:11:22:33:44:55")

            # Queue a packet for the device to "send"
            header = MeshtasticHeader(
                from_node=0xDE000001,
                to=BROADCAST_ADDR,
                id=0x12345678,
            )
            pkt = MeshPacket(header=header, encrypted=b"\xAA\xBB")
            mock._read_queue.append(encode_fromradio_packet(pkt, msg_id=10))

            # Trigger notification in a separate task
            async def trigger():
                await asyncio.sleep(0.05)
                mock.trigger_fromnum()

            asyncio.ensure_future(trigger())
            received = await central.wait_for_packet(timeout_s=1.0)

            assert received is not None
            assert received.header.from_node == 0xDE000001
            assert received.encrypted == b"\xAA\xBB"

        run_async(_test())

    def test_wait_for_packet_timeout(self):
        """wait_for_packet returns None on timeout."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)
            await central.connect("00:11:22:33:44:55")

            result = await central.wait_for_packet(timeout_s=0.1)
            assert result is None

        run_async(_test())


class TestBLEDeviceTransport:
    def test_start_does_handshake(self):
        """Starting the transport connects and does config handshake."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)
            transport = BLEDeviceTransport(central=central)

            await central.connect("00:11:22:33:44:55")
            await transport.start()

            # Handshake should have written want_config_id
            assert len(mock._written_data) == 1
            decoded = decode_toradio(mock._written_data[0][1])
            assert "want_config_id" in decoded

            await transport.stop()

        run_async(_test())

    def test_send_receive(self):
        """Send and receive via BLE device transport."""
        async def _test():
            mock = MockBleakClient()
            central = BLECentral(client=mock)
            transport = BLEDeviceTransport(central=central)

            await central.connect("00:11:22:33:44:55")

            # Send a packet
            packet = MeshPacket.create_text(text="via BLE", from_node=0x11111111)
            await transport.send_packet(packet)

            # Verify it was written
            toradio_writes = [d for u, d in mock._written_data if u == TORADIO_UUID]
            assert len(toradio_writes) >= 1

            await transport.stop()

        run_async(_test())
