"""BLE Central — connect to an existing Meshtastic device via BLE.

Uses bleak (async BLE client library) to connect to a real Meshtastic device
(T-Beam, Heltec, etc.) and communicate via the Meshtastic BLE GATT service.
"""

import asyncio
import struct
from typing import Optional, Callable

from .constants import SERVICE_UUID, TORADIO_UUID, FROMRADIO_UUID, FROMNUM_UUID
from .protobuf_codec import (
    encode_toradio_packet,
    encode_toradio_want_config,
    encode_toradio_disconnect,
    decode_fromradio,
    mesh_packet_to_protobuf,
)
from ..protocol.mesh_packet import MeshPacket

try:
    from bleak import BleakClient, BleakScanner
    HAS_BLEAK = True
except ImportError:
    HAS_BLEAK = False


class BLECentral:
    """BLE Central mode — connects to a Meshtastic device as a client."""

    def __init__(self, client=None):
        """Initialize BLE Central.

        Args:
            client: Optional BleakClient instance (for testing with mocks).
        """
        self._client = client
        self._data_event = asyncio.Event()
        self._connected = False
        self._fromradio_queue: list[bytes] = []
        self._on_packet: Optional[Callable[[MeshPacket], None]] = None

    @staticmethod
    async def scan(timeout: float = 5.0) -> list[dict]:
        """Scan for nearby Meshtastic BLE devices.

        Returns list of dicts with "name", "address", "rssi" keys.
        """
        if not HAS_BLEAK:
            raise RuntimeError("bleak is required for BLE scanning. Install with: pip install bleak")
        devices = await BleakScanner.discover(timeout=timeout)
        results = []
        for d in devices:
            uuids = [str(u) for u in (d.metadata.get("uuids", []))]
            if SERVICE_UUID in uuids:
                results.append({
                    "name": d.name or "Unknown",
                    "address": d.address,
                    "rssi": d.rssi,
                })
        return results

    async def connect(self, address: str) -> None:
        """Connect to a Meshtastic device by BLE address."""
        if self._client is None:
            if not HAS_BLEAK:
                raise RuntimeError("bleak is required. Install with: pip install bleak")
            self._client = BleakClient(address)
        await self._client.connect()
        self._connected = True
        await self._client.start_notify(FROMNUM_UUID, self._fromnum_handler)

    def _fromnum_handler(self, sender, data: bytearray) -> None:
        """Handle FromNum notifications (data available signal)."""
        self._data_event.set()

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._client and self._connected:
            await self._client.stop_notify(FROMNUM_UUID)
            await self._client.disconnect()
            self._connected = False

    async def config_handshake(self, config_id: int = 69420) -> list[dict]:
        """Perform the config handshake to retrieve device configuration.

        Sends want_config_id and reads all FromRadio responses until
        config_complete_id is received.

        Returns list of decoded FromRadio message dicts.
        """
        toradio_bytes = encode_toradio_want_config(config_id)
        await self._client.write_gatt_char(TORADIO_UUID, toradio_bytes, response=True)

        responses = []
        while True:
            data = await self._client.read_gatt_char(FROMRADIO_UUID)
            if not data or len(data) == 0:
                break
            decoded = decode_fromradio(bytes(data))
            responses.append(decoded)
            if "config_complete_id" in decoded:
                break

        return responses

    async def write_toradio(self, data: bytes) -> None:
        """Write raw bytes to the ToRadio characteristic."""
        await self._client.write_gatt_char(TORADIO_UUID, data, response=True)

    async def send_packet(self, packet: MeshPacket) -> None:
        """Send a MeshPacket to the device (wrapped in ToRadio)."""
        toradio_bytes = encode_toradio_packet(packet)
        await self.write_toradio(toradio_bytes)

    async def read_fromradio(self) -> Optional[dict]:
        """Read a single FromRadio message from the device.

        Returns decoded FromRadio dict, or None if no data.
        """
        data = await self._client.read_gatt_char(FROMRADIO_UUID)
        if not data or len(data) == 0:
            return None
        return decode_fromradio(bytes(data))

    async def wait_for_packet(self, timeout_s: float = 30.0) -> Optional[MeshPacket]:
        """Wait for a FromNum notification then read the packet.

        Returns MeshPacket if one is available, None on timeout.
        """
        self._data_event.clear()
        try:
            await asyncio.wait_for(self._data_event.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            return None

        result = await self.read_fromradio()
        if result and "packet" in result:
            return result["packet"]
        return None

    @property
    def is_connected(self) -> bool:
        return self._connected
