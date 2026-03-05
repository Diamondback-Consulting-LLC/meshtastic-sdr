"""BLE device transport — wraps BLE Central as TransportBackend.

When tethered to a real Meshtastic device via BLE, the device handles
encryption, LoRa encoding, and RF — we just shuttle protobuf messages.
"""

from typing import Optional

from .base import TransportBackend
from ..ble.central import BLECentral
from ..ble.protobuf_codec import encode_toradio_packet, decode_fromradio
from ..protocol.mesh_packet import MeshPacket


class BLEDeviceTransport(TransportBackend):
    """TransportBackend that communicates via BLE to a real Meshtastic device."""

    def __init__(self, address: str = "", central: BLECentral | None = None):
        """Initialize BLE device transport.

        Args:
            address: BLE address of the target Meshtastic device.
            central: Optional pre-configured BLECentral (for testing).
        """
        self._address = address
        self._central = central or BLECentral()

    async def start(self) -> None:
        if not self._central.is_connected:
            await self._central.connect(self._address)
        await self._central.config_handshake()

    async def stop(self) -> None:
        await self._central.disconnect()

    async def send_packet(self, packet: MeshPacket) -> None:
        await self._central.send_packet(packet)

    async def receive_packet(self, timeout_s: float = 10.0) -> Optional[MeshPacket]:
        return await self._central.wait_for_packet(timeout_s=timeout_s)

    @property
    def central(self) -> BLECentral:
        return self._central
