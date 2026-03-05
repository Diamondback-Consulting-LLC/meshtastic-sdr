"""Abstract transport backend interface (packet-level, async).

TransportBackend operates at the MeshPacket level, unlike RadioBackend
which operates on IQ samples. This allows both SDR (radio + LoRa + crypto)
and BLE (protobuf over GATT) backends to share the same interface.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..protocol.mesh_packet import MeshPacket


class TransportBackend(ABC):
    """Abstract base class for packet-level transport backends."""

    @abstractmethod
    async def send_packet(self, packet: MeshPacket) -> None:
        """Send a MeshPacket over this transport.

        Args:
            packet: The packet to send (with data populated, not yet encrypted
                    for SDR transport; already-encrypted for BLE device transport).
        """

    @abstractmethod
    async def receive_packet(self, timeout_s: float = 10.0) -> Optional[MeshPacket]:
        """Receive a MeshPacket from this transport.

        Args:
            timeout_s: Maximum time to wait in seconds.

        Returns:
            Decoded MeshPacket with data decrypted, or None if timeout.
        """

    @abstractmethod
    async def start(self) -> None:
        """Initialize and start the transport."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the transport and release resources."""

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()
