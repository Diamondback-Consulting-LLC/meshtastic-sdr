"""BLE Peripheral — GATT server for phone connections (Gateway mode).

Our SDR acts as a Meshtastic device. A phone running the Meshtastic app
connects to us via BLE, sends ToRadio protobufs, and we transmit over
the air via the SDR.
"""

import asyncio
import struct
import logging
from typing import Optional, Callable

from .constants import SERVICE_UUID, TORADIO_UUID, FROMRADIO_UUID, FROMNUM_UUID, LOGRADIO_UUID
from .config_state import ConfigState
from .admin_handler import AdminHandler
from .protobuf_codec import (
    decode_toradio,
    encode_fromradio_packet,
    encode_fromradio_queue_status,
)
from ..protocol.mesh_packet import MeshPacket
from ..protocol.portnums import PortNum
from ..mesh.node import MeshNode
from ..protocol.channels import ChannelConfig

try:
    from bless import BlessServer, BlessGATTCharacteristic, GATTCharacteristicProperties, GATTAttributePermissions
    HAS_BLESS = True
except ImportError:
    HAS_BLESS = False

logger = logging.getLogger(__name__)


class BLEGateway:
    """BLE Peripheral/Gateway — advertises as a Meshtastic device for phone connections."""

    def __init__(self, node: MeshNode, channel: ChannelConfig | None = None,
                 on_packet_from_phone: Optional[Callable[[MeshPacket], None]] = None,
                 server: Optional[object] = None,
                 interface=None, config=None):
        """Initialize BLE Gateway.

        Args:
            node: Local mesh node identity.
            channel: Channel configuration.
            on_packet_from_phone: Callback when phone sends a MeshPacket via ToRadio.
            server: Optional pre-configured BlessServer (for testing with mocks).
            interface: MeshInterface for reconfiguring the SDR radio.
            config: SDRConfig for reading/persisting configuration.
        """
        self.node = node
        self.channel = channel or ChannelConfig.default()
        self.config_state = ConfigState(node, channel, config=config)
        self.interface = interface
        self.config = config
        self.admin_handler = AdminHandler(self)
        self._on_packet_from_phone = on_packet_from_phone
        self._server = server
        self._fromradio_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._fromnum_counter = 0
        self._active_config_id: int | None = None
        self._running = False
        self._phone_connected = False
        self._connection_monitor_task = None

    async def start(self, name: str = "Meshtastic SDR") -> None:
        """Start the BLE GATT server and begin advertising."""
        if self._server is None:
            if not HAS_BLESS:
                raise RuntimeError("bless is required for BLE gateway. Install with: pip install bless")
            self._server = BlessServer(name=name)

        await self._setup_gatt()
        await self._server.start()
        self._running = True
        self._connection_monitor_task = asyncio.ensure_future(self._monitor_connection())
        logger.info("BLE Gateway started, advertising as '%s'", name)

    async def _setup_gatt(self) -> None:
        """Configure the GATT service and characteristics."""
        if HAS_BLESS:
            await self._server.add_new_service(SERVICE_UUID)

            # ToRadio: Write with Response
            await self._server.add_new_characteristic(
                SERVICE_UUID, TORADIO_UUID,
                GATTCharacteristicProperties.write,
                None,
                GATTAttributePermissions.writeable,
            )

            # FromRadio: Read
            await self._server.add_new_characteristic(
                SERVICE_UUID, FROMRADIO_UUID,
                GATTCharacteristicProperties.read,
                None,
                GATTAttributePermissions.readable,
            )

            # FromNum: Notify
            await self._server.add_new_characteristic(
                SERVICE_UUID, FROMNUM_UUID,
                GATTCharacteristicProperties.notify,
                None,
                GATTAttributePermissions.readable,
            )

            # LogRadio: Notify (required by Android app for service discovery)
            await self._server.add_new_characteristic(
                SERVICE_UUID, LOGRADIO_UUID,
                GATTCharacteristicProperties.notify,
                None,
                GATTAttributePermissions.readable,
            )
        elif hasattr(self._server, 'add_new_service'):
            # Mock server with same interface
            await self._server.add_new_service(SERVICE_UUID)

        self._server.write_request_func = self._handle_write
        self._server.read_request_func = self._handle_read

    def _handle_write(self, characteristic: object, value: bytearray, **kwargs) -> None:
        """Handle ToRadio write from phone."""
        char_uuid = str(getattr(characteristic, "uuid", ""))
        if TORADIO_UUID.lower() not in char_uuid.lower():
            return

        raw = bytes(value)
        try:
            parsed = decode_toradio(raw)
        except Exception:
            logger.warning("Failed to decode ToRadio message: %s", raw.hex())
            return

        if not parsed:
            logger.debug("Empty/unrecognized ToRadio: %s", raw.hex())
            return

        if "want_config_id" in parsed:
            config_id = parsed["want_config_id"]
            if config_id == self._active_config_id and not self._fromradio_queue.empty():
                # Phone is retrying the same config_id — responses already queued,
                # let it keep reading instead of resetting progress.
                logger.debug("Ignoring duplicate want_config_id=%d (%d responses still queued)",
                             config_id, self._fromradio_queue.qsize())
                return
            # New config_id (or queue drained) — generate fresh responses
            while not self._fromradio_queue.empty():
                try:
                    self._fromradio_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            self._active_config_id = config_id
            logger.info("Phone requested config (id=%d)", config_id)
            responses = self.config_state.generate_config_response(config_id)
            for resp in responses:
                self._fromradio_queue.put_nowait(resp)
            logger.info("Queued %d config responses", len(responses))
            self._advance_fromradio()
            self._bump_fromnum()
        elif "heartbeat" in parsed:
            logger.debug("Heartbeat received from phone")
        elif "packet" in parsed:
            packet = parsed["packet"]
            if packet.header.id == 0 and not packet.data:
                logger.debug("Ignoring empty packet (likely heartbeat artifact): %s", raw.hex())
                return
            logger.info("Phone sent packet id=0x%08x", packet.header.id)

            # Check if this is an AdminMessage addressed to us
            if (packet.data and packet.data.portnum == PortNum.ADMIN_APP
                    and (packet.header.to == self.node.node_id
                         or packet.header.to == 0xFFFFFFFF)):
                admin_responses = self.admin_handler.handle_admin_packet(packet)
                for resp in admin_responses:
                    self._fromradio_queue.put_nowait(resp)
                if admin_responses:
                    self._advance_fromradio()
                    self._bump_fromnum()
            else:
                if self._on_packet_from_phone:
                    self._on_packet_from_phone(packet)

            # Send QueueStatus after every packet from phone (Android expects this)
            qs = encode_fromradio_queue_status(
                free=max(0, 16 - self._fromradio_queue.qsize()),
                max_to_send=16,
                mesh_packet_id=packet.header.id,
            )
            self._fromradio_queue.put_nowait(qs)
            self._advance_fromradio()
            self._bump_fromnum()
        elif "disconnect" in parsed:
            logger.info("Phone requested disconnect")

    def _handle_read(self, characteristic: object, **kwargs) -> bytearray:
        """Handle FromRadio read from phone.

        The characteristic.value was pre-loaded with the current message by
        _advance_fromradio(). After the phone reads it, advance to the next
        message so it's ready for the next read.

        This handles both bless behaviors:
        - If bless reads value BEFORE callback: pre-loaded value is returned
        - If bless reads value AFTER callback: next value is returned
        """
        char_uuid = str(getattr(characteristic, "uuid", ""))
        if FROMRADIO_UUID.lower() not in char_uuid.lower():
            return bytearray()

        # Try pre-loaded value first (set by _advance_fromradio for bless/BlueZ)
        pre_loaded = getattr(characteristic, "value", None)
        if pre_loaded:
            result = bytes(pre_loaded)
            logger.debug("FROMRADIO read: %d bytes (pre-loaded), %d queued",
                         len(result), self._fromradio_queue.qsize())
        else:
            # Fallback: dequeue directly (mock servers, or first read before preload)
            try:
                data = self._fromradio_queue.get_nowait()
                result = bytes(data)
            except asyncio.QueueEmpty:
                result = b""
            logger.debug("FROMRADIO read: %d bytes (dequeued), %d queued",
                         len(result), self._fromradio_queue.qsize())

        # Advance: load next message into characteristic for the next read
        self._advance_fromradio()
        return bytearray(result)

    def _advance_fromradio(self) -> None:
        """Pre-load next queued message into FROMRADIO characteristic value.

        Called after queuing data and after each read, so the value is always
        ready before the phone's next ReadValue call.
        """
        if self._server is None:
            return
        try:
            char = self._server.get_characteristic(FROMRADIO_UUID)
            if char is None:
                return
        except Exception:
            return
        try:
            data = self._fromradio_queue.get_nowait()
            char.value = bytearray(data)
        except asyncio.QueueEmpty:
            char.value = bytearray()

    def _bump_fromnum(self) -> None:
        """Increment FromNum counter and notify phone of new data."""
        self._fromnum_counter += 1
        if self._server is not None and HAS_BLESS:
            try:
                # Set the 4-byte LE counter value before notifying
                char = self._server.get_characteristic(FROMNUM_UUID)
                if char is not None:
                    char.value = struct.pack("<I", self._fromnum_counter)
                self._server.update_value(SERVICE_UUID, FROMNUM_UUID)
            except Exception:
                pass

    async def _monitor_connection(self) -> None:
        """Poll bless for connection state changes and log them."""
        while self._running:
            try:
                connected = False
                if HAS_BLESS and hasattr(self._server, 'is_connected'):
                    connected = await self._server.is_connected()
                if connected and not self._phone_connected:
                    self._phone_connected = True
                    logger.info("Phone connected via BLE")
                elif not connected and self._phone_connected:
                    self._phone_connected = False
                    logger.info("Phone disconnected from BLE")
            except Exception:
                pass
            await asyncio.sleep(2)

    def queue_packet_for_phone(self, packet: MeshPacket, msg_id: int = 0) -> None:
        """Queue a received-from-air packet to send to the connected phone.

        Called when the SDR receives a packet over LoRa that should be
        forwarded to the phone.
        """
        fromradio_bytes = encode_fromradio_packet(packet, msg_id=msg_id)
        self._fromradio_queue.put_nowait(fromradio_bytes)
        self._advance_fromradio()
        self._bump_fromnum()

    async def stop(self) -> None:
        """Stop the BLE GATT server."""
        self._running = False
        if self._connection_monitor_task:
            self._connection_monitor_task.cancel()
            self._connection_monitor_task = None
        if self._server is not None:
            await self._server.stop()
        logger.info("BLE Gateway stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def queue_size(self) -> int:
        return self._fromradio_queue.qsize()
