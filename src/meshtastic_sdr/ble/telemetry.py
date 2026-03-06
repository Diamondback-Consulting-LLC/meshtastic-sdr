"""Local telemetry collection for the SDR gateway.

Collects host metrics (CPU temp, uptime, memory, disk, load) and
sends them to the connected phone as Meshtastic telemetry packets.
"""

import os
import struct
import time
import asyncio
import logging
from pathlib import Path

from ..protocol.mesh_packet import MeshPacket, DataPayload, _encode_varint
from ..protocol.header import MeshtasticHeader
from ..protocol.portnums import PortNum

logger = logging.getLogger(__name__)

# Protobuf field numbers
# Telemetry message
TELEMETRY_TIME = 1           # fixed32
TELEMETRY_DEVICE_METRICS = 2  # sub-message
TELEMETRY_ENVIRONMENT_METRICS = 3  # sub-message

# DeviceMetrics fields
DM_BATTERY_LEVEL = 1     # uint32
DM_VOLTAGE = 2            # float
DM_CHANNEL_UTIL = 3       # float
DM_AIR_UTIL_TX = 4        # float
DM_UPTIME_SECONDS = 5     # uint32

# EnvironmentMetrics fields
EM_TEMPERATURE = 1        # float

_start_time = time.monotonic()


def _encode_float(value: float) -> bytes:
    return struct.pack("<f", value)


def _encode_submsg(field_num: int, data: bytes) -> bytes:
    """Encode a length-delimited sub-message field."""
    tag = (field_num << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def _encode_float_field(field_num: int, value: float) -> bytes:
    """Encode a float field (wire type 5 = 32-bit)."""
    tag = (field_num << 3) | 5
    return _encode_varint(tag) + _encode_float(value)


def _encode_varint_field(field_num: int, value: int) -> bytes:
    """Encode a varint field (wire type 0)."""
    tag = (field_num << 3) | 0
    return _encode_varint(tag) + _encode_varint(value)


def _encode_fixed32_field(field_num: int, value: int) -> bytes:
    """Encode a fixed32 field (wire type 5)."""
    tag = (field_num << 3) | 5
    return _encode_varint(tag) + struct.pack("<I", value)


def get_cpu_temperature() -> float | None:
    """Read CPU temperature from hwmon or thermal_zone."""
    # Try hwmon k10temp/coretemp first
    for hwmon in Path("/sys/class/hwmon").glob("hwmon*"):
        name_file = hwmon / "name"
        if name_file.exists():
            name = name_file.read_text().strip()
            if name in ("k10temp", "coretemp"):
                for temp_file in sorted(hwmon.glob("temp*_input")):
                    try:
                        return int(temp_file.read_text().strip()) / 1000.0
                    except (ValueError, OSError):
                        continue

    # Fallback to thermal zones
    for tz in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        try:
            temp = int((tz / "temp").read_text().strip()) / 1000.0
            if 0 < temp < 120:
                return temp
        except (ValueError, OSError, FileNotFoundError):
            continue
    return None


def get_uptime_seconds() -> int:
    """Get process uptime in seconds."""
    return int(time.monotonic() - _start_time)


def get_system_uptime() -> int:
    """Get system uptime in seconds."""
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError):
        return get_uptime_seconds()


def get_free_memory_bytes() -> int:
    """Get available memory in bytes."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def get_disk_free_bytes(path: str = "/") -> int:
    """Get free disk space in bytes."""
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
    except OSError:
        return 0


def get_load_average() -> tuple[float, float, float]:
    """Get 1/5/15 minute load averages."""
    try:
        loads = os.getloadavg()
        return (loads[0], loads[1], loads[2])
    except OSError:
        return (0.0, 0.0, 0.0)


def encode_device_metrics_telemetry() -> bytes:
    """Encode a Telemetry protobuf with DeviceMetrics.

    Reports: battery=101 (powered), uptime, channel_util=0.
    """
    # DeviceMetrics sub-message
    dm_parts = []
    dm_parts.append(_encode_varint_field(DM_BATTERY_LEVEL, 101))  # >100 = powered
    dm_parts.append(_encode_float_field(DM_VOLTAGE, 5.0))  # USB power
    dm_parts.append(_encode_float_field(DM_CHANNEL_UTIL, 0.0))
    dm_parts.append(_encode_float_field(DM_AIR_UTIL_TX, 0.0))
    dm_parts.append(_encode_varint_field(DM_UPTIME_SECONDS, get_uptime_seconds()))
    dm_data = b"".join(dm_parts)

    # Telemetry wrapper
    parts = []
    parts.append(_encode_fixed32_field(TELEMETRY_TIME, int(time.time())))
    parts.append(_encode_submsg(TELEMETRY_DEVICE_METRICS, dm_data))
    return b"".join(parts)


def encode_environment_metrics_telemetry() -> bytes | None:
    """Encode a Telemetry protobuf with EnvironmentMetrics (CPU temperature).

    Returns None if no temperature sensor is available.
    """
    temp = get_cpu_temperature()
    if temp is None:
        return None

    # EnvironmentMetrics sub-message
    em_data = _encode_float_field(EM_TEMPERATURE, temp)

    # Telemetry wrapper
    parts = []
    parts.append(_encode_fixed32_field(TELEMETRY_TIME, int(time.time())))
    parts.append(_encode_submsg(TELEMETRY_ENVIRONMENT_METRICS, em_data))
    return b"".join(parts)


def create_telemetry_packet(node_id: int, telemetry_payload: bytes) -> MeshPacket:
    """Create a MeshPacket with telemetry data for the local node."""
    pkt_id = struct.unpack("<I", os.urandom(4))[0]

    header = MeshtasticHeader(
        to=node_id,  # Addressed to self (local telemetry)
        from_node=node_id,
        id=pkt_id,
        hop_limit=0,
        hop_start=0,
        channel=0,
    )

    data = DataPayload(
        portnum=PortNum.TELEMETRY_APP,
        payload=telemetry_payload,
    )

    return MeshPacket(header=header, data=data)


class TelemetryService:
    """Periodically sends telemetry to a connected phone via BLE gateway."""

    def __init__(self, gateway, node_id: int,
                 device_interval: int = 900,
                 environment_interval: int = 900):
        """
        Args:
            gateway: BLEGateway instance to queue packets to.
            node_id: Our node ID.
            device_interval: Seconds between device metrics updates.
            environment_interval: Seconds between environment metrics updates.
        """
        self.gateway = gateway
        self.node_id = node_id
        self.device_interval = device_interval
        self.environment_interval = environment_interval
        self._task: asyncio.Task | None = None
        self._msg_id = 0x10000

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def start(self):
        """Start the periodic telemetry loop."""
        if self._task is None:
            self._task = asyncio.ensure_future(self._run())
            logger.info("Telemetry service started (device=%ds, env=%ds)",
                        self.device_interval, self.environment_interval)

    async def _run(self):
        # Send initial telemetry after a short delay
        await asyncio.sleep(5)
        self._send_device_metrics()
        self._send_environment_metrics()

        device_timer = 0
        env_timer = 0
        while True:
            await asyncio.sleep(60)
            device_timer += 60
            env_timer += 60

            if device_timer >= self.device_interval:
                self._send_device_metrics()
                device_timer = 0

            if env_timer >= self.environment_interval:
                self._send_environment_metrics()
                env_timer = 0

    def _send_device_metrics(self):
        payload = encode_device_metrics_telemetry()
        pkt = create_telemetry_packet(self.node_id, payload)
        self.gateway.queue_packet_for_phone(pkt, msg_id=self._next_id())
        logger.info("Sent device metrics (uptime=%ds)", get_uptime_seconds())

    def _send_environment_metrics(self):
        payload = encode_environment_metrics_telemetry()
        if payload is None:
            return
        pkt = create_telemetry_packet(self.node_id, payload)
        self.gateway.queue_packet_for_phone(pkt, msg_id=self._next_id())
        temp = get_cpu_temperature()
        logger.info("Sent environment metrics (temp=%.1f°C)", temp or 0)

    def stop(self):
        if self._task:
            self._task.cancel()
            self._task = None
