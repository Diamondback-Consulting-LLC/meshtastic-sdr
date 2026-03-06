"""BLE gateway simulator — packet factories for all Meshtastic data types.

Creates MeshPacket instances for position, node info, telemetry, waypoints,
traceroutes, and neighbor info. Used by the CLI stdin reader to inject
simulated received packets via slash commands.

Supports dual-path: uses official meshtastic.protobuf if available, manual
encoding as fallback — same pattern as protobuf_codec.py and telemetry.py.
"""

import os
import struct
import time
from dataclasses import dataclass

from ..protocol.mesh_packet import MeshPacket, DataPayload
from ..protocol.header import MeshtasticHeader, BROADCAST_ADDR
from ..protocol.portnums import PortNum
from .telemetry import encode_device_metrics_telemetry, encode_environment_metrics_telemetry

# Reuse protobuf field helpers from protobuf_codec
from .protobuf_codec import (
    _field_varint, _field_string, _field_submsg,
    _field_fixed32, _field_float, _field_sfixed32,
)

# Try to import official protobuf definitions
try:
    from meshtastic.protobuf.mesh_pb2 import (
        Position as PbPosition,
        User as PbUser,
        Waypoint as PbWaypoint,
        RouteDiscovery as PbRouteDiscovery,
        NeighborInfo as PbNeighborInfo,
    )
    HAS_MESH_PB = True
except ImportError:
    HAS_MESH_PB = False


@dataclass
class SimulatorConfig:
    """Configuration for the BLE gateway simulator defaults."""
    fake_sender: int = 0xDE000001
    latitude: float = 59.9139      # Oslo, Norway
    longitude: float = 10.7522
    altitude: int = 25             # meters MSL


def _random_id() -> int:
    return struct.unpack("<I", os.urandom(4))[0]


def _make_packet(sender: int, channel_hash: int, portnum: int,
                 payload: bytes) -> MeshPacket:
    """Create a broadcast MeshPacket with the given portnum and payload."""
    header = MeshtasticHeader(
        to=BROADCAST_ADDR,
        from_node=sender,
        id=_random_id(),
        hop_limit=3,
        hop_start=3,
        channel=channel_hash,
    )
    data = DataPayload(
        portnum=portnum,
        payload=payload,
    )
    return MeshPacket(header=header, data=data)


def create_position_packet(sender: int, channel_hash: int,
                           lat: float, lon: float, alt: int,
                           time_s: int | None = None) -> MeshPacket:
    """Create a POSITION_APP packet.

    Position proto fields:
      1: latitude_i (sfixed32, lat * 1e7)
      2: longitude_i (sfixed32, lon * 1e7)
      3: altitude (int32)
      4: time (fixed32, epoch seconds)
    """
    if time_s is None:
        time_s = int(time.time())

    lat_i = int(lat * 1e7)
    lon_i = int(lon * 1e7)

    if HAS_MESH_PB:
        pos = PbPosition()
        pos.latitude_i = lat_i
        pos.longitude_i = lon_i
        pos.altitude = alt
        pos.time = time_s
        payload = pos.SerializeToString()
    else:
        parts = []
        parts.append(_field_sfixed32(1, lat_i))
        parts.append(_field_sfixed32(2, lon_i))
        parts.append(_field_varint(3, alt))
        parts.append(_field_fixed32(4, time_s))
        payload = b"".join(parts)

    return _make_packet(sender, channel_hash, PortNum.POSITION_APP, payload)


def create_nodeinfo_packet(sender: int, channel_hash: int,
                           long_name: str = "SimNode Alpha",
                           short_name: str = "SN",
                           hw_model: int = 37) -> MeshPacket:
    """Create a NODEINFO_APP packet.

    User proto fields:
      1: id (string, "!XXXXXXXX")
      2: long_name (string)
      3: short_name (string)
      5: hw_model (varint)
    """
    node_id_str = f"!{sender:08x}"

    if HAS_MESH_PB:
        user = PbUser()
        user.id = node_id_str
        user.long_name = long_name
        user.short_name = short_name
        user.hw_model = hw_model
        payload = user.SerializeToString()
    else:
        parts = []
        parts.append(_field_string(1, node_id_str))
        parts.append(_field_string(2, long_name))
        parts.append(_field_string(3, short_name))
        parts.append(_field_varint(5, hw_model))
        payload = b"".join(parts)

    return _make_packet(sender, channel_hash, PortNum.NODEINFO_APP, payload)


def create_telemetry_device_packet(sender: int,
                                   channel_hash: int) -> MeshPacket:
    """Create a TELEMETRY_APP packet with device metrics."""
    payload = encode_device_metrics_telemetry()
    return _make_packet(sender, channel_hash, PortNum.TELEMETRY_APP, payload)


def create_telemetry_env_packet(sender: int,
                                channel_hash: int) -> MeshPacket:
    """Create a TELEMETRY_APP packet with environment metrics.

    Falls back to a fake 42.0C temperature if no real sensor is available.
    """
    payload = encode_environment_metrics_telemetry()
    if payload is None:
        # No real sensor — encode a fake temperature
        from .telemetry import (
            _encode_float_field, _encode_fixed32_field, _encode_submsg,
            TELEMETRY_TIME, TELEMETRY_ENVIRONMENT_METRICS, EM_TEMPERATURE,
        )
        em_data = _encode_float_field(EM_TEMPERATURE, 42.0)
        parts = []
        parts.append(_encode_fixed32_field(TELEMETRY_TIME, int(time.time())))
        parts.append(_encode_submsg(TELEMETRY_ENVIRONMENT_METRICS, em_data))
        payload = b"".join(parts)

    return _make_packet(sender, channel_hash, PortNum.TELEMETRY_APP, payload)


def create_waypoint_packet(sender: int, channel_hash: int,
                           lat: float, lon: float,
                           name: str = "SimWaypoint",
                           description: str = "Simulated waypoint") -> MeshPacket:
    """Create a WAYPOINT_APP packet.

    Waypoint proto fields:
      1: id (uint32)
      2: latitude_i (sfixed32)
      3: longitude_i (sfixed32)
      4: expire (uint32, epoch seconds)
      5: locked_to (uint32)
      6: name (string)
      7: description (string)
      8: icon (fixed32, unicode codepoint)
    """
    lat_i = int(lat * 1e7)
    lon_i = int(lon * 1e7)
    expire = int(time.time()) + 86400  # 24 hours from now
    wp_id = _random_id()

    if HAS_MESH_PB:
        wp = PbWaypoint()
        wp.id = wp_id
        wp.latitude_i = lat_i
        wp.longitude_i = lon_i
        wp.expire = expire
        wp.name = name
        wp.description = description
        wp.icon = 0x1F4CD  # pin emoji
        payload = wp.SerializeToString()
    else:
        parts = []
        parts.append(_field_varint(1, wp_id))
        parts.append(_field_sfixed32(2, lat_i))
        parts.append(_field_sfixed32(3, lon_i))
        parts.append(_field_varint(4, expire))
        parts.append(_field_string(6, name))
        parts.append(_field_string(7, description))
        parts.append(_field_fixed32(8, 0x1F4CD))
        payload = b"".join(parts)

    return _make_packet(sender, channel_hash, PortNum.WAYPOINT_APP, payload)


def create_traceroute_packet(sender: int, channel_hash: int,
                             our_node_id: int) -> MeshPacket:
    """Create a TRACEROUTE_APP packet with a fake 2-hop route.

    RouteDiscovery proto fields:
      1: route (repeated fixed32)
      2: snr_towards (repeated int32) — SNR * 4
    """
    hop1 = 0xAA000001
    hop2 = 0xBB000002

    if HAS_MESH_PB:
        rd = PbRouteDiscovery()
        rd.route.append(hop1)
        rd.route.append(hop2)
        rd.route.append(our_node_id)
        rd.snr_towards.append(40)   # 10.0 dB
        rd.snr_towards.append(28)   # 7.0 dB
        rd.snr_towards.append(36)   # 9.0 dB
        payload = rd.SerializeToString()
    else:
        parts = []
        # route: field 1, fixed32 (repeated)
        for node in (hop1, hop2, our_node_id):
            parts.append(_field_fixed32(1, node))
        # snr_towards: field 2, int32/varint (repeated)
        for snr in (40, 28, 36):
            parts.append(_field_varint(2, snr))
        payload = b"".join(parts)

    return _make_packet(sender, channel_hash, PortNum.TRACEROUTE_APP, payload)


def create_neighborinfo_packet(sender: int, channel_hash: int,
                               our_node_id: int) -> MeshPacket:
    """Create a NEIGHBORINFO_APP packet with fake neighbors.

    NeighborInfo proto fields:
      1: node_id (uint32)
      2: last_sent_by_id (uint32)
      3: node_broadcast_interval_secs (uint32)
      4: neighbors (repeated Neighbor sub-message)

    Neighbor fields:
      1: node_id (uint32)
      2: snr (float)
    """
    if HAS_MESH_PB:
        ni = PbNeighborInfo()
        ni.node_id = sender
        ni.node_broadcast_interval_secs = 900
        n1 = ni.neighbors.add()
        n1.node_id = our_node_id
        n1.snr = 10.0
        n2 = ni.neighbors.add()
        n2.node_id = 0xCC000003
        n2.snr = 7.5
        payload = ni.SerializeToString()
    else:
        parts = []
        parts.append(_field_varint(1, sender))
        parts.append(_field_varint(3, 900))
        # Neighbor sub-messages (field 4, length-delimited)
        for node_id, snr in ((our_node_id, 10.0), (0xCC000003, 7.5)):
            neighbor = _field_varint(1, node_id) + _field_float(2, snr)
            parts.append(_field_submsg(4, neighbor))
        payload = b"".join(parts)

    return _make_packet(sender, channel_hash, PortNum.NEIGHBORINFO_APP, payload)
