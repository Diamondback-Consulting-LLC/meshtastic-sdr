"""Meshtastic port number definitions and payload decoders.

Port numbers identify the application-layer type of a Meshtastic data payload.
"""

from enum import IntEnum


class PortNum(IntEnum):
    UNKNOWN_APP = 0
    TEXT_MESSAGE_APP = 1
    REMOTE_HARDWARE_APP = 2
    POSITION_APP = 3
    NODEINFO_APP = 4
    ROUTING_APP = 5
    ADMIN_APP = 6
    TEXT_MESSAGE_COMPRESSED_APP = 7
    WAYPOINT_APP = 8
    AUDIO_APP = 9
    DETECTION_SENSOR_APP = 10
    ALERT_APP = 11
    KEY_VERIFICATION_APP = 12
    REPLY_APP = 32
    IP_TUNNEL_APP = 33
    PAXCOUNTER_APP = 34
    STORE_FORWARD_PLUSPLUS_APP = 35
    NODE_STATUS_APP = 36
    SERIAL_APP = 64
    STORE_FORWARD_APP = 65
    RANGE_TEST_APP = 66
    TELEMETRY_APP = 67
    ZPS_APP = 68
    SIMULATOR_APP = 69
    TRACEROUTE_APP = 70
    NEIGHBORINFO_APP = 71
    ATAK_PLUGIN = 72
    MAP_REPORT_APP = 73
    POWERSTRESS_APP = 74
    RETICULUM_TUNNEL_APP = 76
    CAYENNE_APP = 77
    PRIVATE_APP = 256
    ATAK_FORWARDER = 257
    MAX = 511


# Human-readable names
PORT_NAMES = {p: p.name for p in PortNum}


def decode_text_payload(payload: bytes) -> str:
    """Decode a TEXT_MESSAGE_APP payload."""
    return payload.decode("utf-8", errors="replace")


def describe_portnum(portnum: int) -> str:
    """Get a human-readable description of a port number."""
    try:
        return PortNum(portnum).name
    except ValueError:
        return f"UNKNOWN({portnum})"
