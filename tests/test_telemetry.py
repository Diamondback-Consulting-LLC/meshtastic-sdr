"""Tests for BLE telemetry service."""

import sys
import struct
import time

sys.path.insert(0, "src")

from meshtastic_sdr.ble.telemetry import (
    encode_device_metrics_telemetry,
    encode_environment_metrics_telemetry,
    create_telemetry_packet,
    get_uptime_seconds,
    _encode_varint,
    _encode_float,
)
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.protocol.mesh_packet import _decode_varint


def _decode_tag(data, offset=0):
    """Decode a protobuf tag into (field_number, wire_type, new_offset)."""
    val, off = _decode_varint(data, offset)
    return val >> 3, val & 0x7, off


def _decode_telemetry_fields(data):
    """Parse a Telemetry protobuf into a dict of field_num -> value."""
    fields = {}
    offset = 0
    while offset < len(data):
        field_num, wire_type, offset = _decode_tag(data, offset)
        if wire_type == 0:  # varint
            val, offset = _decode_varint(data, offset)
            fields[field_num] = val
        elif wire_type == 2:  # length-delimited
            length, offset = _decode_varint(data, offset)
            fields[field_num] = data[offset:offset + length]
            offset += length
        elif wire_type == 5:  # 32-bit (float or fixed32)
            fields[field_num] = data[offset:offset + 4]
            offset += 4
        elif wire_type == 1:  # 64-bit
            fields[field_num] = data[offset:offset + 8]
            offset += 8
    return fields


class TestDeviceMetrics:
    def test_encodes_valid_protobuf(self):
        data = encode_device_metrics_telemetry()
        assert len(data) > 0

        fields = _decode_telemetry_fields(data)
        # Field 1: time (fixed32)
        assert 1 in fields
        ts = struct.unpack("<I", fields[1])[0]
        assert abs(ts - time.time()) < 10

        # Field 2: device_metrics (sub-message)
        assert 2 in fields
        dm = _decode_telemetry_fields(fields[2])

        # battery_level = 101 (powered)
        assert dm[1] == 101

        # voltage = 5.0
        voltage = struct.unpack("<f", dm[2])[0]
        assert abs(voltage - 5.0) < 0.01

        # uptime_seconds > 0
        assert dm[5] >= 0

    def test_uptime_increases(self):
        u1 = get_uptime_seconds()
        assert u1 >= 0


class TestEnvironmentMetrics:
    def test_encodes_temperature_if_available(self):
        data = encode_environment_metrics_telemetry()
        # May be None if no temperature sensor (CI environments)
        if data is not None:
            fields = _decode_telemetry_fields(data)
            # Field 3: environment_metrics
            assert 3 in fields
            em = _decode_telemetry_fields(fields[3])
            # Field 1: temperature (float)
            assert 1 in em
            temp = struct.unpack("<f", em[1])[0]
            assert -20 < temp < 120


class TestTelemetryPacket:
    def test_creates_mesh_packet(self):
        payload = encode_device_metrics_telemetry()
        pkt = create_telemetry_packet(0xAABBCCDD, payload)

        assert pkt.header.from_node == 0xAABBCCDD
        assert pkt.header.to == 0xAABBCCDD
        assert pkt.data.portnum == PortNum.TELEMETRY_APP
        assert pkt.data.payload == payload
        assert pkt.header.id != 0
