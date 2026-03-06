"""Tests for BLE gateway simulator packet factories."""

from meshtastic_sdr.ble.simulator import (
    SimulatorConfig,
    create_position_packet,
    create_nodeinfo_packet,
    create_telemetry_device_packet,
    create_telemetry_env_packet,
    create_waypoint_packet,
    create_traceroute_packet,
    create_neighborinfo_packet,
)
from meshtastic_sdr.protocol.mesh_packet import MeshPacket
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.protocol.header import BROADCAST_ADDR


FAKE_SENDER = 0xDE000001
CHANNEL_HASH = 0x08
OUR_NODE = 0x12345678


class TestSimulatorConfig:
    def test_defaults(self):
        cfg = SimulatorConfig()
        assert cfg.fake_sender == 0xDE000001
        assert cfg.latitude == 59.9139
        assert cfg.longitude == 10.7522
        assert cfg.altitude == 25

    def test_custom(self):
        cfg = SimulatorConfig(latitude=60.0, longitude=11.0, altitude=100)
        assert cfg.latitude == 60.0
        assert cfg.longitude == 11.0
        assert cfg.altitude == 100


class TestPositionPacket:
    def test_creates_valid_packet(self):
        pkt = create_position_packet(FAKE_SENDER, CHANNEL_HASH, 59.9139, 10.7522, 25)
        assert isinstance(pkt, MeshPacket)
        assert pkt.data is not None
        assert pkt.data.portnum == PortNum.POSITION_APP
        assert pkt.header.from_node == FAKE_SENDER
        assert pkt.header.to == BROADCAST_ADDR
        assert pkt.header.channel == CHANNEL_HASH

    def test_payload_not_empty(self):
        pkt = create_position_packet(FAKE_SENDER, CHANNEL_HASH, 59.9139, 10.7522, 25)
        assert len(pkt.data.payload) > 0

    def test_custom_coordinates(self):
        pkt = create_position_packet(FAKE_SENDER, CHANNEL_HASH, 40.7128, -74.0060, 10)
        assert pkt.data.portnum == PortNum.POSITION_APP
        assert len(pkt.data.payload) > 0

    def test_with_explicit_time(self):
        ts = 1700000000
        pkt = create_position_packet(FAKE_SENDER, CHANNEL_HASH, 59.9, 10.7, 25, time_s=ts)
        assert pkt.data.portnum == PortNum.POSITION_APP

    def test_negative_coordinates(self):
        pkt = create_position_packet(FAKE_SENDER, CHANNEL_HASH, -33.8688, 151.2093, 5)
        assert pkt.data.portnum == PortNum.POSITION_APP
        assert len(pkt.data.payload) > 0


class TestNodeInfoPacket:
    def test_creates_valid_packet(self):
        pkt = create_nodeinfo_packet(FAKE_SENDER, CHANNEL_HASH)
        assert pkt.data.portnum == PortNum.NODEINFO_APP
        assert pkt.header.from_node == FAKE_SENDER

    def test_default_names(self):
        pkt = create_nodeinfo_packet(FAKE_SENDER, CHANNEL_HASH)
        # Payload should contain the default names
        payload = pkt.data.payload
        assert b"SimNode Alpha" in payload
        assert b"SN" in payload

    def test_custom_names(self):
        pkt = create_nodeinfo_packet(
            FAKE_SENDER, CHANNEL_HASH,
            long_name="Test Node", short_name="TN", hw_model=42
        )
        assert b"Test Node" in pkt.data.payload
        assert b"TN" in pkt.data.payload

    def test_contains_node_id_string(self):
        pkt = create_nodeinfo_packet(FAKE_SENDER, CHANNEL_HASH)
        assert b"!de000001" in pkt.data.payload


class TestTelemetryDevicePacket:
    def test_creates_valid_packet(self):
        pkt = create_telemetry_device_packet(FAKE_SENDER, CHANNEL_HASH)
        assert pkt.data.portnum == PortNum.TELEMETRY_APP
        assert pkt.header.from_node == FAKE_SENDER

    def test_payload_not_empty(self):
        pkt = create_telemetry_device_packet(FAKE_SENDER, CHANNEL_HASH)
        assert len(pkt.data.payload) > 0


class TestTelemetryEnvPacket:
    def test_creates_valid_packet(self):
        pkt = create_telemetry_env_packet(FAKE_SENDER, CHANNEL_HASH)
        assert pkt.data.portnum == PortNum.TELEMETRY_APP
        assert pkt.header.from_node == FAKE_SENDER

    def test_payload_not_empty(self):
        pkt = create_telemetry_env_packet(FAKE_SENDER, CHANNEL_HASH)
        assert len(pkt.data.payload) > 0


class TestWaypointPacket:
    def test_creates_valid_packet(self):
        pkt = create_waypoint_packet(FAKE_SENDER, CHANNEL_HASH, 59.9139, 10.7522)
        assert pkt.data.portnum == PortNum.WAYPOINT_APP
        assert pkt.header.from_node == FAKE_SENDER

    def test_default_name(self):
        pkt = create_waypoint_packet(FAKE_SENDER, CHANNEL_HASH, 59.9, 10.7)
        assert b"SimWaypoint" in pkt.data.payload

    def test_custom_name(self):
        pkt = create_waypoint_packet(
            FAKE_SENDER, CHANNEL_HASH, 59.9, 10.7, name="Home Base"
        )
        assert b"Home Base" in pkt.data.payload

    def test_payload_not_empty(self):
        pkt = create_waypoint_packet(FAKE_SENDER, CHANNEL_HASH, 59.9, 10.7)
        assert len(pkt.data.payload) > 0


class TestTraceroutePacket:
    def test_creates_valid_packet(self):
        pkt = create_traceroute_packet(FAKE_SENDER, CHANNEL_HASH, OUR_NODE)
        assert pkt.data.portnum == PortNum.TRACEROUTE_APP
        assert pkt.header.from_node == FAKE_SENDER

    def test_payload_not_empty(self):
        pkt = create_traceroute_packet(FAKE_SENDER, CHANNEL_HASH, OUR_NODE)
        assert len(pkt.data.payload) > 0


class TestNeighborInfoPacket:
    def test_creates_valid_packet(self):
        pkt = create_neighborinfo_packet(FAKE_SENDER, CHANNEL_HASH, OUR_NODE)
        assert pkt.data.portnum == PortNum.NEIGHBORINFO_APP
        assert pkt.header.from_node == FAKE_SENDER

    def test_payload_not_empty(self):
        pkt = create_neighborinfo_packet(FAKE_SENDER, CHANNEL_HASH, OUR_NODE)
        assert len(pkt.data.payload) > 0


class TestAllPacketsBroadcast:
    """Verify all packet types use broadcast destination and correct sender."""

    def test_all_broadcast(self):
        factories = [
            lambda: create_position_packet(FAKE_SENDER, CHANNEL_HASH, 59.9, 10.7, 25),
            lambda: create_nodeinfo_packet(FAKE_SENDER, CHANNEL_HASH),
            lambda: create_telemetry_device_packet(FAKE_SENDER, CHANNEL_HASH),
            lambda: create_telemetry_env_packet(FAKE_SENDER, CHANNEL_HASH),
            lambda: create_waypoint_packet(FAKE_SENDER, CHANNEL_HASH, 59.9, 10.7),
            lambda: create_traceroute_packet(FAKE_SENDER, CHANNEL_HASH, OUR_NODE),
            lambda: create_neighborinfo_packet(FAKE_SENDER, CHANNEL_HASH, OUR_NODE),
        ]
        for factory in factories:
            pkt = factory()
            assert pkt.header.to == BROADCAST_ADDR
            assert pkt.header.from_node == FAKE_SENDER
            assert pkt.header.channel == CHANNEL_HASH
            assert pkt.header.id != 0  # random, should not be zero
            assert pkt.data is not None
            assert len(pkt.data.payload) > 0
