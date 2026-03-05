"""Tests for Meshtastic 16-byte OTA header pack/unpack."""

import sys
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR, HEADER_SIZE


class TestHeaderPackUnpack:
    def test_broadcast_header_roundtrip(self):
        hdr = MeshtasticHeader(
            to=BROADCAST_ADDR,
            from_node=0x12345678,
            id=0xDEADBEEF,
            hop_limit=3,
            want_ack=False,
            via_mqtt=False,
            hop_start=3,
            channel=0x42,
        )
        packed = hdr.pack()
        assert len(packed) == HEADER_SIZE

        recovered = MeshtasticHeader.unpack(packed)
        assert recovered.to == BROADCAST_ADDR
        assert recovered.from_node == 0x12345678
        assert recovered.id == 0xDEADBEEF
        assert recovered.hop_limit == 3
        assert recovered.want_ack is False
        assert recovered.via_mqtt is False
        assert recovered.hop_start == 3
        assert recovered.channel == 0x42

    def test_unicast_with_ack(self):
        hdr = MeshtasticHeader(
            to=0xAABBCCDD,
            from_node=0x11223344,
            id=0x00000001,
            hop_limit=7,
            want_ack=True,
            via_mqtt=True,
            hop_start=7,
            channel=0xFF,
        )
        packed = hdr.pack()
        recovered = MeshtasticHeader.unpack(packed)

        assert recovered.to == 0xAABBCCDD
        assert recovered.from_node == 0x11223344
        assert recovered.id == 0x00000001
        assert recovered.hop_limit == 7
        assert recovered.want_ack is True
        assert recovered.via_mqtt is True
        assert recovered.hop_start == 7
        assert recovered.channel == 0xFF

    def test_flags_field(self):
        hdr = MeshtasticHeader()
        hdr.hop_limit = 5
        hdr.want_ack = True
        hdr.via_mqtt = False
        hdr.hop_start = 6
        # flags = (hop_start << 5) | (via_mqtt << 4) | (want_ack << 3) | hop_limit
        expected = (6 << 5) | (0 << 4) | (1 << 3) | 5
        assert hdr.flags == expected

    def test_flags_setter(self):
        hdr = MeshtasticHeader()
        hdr.flags = 0xFF
        assert hdr.hop_limit == 7
        assert hdr.want_ack is True
        assert hdr.via_mqtt is True
        assert hdr.hop_start == 7

    def test_is_broadcast(self):
        hdr = MeshtasticHeader(to=BROADCAST_ADDR)
        assert hdr.is_broadcast is True

        hdr.to = 0x12345678
        assert hdr.is_broadcast is False

    def test_next_hop_relay_node(self):
        hdr = MeshtasticHeader(next_hop=0xAB, relay_node=0xCD)
        packed = hdr.pack()
        recovered = MeshtasticHeader.unpack(packed)
        assert recovered.next_hop == 0xAB
        assert recovered.relay_node == 0xCD

    def test_zero_header(self):
        hdr = MeshtasticHeader(to=0, from_node=0, id=0, hop_limit=0,
                               channel=0, next_hop=0, relay_node=0)
        packed = hdr.pack()
        recovered = MeshtasticHeader.unpack(packed)
        assert recovered.to == 0
        assert recovered.from_node == 0
        assert recovered.id == 0
        assert recovered.hop_limit == 0

    def test_unpack_too_short(self):
        with pytest.raises(ValueError):
            MeshtasticHeader.unpack(b"\x00" * 10)

    def test_repr(self):
        hdr = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0xDEAD)
        s = repr(hdr)
        assert "broadcast" in s
        assert "0000dead" in s
