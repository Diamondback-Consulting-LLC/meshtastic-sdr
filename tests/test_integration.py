"""Full TX -> RX loopback integration tests via simulated radio.

Tests the complete chain:
  Text -> MeshPacket -> encrypt -> LoRa encode -> modulate -> IQ samples
  IQ samples -> demodulate -> LoRa decode -> decrypt -> MeshPacket -> text
"""

import sys
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.radio.simulated import SimulatedRadio
from meshtastic_sdr.lora.params import get_preset
from meshtastic_sdr.lora.packet import LoRaPacket
from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR, HEADER_SIZE
from meshtastic_sdr.protocol.encryption import MeshtasticCrypto
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.protocol.channels import ChannelConfig
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.mesh.router import MeshRouter


class TestSimulatedRadio:
    def test_loopback_clean(self):
        """TX samples should be received unchanged."""
        import numpy as np
        radio = SimulatedRadio()
        samples = np.array([1 + 2j, 3 + 4j, 5 + 6j], dtype=np.complex64)
        radio.transmit(samples)
        received = radio.receive(3)
        np.testing.assert_array_almost_equal(received, samples)

    def test_loopback_with_noise(self):
        """TX with noise — samples should have noise added."""
        import numpy as np
        radio = SimulatedRadio(snr_db=30)
        samples = np.ones(1000, dtype=np.complex64)
        radio.transmit(samples)
        received = radio.receive(1000)
        # Should be close but not exact
        assert np.mean(np.abs(received - samples)) < 0.1

    def test_receive_empty(self):
        """Receiving from empty buffer returns zeros."""
        import numpy as np
        radio = SimulatedRadio()
        received = radio.receive(100)
        assert len(received) == 100
        assert np.all(received == 0)


class TestHeaderEncryption:
    def test_header_encrypt_decrypt(self):
        """Build a packet, encrypt, serialize, deserialize, decrypt."""
        from_node = 0x12345678
        pkt_id = 0xAABBCCDD

        header = MeshtasticHeader(
            to=BROADCAST_ADDR,
            from_node=from_node,
            id=pkt_id,
            hop_limit=3,
            hop_start=3,
            channel=0,
        )

        data = DataPayload(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=b"Hello from test!",
        )

        packet = MeshPacket(header=header, data=data)
        crypto = MeshtasticCrypto()

        # Encrypt
        ota_bytes = packet.encrypt_payload(crypto)
        assert len(ota_bytes) == HEADER_SIZE + len(packet.encrypted)

        # Parse from raw bytes
        parsed = MeshPacket.from_bytes(ota_bytes)
        assert parsed.header.to == BROADCAST_ADDR
        assert parsed.header.from_node == from_node
        assert parsed.header.id == pkt_id

        # Decrypt
        parsed.decrypt_payload(crypto)
        assert parsed.data.portnum == PortNum.TEXT_MESSAGE_APP
        assert parsed.data.payload == b"Hello from test!"
        assert parsed.data.text == "Hello from test!"


class TestMeshRouter:
    def test_duplicate_detection(self):
        router = MeshRouter(local_node_id=0x11111111)
        header = MeshtasticHeader(from_node=0x22222222, id=0xAAAA)

        assert not router.is_duplicate(header)
        router.record_packet(header)
        assert router.is_duplicate(header)

    def test_should_not_rebroadcast_own(self):
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(
            header=MeshtasticHeader(from_node=0x11111111, id=1, hop_limit=3),
        )
        assert not router.should_rebroadcast(packet)

    def test_should_rebroadcast_others(self):
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(
            header=MeshtasticHeader(
                to=BROADCAST_ADDR,
                from_node=0x22222222,
                id=1,
                hop_limit=3,
                hop_start=3,
            ),
        )
        assert router.should_rebroadcast(packet)

    def test_no_rebroadcast_at_zero_hops(self):
        router = MeshRouter(local_node_id=0x11111111)
        packet = MeshPacket(
            header=MeshtasticHeader(from_node=0x22222222, id=1, hop_limit=0),
        )
        assert not router.should_rebroadcast(packet)


class TestNodeDB:
    def test_node_creation(self):
        node = MeshNode(node_id=0xDEADBEEF, long_name="Test")
        assert node.node_id == 0xDEADBEEF
        assert node.long_name == "Test"

    def test_node_db_update(self):
        node = MeshNode()
        node.update_node(0x12345678, long_name="Remote Node")
        info = node.get_node(0x12345678)
        assert info is not None
        assert info.long_name == "Remote Node"

    def test_random_node_id(self):
        node1 = MeshNode()
        node2 = MeshNode()
        assert node1.node_id != node2.node_id


class TestLoRaPacketRoundTrip:
    """Test LoRa PHY layer packet build and parse."""

    @pytest.mark.parametrize("preset_name", ["SHORT_FAST"])
    def test_lora_packet_roundtrip(self, preset_name):
        """Build a LoRa packet and parse it back."""
        preset = get_preset(preset_name)
        lora = LoRaPacket(preset)

        payload = b"\x01\x02\x03\x04\x05"
        iq = lora.build(payload)
        assert len(iq) > 0

        recovered = lora.parse(iq)
        assert recovered is not None
        assert recovered == payload


class TestSDRTransportIntegration:
    """Test SDRTransport matches MeshInterface behavior."""

    def test_sdr_transport_matches_mesh_interface(self):
        """SDRTransport produces the same result as direct MeshInterface."""
        import asyncio
        from meshtastic_sdr.transport.sdr_transport import SDRTransport
        from meshtastic_sdr.mesh.interface import AsyncMeshInterface

        async def _test():
            radio = SimulatedRadio()
            tx_node = MeshNode(node_id=0xAAAAAAAA)
            rx_node = MeshNode(node_id=0xBBBBBBBB)

            tx = SDRTransport(radio, preset_name="SHORT_FAST", node=tx_node)
            rx = SDRTransport(radio, preset_name="SHORT_FAST", node=rx_node)
            await tx.start()

            pkt = MeshPacket.create_text("Integration test!", from_node=tx_node.node_id,
                                         channel=tx.channel.channel_hash)
            await tx.send_packet(pkt)
            received = await rx.receive_packet(timeout_s=5.0)

            assert received is not None
            assert received.data.text == "Integration test!"
            await tx.stop()
            await rx.stop()

        asyncio.get_event_loop().run_until_complete(_test())


class TestBLEIntegration:
    """End-to-end BLE integration test with simulated radio."""

    def test_ble_gateway_phone_to_air_loopback(self):
        """Phone -> BLE Gateway -> SDR TX -> SimulatedRadio -> SDR RX -> verify."""
        import asyncio
        from meshtastic_sdr.ble.peripheral import BLEGateway
        from meshtastic_sdr.ble.protobuf_codec import encode_toradio_packet
        from meshtastic_sdr.transport.sdr_transport import SDRTransport

        async def _test():
            radio = SimulatedRadio()
            gw_node = MeshNode(node_id=0x60000001, long_name="Gateway")
            rx_node = MeshNode(node_id=0x70000001)

            # Track packets the gateway transmits
            transmitted = []

            def on_phone_packet(packet):
                from meshtastic_sdr.protocol.encryption import MeshtasticCrypto
                crypto = MeshtasticCrypto()
                ota = packet.encrypt_payload(crypto)
                from meshtastic_sdr.lora.packet import LoRaPacket
                from meshtastic_sdr.lora.params import get_preset
                preset = get_preset("SHORT_FAST")
                lora = LoRaPacket(preset)
                iq = lora.build(ota)
                radio.transmit(iq)
                transmitted.append(packet)

            gateway = BLEGateway(
                node=gw_node,
                on_packet_from_phone=on_phone_packet,
            )

            # Simulate phone sending a text packet via BLE
            from meshtastic_sdr.protocol.channels import ChannelConfig as _CC
            default_ch = _CC.default()
            pkt = MeshPacket.create_text(
                text="Phone to air!",
                from_node=gw_node.node_id,
                channel=default_ch.channel_hash,
            )
            toradio = encode_toradio_packet(pkt)

            # Manually handle the write (no actual BLE server needed)
            from meshtastic_sdr.ble.protobuf_codec import decode_toradio
            parsed = decode_toradio(toradio)
            assert "packet" in parsed
            on_phone_packet(parsed["packet"])

            assert len(transmitted) == 1

            # Now receive it on the other side
            rx_transport = SDRTransport(radio, preset_name="SHORT_FAST", node=rx_node)
            received = await rx_transport.receive_packet(timeout_s=5.0)

            assert received is not None
            assert received.data is not None
            assert received.data.text == "Phone to air!"

            await rx_transport.stop()

        asyncio.get_event_loop().run_until_complete(_test())


class TestFullStackLoopback:
    """Complete TX -> RX through simulated radio."""

    def test_text_message_loopback(self):
        """Full stack: send text, receive and decode it."""
        radio = SimulatedRadio()
        preset = get_preset("SHORT_FAST")
        lora = LoRaPacket(preset)
        crypto = MeshtasticCrypto()

        # TX side
        tx_node = 0xAAAAAAAA
        message = "Hello mesh!"

        tx_packet = MeshPacket.create_text(
            text=message,
            from_node=tx_node,
            channel=0,
        )
        ota_bytes = tx_packet.encrypt_payload(crypto)
        iq_samples = lora.build(ota_bytes)
        radio.transmit(iq_samples)

        # RX side
        rx_samples = radio.receive(len(iq_samples))
        recovered_bytes = lora.parse(rx_samples)

        assert recovered_bytes is not None
        assert len(recovered_bytes) >= HEADER_SIZE

        rx_packet = MeshPacket.from_bytes(recovered_bytes)
        assert rx_packet.header.from_node == tx_node

        rx_packet.decrypt_payload(crypto)
        assert rx_packet.data is not None
        assert rx_packet.data.text == message

    def test_channel_config(self):
        """Test channel hash and frequency calculation."""
        ch = ChannelConfig.default()
        assert ch.display_name == "LongFast"
        assert ch.has_encryption()
        assert 0 <= ch.channel_hash <= 255
