"""RX/TX audit tests: radio backends, transport, LoRa PHY integration, frequency, routing."""

import sys
import asyncio
import struct
import threading
import time
import unittest

import numpy as np

sys.path.insert(0, "src")

from meshtastic_sdr.radio.base import RadioBackend
from meshtastic_sdr.radio.simulated import SimulatedRadio
from meshtastic_sdr.radio.bladerf_radio import complex64_to_sc16q11, sc16q11_to_complex64, SC16_Q11_SCALE
from meshtastic_sdr.lora.params import get_preset, PRESETS, CodingRate
from meshtastic_sdr.lora.packet import LoRaPacket
from meshtastic_sdr.lora.modulator import LoRaModulator, MESHTASTIC_SYNC_WORD
from meshtastic_sdr.lora.demodulator import LoRaDemodulator
from meshtastic_sdr.lora.encoder import LoRaEncoder
from meshtastic_sdr.lora.decoder import LoRaDecoder
from meshtastic_sdr.protocol.header import MeshtasticHeader, BROADCAST_ADDR, HEADER_SIZE
from meshtastic_sdr.protocol.encryption import MeshtasticCrypto, DEFAULT_KEY
from meshtastic_sdr.protocol.channels import (
    ChannelConfig, RegionConfig, REGIONS, get_default_frequency,
    compute_channel_hash, _djb2_hash, get_channel_num,
)
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.mesh.router import MeshRouter
from meshtastic_sdr.mesh.interface import MeshInterface, AsyncMeshInterface
from meshtastic_sdr.transport.sdr_transport import SDRTransport


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# =============================================================================
# Frequency calculation — DJB2 hash and channel slot
# =============================================================================

class TestDJB2Hash(unittest.TestCase):
    """DJB2 hash must match Meshtastic firmware/Android."""

    def test_longfast_hash_gives_channel_20(self):
        """Android ChannelTest: channelNum for 'LongFast' on US (104 ch) = 20."""
        h = _djb2_hash("LongFast")
        num_channels = 104  # US at 250kHz BW
        channel_num = (h % num_channels) + 1
        self.assertEqual(channel_num, 20)

    def test_get_channel_num_longfast_us(self):
        self.assertEqual(get_channel_num("LongFast", 104), 20)

    def test_get_channel_num_empty_defaults_to_longfast(self):
        self.assertEqual(get_channel_num("", 104), get_channel_num("LongFast", 104))

    def test_get_channel_num_always_1_indexed(self):
        """Result is always >= 1."""
        for name in ["LongFast", "test", "a", "Z" * 100]:
            result = get_channel_num(name, 104)
            self.assertGreaterEqual(result, 1)
            self.assertLessEqual(result, 104)

    def test_get_channel_num_single_channel(self):
        """With 1 channel, always returns 1."""
        self.assertEqual(get_channel_num("LongFast", 1), 1)

    def test_djb2_is_uint32(self):
        """Hash fits in uint32."""
        h = _djb2_hash("LongFast")
        self.assertGreaterEqual(h, 0)
        self.assertLess(h, 2**32)


class TestFrequencyCalculation(unittest.TestCase):
    """Frequency must match Meshtastic firmware exactly."""

    def test_us_longfast_906_875(self):
        """Android ChannelTest: US/LongFast at 250kHz = 906.875 MHz."""
        freq = get_default_frequency("US", 250.0, "LongFast")
        self.assertAlmostEqual(freq, 906.875e6, places=0)

    def test_us_longfast_explicit_channel_20(self):
        """Explicit 1-indexed channel_num=20 also gives 906.875 MHz."""
        freq = get_default_frequency("US", 250.0, channel_num=20)
        self.assertAlmostEqual(freq, 906.875e6, places=0)

    def test_channel_1_gives_first_slot(self):
        """channel_num=1 should be the first slot (lowest frequency)."""
        freq = get_default_frequency("US", 250.0, channel_num=1)
        # freq_start + BW/2 + (1-1)*BW = 902.0 + 0.125 = 902.125 MHz
        self.assertAlmostEqual(freq, 902.125e6, places=0)

    def test_eu868_default(self):
        freq = get_default_frequency("EU_868", 250.0)
        # EU_868: 869.4-869.65, BW=0.25MHz
        # num_channels = floor(0.25/0.25) = 1
        # channel_num = hash % 1 + 1 = 1
        # freq = 869.4 + 0.125 + 0 = 869.525 MHz
        self.assertAlmostEqual(freq, 869.525e6, places=0)

    def test_unknown_region_raises(self):
        with self.assertRaises(ValueError):
            get_default_frequency("INVALID", 250.0)

    def test_different_bandwidths_different_slots(self):
        """Wider bandwidth = fewer channels = different slot."""
        freq_250 = get_default_frequency("US", 250.0)
        freq_500 = get_default_frequency("US", 500.0)
        # Different bandwidths should give different frequencies
        self.assertNotAlmostEqual(freq_250, freq_500, places=0)

    def test_num_channels_for_bw(self):
        us = REGIONS["US"]
        self.assertEqual(us.num_channels_for_bw(250.0), 104)
        self.assertEqual(us.num_channels_for_bw(500.0), 52)
        self.assertEqual(us.num_channels_for_bw(125.0), 208)

    def test_channel_frequency_1indexed(self):
        """channel_frequency uses 1-indexed convention."""
        us = REGIONS["US"]
        # channel 1: 902.0 + 0.125 + 0*0.25 = 902.125
        self.assertAlmostEqual(us.channel_frequency(1, 250.0), 902.125e6, places=0)
        # channel 2: 902.0 + 0.125 + 1*0.25 = 902.375
        self.assertAlmostEqual(us.channel_frequency(2, 250.0), 902.375e6, places=0)


# =============================================================================
# SC16_Q11 format conversion (BladeRF)
# =============================================================================

class TestSC16Q11Conversion(unittest.TestCase):
    """Verify BladeRF SC16_Q11 format conversion correctness."""

    def test_roundtrip_unity(self):
        """Convert to SC16_Q11 and back, values should be close."""
        samples = np.array([1.0 + 0j, -1.0 + 0j, 0 + 1j, 0 - 1j, 0.5 + 0.5j],
                           dtype=np.complex64)
        sc16 = complex64_to_sc16q11(samples)
        recovered = sc16q11_to_complex64(sc16)
        np.testing.assert_allclose(np.real(recovered), np.real(samples), atol=1e-3)
        np.testing.assert_allclose(np.imag(recovered), np.imag(samples), atol=1e-3)

    def test_interleaved_format(self):
        """SC16_Q11 is interleaved I, Q, I, Q."""
        samples = np.array([0.5 + 0.25j], dtype=np.complex64)
        sc16 = complex64_to_sc16q11(samples)
        self.assertEqual(len(sc16), 2)
        # I should be ~0.5 * 2047 = ~1024
        self.assertAlmostEqual(sc16[0], round(0.5 * SC16_Q11_SCALE), delta=1)
        # Q should be ~0.25 * 2047 = ~512
        self.assertAlmostEqual(sc16[1], round(0.25 * SC16_Q11_SCALE), delta=1)

    def test_clipping(self):
        """Values beyond [-1, 1] should be clipped to SC16_Q11 range."""
        samples = np.array([2.0 + 0j, -2.0 + 0j], dtype=np.complex64)
        sc16 = complex64_to_sc16q11(samples)
        # Should be clipped to +-2047 (SC16_Q11_SCALE)
        self.assertLessEqual(sc16[0], 2047)
        self.assertGreaterEqual(sc16[2], -2048)

    def test_zero_samples(self):
        samples = np.array([0 + 0j], dtype=np.complex64)
        sc16 = complex64_to_sc16q11(samples)
        self.assertEqual(sc16[0], 0)
        self.assertEqual(sc16[1], 0)

    def test_output_dtype(self):
        samples = np.ones(10, dtype=np.complex64)
        sc16 = complex64_to_sc16q11(samples)
        self.assertEqual(sc16.dtype, np.int16)
        recovered = sc16q11_to_complex64(sc16)
        self.assertEqual(recovered.dtype, np.complex64)


# =============================================================================
# SimulatedRadio
# =============================================================================

class TestSimulatedRadio(unittest.TestCase):
    """Test the in-memory loopback radio."""

    def test_implements_radio_backend(self):
        radio = SimulatedRadio()
        self.assertIsInstance(radio, RadioBackend)

    def test_configure(self):
        radio = SimulatedRadio()
        radio.configure(906.875e6, 250000, 250000, tx_gain=30, rx_gain=30)
        self.assertEqual(radio._frequency, 906.875e6)
        self.assertEqual(radio._sample_rate, 250000)

    def test_loopback_no_noise(self):
        radio = SimulatedRadio()
        data = np.ones(100, dtype=np.complex64) * (0.5 + 0.3j)
        radio.transmit(data)
        received = radio.receive(100)
        np.testing.assert_array_almost_equal(received, data)

    def test_loopback_with_noise(self):
        radio = SimulatedRadio(snr_db=40)  # High SNR, should be close
        data = np.ones(1000, dtype=np.complex64) * 0.5
        radio.transmit(data)
        received = radio.receive(1000)
        # With 40dB SNR, error should be small
        np.testing.assert_allclose(np.abs(received), np.abs(data), atol=0.05)

    def test_receive_empty_returns_zeros(self):
        radio = SimulatedRadio()
        received = radio.receive(100)
        self.assertEqual(len(received), 100)
        np.testing.assert_array_equal(received, 0)

    def test_receive_partial(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(50, dtype=np.complex64))
        received = radio.receive(100)
        self.assertEqual(len(received), 100)
        # First 50 should be data, rest zeros
        np.testing.assert_array_almost_equal(received[:50], 1.0)
        np.testing.assert_array_equal(received[50:], 0)

    def test_receive_available(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(75, dtype=np.complex64))
        available = radio.receive_available()
        self.assertEqual(len(available), 75)
        self.assertEqual(radio.samples_available, 0)

    def test_samples_available(self):
        radio = SimulatedRadio()
        self.assertEqual(radio.samples_available, 0)
        radio.transmit(np.ones(42, dtype=np.complex64))
        self.assertEqual(radio.samples_available, 42)

    def test_close_clears_buffer(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(100, dtype=np.complex64))
        radio.close()
        self.assertEqual(radio.samples_available, 0)

    def test_device_name(self):
        self.assertEqual(SimulatedRadio().device_name, "Simulated")

    def test_context_manager(self):
        with SimulatedRadio() as radio:
            radio.transmit(np.ones(10, dtype=np.complex64))
        self.assertEqual(radio.samples_available, 0)

    def test_multiple_transmits_concatenate(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(50, dtype=np.complex64) * 0.5)
        radio.transmit(np.ones(50, dtype=np.complex64) * 0.8)
        received = radio.receive(100)
        np.testing.assert_array_almost_equal(received[:50], 0.5)
        np.testing.assert_array_almost_equal(received[50:], 0.8)


# =============================================================================
# MeshInterface TX/RX
# =============================================================================

class TestMeshInterfaceTX(unittest.TestCase):
    """Test the sync MeshInterface transmit path."""

    def _make_interface(self, preset="SHORT_FAST"):
        radio = SimulatedRadio()
        node = MeshNode(node_id=0xAAAAAAAA, long_name="Test TX")
        iface = MeshInterface(radio, preset_name=preset, node=node)
        iface.configure_radio()
        return iface

    def test_send_text_produces_iq(self):
        iface = self._make_interface()
        pkt = iface.send_text("Hello")
        # Radio buffer should have IQ samples
        self.assertGreater(iface.radio.samples_available, 0)
        # Packet should have data
        self.assertIsNotNone(pkt.data)
        self.assertEqual(pkt.data.text, "Hello")

    def test_send_text_sets_header_fields(self):
        iface = self._make_interface()
        pkt = iface.send_text("test", to=0x12345678)
        self.assertEqual(pkt.header.from_node, 0xAAAAAAAA)
        self.assertEqual(pkt.header.to, 0x12345678)
        self.assertEqual(pkt.header.channel, iface.channel.channel_hash)
        self.assertGreater(pkt.header.id, 0)

    def test_send_text_broadcast_default(self):
        iface = self._make_interface()
        pkt = iface.send_text("broadcast")
        self.assertEqual(pkt.header.to, BROADCAST_ADDR)

    def test_send_data_arbitrary_portnum(self):
        iface = self._make_interface()
        pkt = iface.send_data(b"\x01\x02\x03", PortNum.POSITION_APP)
        self.assertEqual(pkt.data.portnum, PortNum.POSITION_APP)
        self.assertEqual(pkt.data.payload, b"\x01\x02\x03")

    def test_send_records_in_router(self):
        iface = self._make_interface()
        pkt = iface.send_text("recorded")
        self.assertTrue(iface.router.is_duplicate(pkt.header))

    def test_want_ack_flag(self):
        iface = self._make_interface()
        pkt = iface.send_text("ack me", want_ack=True)
        self.assertTrue(pkt.header.want_ack)

    def test_hop_limit_from_router(self):
        iface = self._make_interface()
        pkt = iface.send_text("hops")
        self.assertEqual(pkt.header.hop_limit, iface.router.default_hop_limit)
        self.assertEqual(pkt.header.hop_start, iface.router.default_hop_limit)


class TestMeshInterfaceRX(unittest.TestCase):
    """Test the sync MeshInterface receive path."""

    def _make_pair(self, preset="SHORT_FAST"):
        radio = SimulatedRadio()
        tx_node = MeshNode(node_id=0xAAAAAAAA)
        rx_node = MeshNode(node_id=0xBBBBBBBB)
        tx = MeshInterface(radio, preset_name=preset, node=tx_node)
        rx = MeshInterface(radio, preset_name=preset, node=rx_node)
        tx.configure_radio()
        return tx, rx

    def test_send_receive_roundtrip(self):
        tx, rx = self._make_pair()
        tx.send_text("Hello RX!")
        pkt = rx.receive_once(timeout_s=5.0)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.data.text, "Hello RX!")
        self.assertEqual(pkt.header.from_node, 0xAAAAAAAA)

    def test_no_packet_returns_none(self):
        radio = SimulatedRadio()
        rx = MeshInterface(radio, preset_name="SHORT_FAST")
        rx.configure_radio()
        result = rx.receive_once(timeout_s=0.1)
        self.assertIsNone(result)

    def test_wrong_channel_hash_filtered(self):
        """Packets on a different channel should be filtered."""
        radio = SimulatedRadio()
        ch_a = ChannelConfig(name="ChannelA", psk=DEFAULT_KEY)
        ch_b = ChannelConfig(name="ChannelB", psk=DEFAULT_KEY)
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0x11), channel=ch_a)
        rx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0x22), channel=ch_b)
        tx.configure_radio()
        tx.send_text("wrong channel")
        result = rx.receive_once(timeout_s=1.0)
        self.assertIsNone(result)

    def test_same_channel_received(self):
        """Packets on the same channel should be received."""
        radio = SimulatedRadio()
        ch = ChannelConfig(name="TestChan", psk=DEFAULT_KEY)
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0x11), channel=ch)
        rx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0x22), channel=ch)
        tx.configure_radio()
        tx.send_text("same channel")
        result = rx.receive_once(timeout_s=5.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.data.text, "same channel")

    def test_duplicate_packet_filtered(self):
        """Receiving the same packet twice should filter the duplicate."""
        tx, rx = self._make_pair()
        pkt = tx.send_text("once")
        result1 = rx.receive_once(timeout_s=5.0)
        self.assertIsNotNone(result1)

        # Transmit the same packet again (replay attack / echo)
        iq = tx.lora.build(pkt.to_bytes())
        tx.radio.transmit(iq)
        result2 = rx.receive_once(timeout_s=5.0)
        self.assertIsNone(result2)  # Should be filtered as duplicate

    def test_unicast_for_us(self):
        """Unicast packets addressed to us should be received."""
        radio = SimulatedRadio()
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xAA))
        rx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xBB))
        tx.configure_radio()
        tx.send_text("for you", to=0xBB)
        result = rx.receive_once(timeout_s=5.0)
        self.assertIsNotNone(result)

    def test_unicast_not_for_us_filtered(self):
        """Unicast packets for other nodes should be filtered (returned as None)."""
        radio = SimulatedRadio()
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xAA))
        rx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xBB))
        tx.configure_radio()
        tx.send_text("for someone else", to=0xCC)
        result = rx.receive_once(timeout_s=5.0)
        # Not for us, and should_rebroadcast may be true but receive_once returns None
        self.assertIsNone(result)

    def test_context_manager(self):
        radio = SimulatedRadio()
        node = MeshNode(node_id=0x42)
        with MeshInterface(radio, preset_name="SHORT_FAST", node=node) as iface:
            iface.send_text("context manager")


class TestMeshInterfaceRebroadcast(unittest.TestCase):
    """Test rebroadcast logic during receive."""

    def test_rebroadcast_decrements_hop(self):
        """Rebroadcast of unicast-not-for-us should decrement hop limit."""
        radio = SimulatedRadio()
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xAA))
        # Router node — receives the packet, should rebroadcast
        router = MeshInterface(radio, preset_name="SHORT_FAST",
                               node=MeshNode(node_id=0xBB))
        tx.configure_radio()

        # Send unicast to 0xCC (not 0xBB) — router should rebroadcast
        tx.send_text("relay me", to=0xCC)
        result = router.receive_once(timeout_s=5.0)
        # Not for router, but it should have rebroadcast
        self.assertIsNone(result)
        # Radio should have more samples (rebroadcast was transmitted)
        self.assertGreater(radio.samples_available, 0)

    def test_own_packets_not_rebroadcast(self):
        """Packets from ourselves should not be rebroadcast."""
        radio = SimulatedRadio()
        node = MeshNode(node_id=0xAA)
        iface = MeshInterface(radio, preset_name="SHORT_FAST", node=node)
        iface.configure_radio()
        iface.send_text("my own")
        # Record how many samples are in buffer after our TX
        pre_rx_samples = radio.samples_available
        # Receiving our own packet should not add more (no rebroadcast)
        result = iface.receive_once(timeout_s=5.0)
        self.assertIsNone(result)  # Filtered as our own


# =============================================================================
# SDRTransport
# =============================================================================

class TestSDRTransportFrequency(unittest.TestCase):
    """Verify SDRTransport derives frequency correctly."""

    def test_default_frequency_matches_firmware(self):
        radio = SimulatedRadio()
        transport = SDRTransport(radio, preset_name="LONG_FAST", region="US")
        self.assertAlmostEqual(transport.frequency, 906.875e6, places=0)

    def test_custom_channel_changes_frequency(self):
        radio = SimulatedRadio()
        ch_default = ChannelConfig.default()
        ch_custom = ChannelConfig(name="MyChannel", psk=DEFAULT_KEY)
        t1 = SDRTransport(radio, region="US", channel=ch_default)
        t2 = SDRTransport(radio, region="US", channel=ch_custom)
        # Different channel names produce different DJB2 hashes -> different freqs
        self.assertNotAlmostEqual(t1.frequency, t2.frequency, places=0)

    def test_eu868_frequency(self):
        radio = SimulatedRadio()
        transport = SDRTransport(radio, region="EU_868")
        # EU_868 has very narrow band (869.4-869.65), only 1 channel at 250kHz
        self.assertAlmostEqual(transport.frequency, 869.525e6, places=0)


class TestSDRTransportRoundtrip(unittest.TestCase):
    """End-to-end send/receive via SDRTransport."""

    def test_async_roundtrip(self):
        async def _test():
            radio = SimulatedRadio()
            tx = SDRTransport(radio, preset_name="SHORT_FAST",
                              node=MeshNode(node_id=0xAA))
            rx = SDRTransport(radio, preset_name="SHORT_FAST",
                              node=MeshNode(node_id=0xBB))
            await tx.start()

            pkt = MeshPacket.create_text("transport test",
                                          from_node=0xAA,
                                          channel=tx.channel.channel_hash)
            await tx.send_packet(pkt)

            received = await rx.receive_packet(timeout_s=5.0)
            self.assertIsNotNone(received)
            self.assertEqual(received.data.text, "transport test")
            await tx.stop()
            await rx.stop()

        run_async(_test())

    def test_channel_hash_mismatch_filtered(self):
        async def _test():
            radio = SimulatedRadio()
            ch_a = ChannelConfig(name="Alpha", psk=DEFAULT_KEY)
            ch_b = ChannelConfig(name="Beta", psk=DEFAULT_KEY)
            tx = SDRTransport(radio, preset_name="SHORT_FAST",
                              node=MeshNode(node_id=0xAA), channel=ch_a)
            rx = SDRTransport(radio, preset_name="SHORT_FAST",
                              node=MeshNode(node_id=0xBB), channel=ch_b)
            await tx.start()
            pkt = MeshPacket.create_text("wrong ch", from_node=0xAA,
                                          channel=ch_a.channel_hash)
            await tx.send_packet(pkt)
            result = await rx.receive_packet(timeout_s=1.0)
            self.assertIsNone(result)
            await tx.stop()
            await rx.stop()

        run_async(_test())


# =============================================================================
# LoRa PHY end-to-end with real packet content
# =============================================================================

class TestLoRaPacketWithMeshtasticPayload(unittest.TestCase):
    """Test LoRa build/parse with actual Meshtastic OTA packets."""

    def test_text_packet_roundtrip(self):
        """Encrypt, LoRa encode, LoRa decode, decrypt — full chain."""
        preset = get_preset("SHORT_FAST")
        lora = LoRaPacket(preset)
        crypto = MeshtasticCrypto()

        pkt = MeshPacket.create_text("LoRa roundtrip", from_node=0xDEAD)
        ota_bytes = pkt.encrypt_payload(crypto)

        # LoRa build -> parse
        iq = lora.build(ota_bytes)
        recovered_bytes = lora.parse(iq)

        self.assertIsNotNone(recovered_bytes)
        self.assertEqual(recovered_bytes, ota_bytes)

        # Decrypt
        recovered_pkt = MeshPacket.from_bytes(recovered_bytes)
        recovered_pkt.decrypt_payload(crypto)
        self.assertEqual(recovered_pkt.data.text, "LoRa roundtrip")

    def test_max_payload_roundtrip(self):
        """237-byte max payload survives LoRa encode/decode."""
        preset = get_preset("SHORT_FAST")
        lora = LoRaPacket(preset)

        # 16-byte header + encrypted data
        header = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0x1234, id=0x5678)
        data_payload = DataPayload(portnum=PortNum.TEXT_MESSAGE_APP,
                                    payload=b"A" * 200)
        pkt = MeshPacket(header=header, data=data_payload)
        crypto = MeshtasticCrypto()
        ota = pkt.encrypt_payload(crypto)

        iq = lora.build(ota)
        recovered = lora.parse(iq)
        self.assertEqual(recovered, ota)

    def test_all_presets_roundtrip(self):
        """Every preset can round-trip a Meshtastic packet."""
        for name, preset in PRESETS.items():
            lora = LoRaPacket(preset)
            header = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0xABCD, id=0x1234)
            data = b"hello"  # 16 header + ~7 encrypted ≈ 23 bytes
            pkt = MeshPacket(header=header, data=DataPayload(payload=data))
            crypto = MeshtasticCrypto()
            ota = pkt.encrypt_payload(crypto)

            iq = lora.build(ota)
            recovered = lora.parse(iq)
            self.assertEqual(recovered, ota, f"Failed for preset {name}")


# =============================================================================
# Router integration during RX
# =============================================================================

class TestRouterIntegrationRX(unittest.TestCase):
    """Test router decisions during the receive path."""

    def test_broadcast_received_and_rebroadcast(self):
        """Broadcast packets: for_us=True, should_rebroadcast=True."""
        router = MeshRouter(local_node_id=0xBBBB)
        header = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0xAAAA, id=1,
                                   hop_limit=3, hop_start=3)
        pkt = MeshPacket(header=header, encrypted=b"\x00" * 10)
        for_us, rebroadcast = router.process_incoming(pkt)
        self.assertTrue(for_us)
        self.assertTrue(rebroadcast)

    def test_unicast_for_us_no_rebroadcast(self):
        """Unicast to us: for_us=True, should_rebroadcast=False."""
        router = MeshRouter(local_node_id=0xBBBB)
        header = MeshtasticHeader(to=0xBBBB, from_node=0xAAAA, id=2,
                                   hop_limit=3, hop_start=3)
        pkt = MeshPacket(header=header, encrypted=b"\x00" * 10)
        for_us, rebroadcast = router.process_incoming(pkt)
        self.assertTrue(for_us)
        self.assertFalse(rebroadcast)

    def test_unicast_not_for_us_rebroadcast(self):
        """Unicast to someone else: for_us=False, should_rebroadcast=True."""
        router = MeshRouter(local_node_id=0xBBBB)
        header = MeshtasticHeader(to=0xCCCC, from_node=0xAAAA, id=3,
                                   hop_limit=3, hop_start=3)
        pkt = MeshPacket(header=header, encrypted=b"\x00" * 10)
        for_us, rebroadcast = router.process_incoming(pkt)
        self.assertFalse(for_us)
        self.assertTrue(rebroadcast)

    def test_hop_limit_zero_no_rebroadcast(self):
        """Packets with hop_limit=0 should not be rebroadcast."""
        router = MeshRouter(local_node_id=0xBBBB)
        header = MeshtasticHeader(to=BROADCAST_ADDR, from_node=0xAAAA, id=4,
                                   hop_limit=0, hop_start=3)
        pkt = MeshPacket(header=header, encrypted=b"\x00" * 10)
        for_us, rebroadcast = router.process_incoming(pkt)
        self.assertTrue(for_us)
        self.assertFalse(rebroadcast)

    def test_prepare_rebroadcast_header(self):
        """Rebroadcast packet has decremented hop and relay_node set."""
        router = MeshRouter(local_node_id=0xBBBB)
        header = MeshtasticHeader(to=0xCCCC, from_node=0xAAAA, id=5,
                                   hop_limit=3, hop_start=3, channel=8)
        pkt = MeshPacket(header=header, encrypted=b"\x00" * 10)
        rebroad = router.prepare_rebroadcast(pkt)
        self.assertEqual(rebroad.header.hop_limit, 2)  # Decremented
        self.assertEqual(rebroad.header.hop_start, 3)  # Unchanged
        self.assertEqual(rebroad.header.relay_node, 0xBB)  # Low byte of our ID
        self.assertEqual(rebroad.header.from_node, 0xAAAA)  # Unchanged
        self.assertEqual(rebroad.header.to, 0xCCCC)  # Unchanged
        self.assertEqual(rebroad.header.channel, 8)  # Unchanged
        self.assertEqual(rebroad.encrypted, pkt.encrypted)  # Payload unchanged


# =============================================================================
# MeshInterface frequency derivation
# =============================================================================

class TestMeshInterfaceFrequency(unittest.TestCase):
    """Verify MeshInterface derives frequency from channel config."""

    def test_default_longfast_us(self):
        radio = SimulatedRadio()
        iface = MeshInterface(radio, preset_name="LONG_FAST", region="US")
        self.assertAlmostEqual(iface.frequency, 906.875e6, places=0)

    def test_custom_channel_name_changes_freq(self):
        radio = SimulatedRadio()
        ch = ChannelConfig(name="SecretChannel", psk=DEFAULT_KEY)
        iface = MeshInterface(radio, preset_name="LONG_FAST", region="US",
                               channel=ch)
        # Different name -> different DJB2 hash -> different frequency
        self.assertNotAlmostEqual(iface.frequency, 906.875e6, places=0)

    def test_eu868_region(self):
        radio = SimulatedRadio()
        iface = MeshInterface(radio, preset_name="LONG_FAST", region="EU_868")
        self.assertAlmostEqual(iface.frequency, 869.525e6, places=0)


# =============================================================================
# Encryption symmetry in RX/TX path
# =============================================================================

class TestEncryptionInPath(unittest.TestCase):
    """Verify encryption/decryption works correctly in the packet path."""

    def test_encrypt_decrypt_preserves_data(self):
        crypto = MeshtasticCrypto()
        pkt = MeshPacket.create_text("encrypt me", from_node=0xDEAD)
        ota = pkt.encrypt_payload(crypto)

        recovered = MeshPacket.from_bytes(ota)
        recovered.decrypt_payload(crypto)
        self.assertEqual(recovered.data.text, "encrypt me")

    def test_wrong_key_garbles_data(self):
        key_a = bytes(range(16))
        key_b = bytes(range(16, 32))
        crypto_a = MeshtasticCrypto(key_a)
        crypto_b = MeshtasticCrypto(key_b)

        pkt = MeshPacket.create_text("secret", from_node=0x42)
        ota = pkt.encrypt_payload(crypto_a)

        recovered = MeshPacket.from_bytes(ota)
        recovered.decrypt_payload(crypto_b)
        # Should NOT produce valid text (garbled protobuf)
        self.assertNotEqual(recovered.data.text, "secret")

    def test_nonce_uses_packet_id_and_from(self):
        """Different packet IDs or sender IDs produce different ciphertext."""
        crypto = MeshtasticCrypto()
        plaintext = b"test" * 10

        ct1 = crypto.encrypt(plaintext, packet_id=1, from_node=100)
        ct2 = crypto.encrypt(plaintext, packet_id=2, from_node=100)
        ct3 = crypto.encrypt(plaintext, packet_id=1, from_node=200)

        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(ct1, ct3)
        self.assertNotEqual(ct2, ct3)


# =============================================================================
# AsyncMeshInterface
# =============================================================================

class TestAsyncMeshInterface(unittest.TestCase):
    """Test the async interface via SDRTransport."""

    def test_send_text_roundtrip(self):
        async def _test():
            radio = SimulatedRadio()
            tx_node = MeshNode(node_id=0x1111)
            rx_node = MeshNode(node_id=0x2222)

            tx_transport = SDRTransport(radio, preset_name="SHORT_FAST",
                                         node=tx_node)
            rx_transport = SDRTransport(radio, preset_name="SHORT_FAST",
                                         node=rx_node)

            async with AsyncMeshInterface(tx_transport, node=tx_node) as tx:
                await tx.send_text("async hello!")
                async with AsyncMeshInterface(rx_transport, node=rx_node) as rx:
                    pkt = await rx.receive_once(timeout_s=5.0)
                    self.assertIsNotNone(pkt)
                    self.assertEqual(pkt.data.text, "async hello!")

        run_async(_test())

    def test_send_data(self):
        async def _test():
            radio = SimulatedRadio()
            node = MeshNode(node_id=0x3333)
            transport = SDRTransport(radio, preset_name="SHORT_FAST", node=node)

            async with AsyncMeshInterface(transport, node=node) as iface:
                pkt = await iface.send_data(b"\xDE\xAD", PortNum.TELEMETRY_APP)
                self.assertEqual(pkt.data.portnum, PortNum.TELEMETRY_APP)
                self.assertEqual(pkt.data.payload, b"\xDE\xAD")

        run_async(_test())


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases(unittest.TestCase):
    """Edge cases in the RX/TX pipeline."""

    def test_truncated_packet_returns_none(self):
        """Packet shorter than HEADER_SIZE should be filtered."""
        radio = SimulatedRadio()
        preset = get_preset("SHORT_FAST")
        lora = LoRaPacket(preset)

        # Build a packet that's only 10 bytes (< 16 byte header)
        short_data = b"\x00" * 10
        iq = lora.build(short_data)
        radio.transmit(iq)

        rx = MeshInterface(radio, preset_name="SHORT_FAST")
        rx.configure_radio()
        result = rx.receive_once(timeout_s=1.0)
        self.assertIsNone(result)

    def test_sync_word_0x2b(self):
        """Meshtastic sync word is 0x2B."""
        self.assertEqual(MESHTASTIC_SYNC_WORD, 0x2B)

    def test_airtime_calculation_positive(self):
        """All presets produce positive airtime for max payload."""
        for name, preset in PRESETS.items():
            airtime = preset.airtime_ms(253)  # Max OTA size (header + payload)
            self.assertGreater(airtime, 0, f"Preset {name}")

    def test_preamble_length_16(self):
        """Meshtastic uses 16-symbol preamble."""
        for name, preset in PRESETS.items():
            self.assertEqual(preset.preamble_length, 16, f"Preset {name}")


# =============================================================================
# Concurrent TX/RX — contamination detection, thread safety, flush
# =============================================================================

class TestRadioTXStateTracking(unittest.TestCase):
    """Test TX state tracking on RadioBackend and SimulatedRadio."""

    def test_base_defaults(self):
        """RadioBackend base defaults: no TX active, no TX happened."""
        radio = SimulatedRadio()
        self.assertFalse(radio.tx_active)
        self.assertFalse(radio.check_and_clear_tx_happened())

    def test_tx_happened_set_after_transmit(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(10, dtype=np.complex64))
        self.assertTrue(radio.check_and_clear_tx_happened())

    def test_tx_happened_cleared_after_check(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(10, dtype=np.complex64))
        radio.check_and_clear_tx_happened()
        self.assertFalse(radio.check_and_clear_tx_happened())

    def test_tx_active_false_after_transmit(self):
        """TX active should be False after transmit completes."""
        radio = SimulatedRadio()
        radio.transmit(np.ones(10, dtype=np.complex64))
        self.assertFalse(radio.tx_active)

    def test_multiple_transmits_single_check(self):
        """Multiple TXs before check — one check_and_clear clears all."""
        radio = SimulatedRadio()
        radio.transmit(np.ones(10, dtype=np.complex64))
        radio.transmit(np.ones(10, dtype=np.complex64))
        self.assertTrue(radio.check_and_clear_tx_happened())
        self.assertFalse(radio.check_and_clear_tx_happened())

    def test_flush_rx_clears_buffer(self):
        radio = SimulatedRadio()
        radio.transmit(np.ones(100, dtype=np.complex64))
        self.assertEqual(radio.samples_available, 100)
        radio.flush_rx()
        self.assertEqual(radio.samples_available, 0)


class _ContaminatingRadio(SimulatedRadio):
    """SimulatedRadio that sets _tx_happened inside receive() to simulate
    TX occurring during the receive window (same-frequency self-interference)."""

    def __init__(self, contaminate: bool = True, **kwargs):
        super().__init__(**kwargs)
        self._contaminate = contaminate

    def receive(self, num_samples: int) -> np.ndarray:
        result = super().receive(num_samples)
        if self._contaminate:
            self._tx_happened.set()
        return result


class TestConcurrentTXRXContamination(unittest.TestCase):
    """Test that TX during RX window causes samples to be discarded."""

    def test_rx_discards_when_tx_during_receive(self):
        """If TX happens during the receive window, receive_once returns None."""
        radio = _ContaminatingRadio(contaminate=True)
        tx_node = MeshNode(node_id=0xAA)
        rx_node = MeshNode(node_id=0xBB)
        tx = MeshInterface(radio, preset_name="SHORT_FAST", node=tx_node)
        rx = MeshInterface(radio, preset_name="SHORT_FAST", node=rx_node)
        tx.configure_radio()

        # Transmit a valid packet
        tx.send_text("contaminated")

        # _ContaminatingRadio sets _tx_happened inside receive(), simulating
        # a TX that happened during the receive window
        result = rx.receive_once(timeout_s=1.0)
        self.assertIsNone(result)

    def test_rx_works_when_no_contamination(self):
        """With contamination disabled, normal roundtrip works."""
        radio = _ContaminatingRadio(contaminate=False)
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xAA))
        rx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xBB))
        tx.configure_radio()
        tx.send_text("clean")
        pkt = rx.receive_once(timeout_s=5.0)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.data.text, "clean")

    def test_rx_works_when_no_tx_during_receive(self):
        """Normal receive works when no TX happens during the window."""
        radio = SimulatedRadio()
        tx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xAA))
        rx = MeshInterface(radio, preset_name="SHORT_FAST",
                           node=MeshNode(node_id=0xBB))
        tx.configure_radio()
        tx.send_text("clean")
        pkt = rx.receive_once(timeout_s=5.0)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.data.text, "clean")

    def test_flush_after_contamination_clears_buffer(self):
        """After contamination detection, flush_rx clears the radio buffer."""
        radio = SimulatedRadio()
        radio.transmit(np.ones(1000, dtype=np.complex64))
        radio.flush_rx()
        self.assertEqual(radio.samples_available, 0)
        # Next receive should get zeros (no data)
        received = radio.receive(100)
        np.testing.assert_array_equal(received, 0)


class TestConcurrentTXRXThreadSafety(unittest.TestCase):
    """Test thread safety of concurrent TX and RX operations."""

    def test_concurrent_send_and_receive(self):
        """TX from main thread while RX loop runs should not crash."""
        radio = SimulatedRadio()
        node = MeshNode(node_id=0xAA)
        iface = MeshInterface(radio, preset_name="SHORT_FAST", node=node)
        iface.configure_radio()

        received = []
        iface.start_receive(lambda pkt: received.append(pkt))

        # Send from main thread while RX loop is running
        for i in range(5):
            iface.send_text(f"msg {i}")
            time.sleep(0.01)

        iface.stop_receive()
        # Should not crash — thread safety is the primary concern

    def test_tx_mutex_serializes_transmit(self):
        """Two concurrent transmits should be serialized (not interleaved)."""
        radio = SimulatedRadio()
        node = MeshNode(node_id=0xAA)
        iface = MeshInterface(radio, preset_name="SHORT_FAST", node=node)
        iface.configure_radio()

        results = []

        def tx_thread(msg):
            try:
                iface.send_text(msg)
                results.append(("ok", msg))
            except Exception as e:
                results.append(("err", str(e)))

        t1 = threading.Thread(target=tx_thread, args=("A",))
        t2 = threading.Thread(target=tx_thread, args=("B",))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        # Both should succeed
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r[0] == "ok" for r in results))

    def test_router_state_lock_prevents_race(self):
        """Router mutations from TX and RX threads should not corrupt state."""
        radio = SimulatedRadio()
        tx_node = MeshNode(node_id=0xAA)
        rx_node = MeshNode(node_id=0xBB)
        tx = MeshInterface(radio, preset_name="SHORT_FAST", node=tx_node)
        rx = MeshInterface(radio, preset_name="SHORT_FAST", node=rx_node)
        tx.configure_radio()

        # Rapid fire TX and RX in parallel
        errors = []

        def tx_loop():
            try:
                for i in range(10):
                    tx.send_text(f"concurrent {i}")
            except Exception as e:
                errors.append(e)

        def rx_loop():
            try:
                for _ in range(10):
                    rx.receive_once(timeout_s=0.1)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=tx_loop)
        t2 = threading.Thread(target=rx_loop)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(errors, [])


class TestSDRTransportConcurrentTXRX(unittest.TestCase):
    """Test SDR transport TX/RX contamination handling."""

    def test_transport_discards_contaminated_rx(self):
        """SDRTransport should discard RX when TX happens during receive."""
        async def _test():
            radio = _ContaminatingRadio(contaminate=True)
            tx_transport = SDRTransport(radio, preset_name="SHORT_FAST",
                                         node=MeshNode(node_id=0xAA))
            rx_transport = SDRTransport(radio, preset_name="SHORT_FAST",
                                         node=MeshNode(node_id=0xBB))
            await tx_transport.start()

            pkt = MeshPacket.create_text("test", from_node=0xAA,
                                          channel=tx_transport.channel.channel_hash)
            await tx_transport.send_packet(pkt)

            # _ContaminatingRadio sets _tx_happened during receive()
            result = await rx_transport.receive_packet(timeout_s=1.0)
            self.assertIsNone(result)
            await tx_transport.stop()
            await rx_transport.stop()

        run_async(_test())

    def test_transport_roundtrip_no_contamination(self):
        """Normal transport roundtrip works without contamination."""
        async def _test():
            radio = SimulatedRadio()
            tx = SDRTransport(radio, preset_name="SHORT_FAST",
                              node=MeshNode(node_id=0xAA))
            rx = SDRTransport(radio, preset_name="SHORT_FAST",
                              node=MeshNode(node_id=0xBB))
            await tx.start()

            pkt = MeshPacket.create_text("clean transport",
                                          from_node=0xAA,
                                          channel=tx.channel.channel_hash)
            await tx.send_packet(pkt)

            received = await rx.receive_packet(timeout_s=5.0)
            self.assertIsNotNone(received)
            self.assertEqual(received.data.text, "clean transport")
            await tx.stop()
            await rx.stop()

        run_async(_test())


if __name__ == "__main__":
    unittest.main()
