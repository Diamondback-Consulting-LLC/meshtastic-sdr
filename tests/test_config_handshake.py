"""Tests for BLE config handshake state machine (two-stage protocol)."""

import sys
import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.mesh.node import MeshNode
from meshtastic_sdr.protocol.channels import ChannelConfig
from meshtastic_sdr.ble.config_state import ConfigState
from meshtastic_sdr.ble.protobuf_codec import decode_fromradio
from meshtastic_sdr.ble.constants import CONFIG_NONCE, NODEDB_NONCE


class TestConfigStateStage1:
    """Stage 1 (CONFIG_NONCE=69420): config only, no nodedb."""

    def test_generates_correct_sequence(self):
        """Stage 1 includes my_info, metadata, configs, modules, channels, config_complete."""
        node = MeshNode(node_id=0xDEADBEEF, long_name="SDR Gateway", short_name="GW")
        state = ConfigState(node)

        responses = state.generate_config_response(CONFIG_NONCE)
        decoded = [decode_fromradio(r) for r in responses]

        # First: MyNodeInfo
        assert "my_info" in decoded[0]
        assert decoded[0]["my_info"]["my_node_num"] == 0xDEADBEEF

        # Second: DeviceMetadata
        assert "metadata" in decoded[1]

        # Last: config_complete
        assert "config_complete_id" in decoded[-1]
        assert decoded[-1]["config_complete_id"] == CONFIG_NONCE

    def test_stage1_count(self):
        """Stage 1: 1 my_info + 1 metadata + 1 own_nodeinfo + 10 configs + 15 modules + 8 channels + 1 complete = 37."""
        node = MeshNode(node_id=0x11111111)
        state = ConfigState(node)
        responses = state.generate_config_response(CONFIG_NONCE)
        assert len(responses) == 37

    def test_message_ids_increment(self):
        """Each response has a unique, incrementing message ID."""
        node = MeshNode(node_id=0x11111111)
        state = ConfigState(node)
        responses = state.generate_config_response(CONFIG_NONCE)

        decoded = [decode_fromradio(r) for r in responses]
        ids = [d["id"] for d in decoded]

        assert ids == sorted(ids)
        assert len(set(ids)) == len(ids)


class TestConfigStateStage2:
    """Stage 2 (NODEDB_NONCE=69421): nodedb entries only."""

    def test_nodedb_with_known_nodes(self):
        """Stage 2 returns NodeInfo for self + known nodes + config_complete."""
        node = MeshNode(node_id=0xAAAAAAAA, long_name="Gateway")
        node.update_node(0xBBBBBBBB, long_name="Remote 1", short_name="R1")
        node.update_node(0xCCCCCCCC, long_name="Remote 2", short_name="R2")

        state = ConfigState(node)
        responses = state.generate_config_response(NODEDB_NONCE)

        # self + 2 known nodes + config_complete = 4
        assert len(responses) == 4

        decoded = [decode_fromradio(r) for r in responses]

        # Our own NodeInfo
        assert "node_info" in decoded[0]
        assert decoded[0]["node_info"]["num"] == 0xAAAAAAAA

        # Remote nodes
        remote_nodes = [d for d in decoded if "node_info" in d and d["node_info"]["num"] != 0xAAAAAAAA]
        assert len(remote_nodes) == 2
        names = {d["node_info"]["long_name"] for d in remote_nodes}
        assert names == {"Remote 1", "Remote 2"}

        # Last: config_complete
        assert "config_complete_id" in decoded[-1]
        assert decoded[-1]["config_complete_id"] == NODEDB_NONCE

    def test_empty_node_db(self):
        """With no known nodes, stage 2 is just own NodeInfo + config_complete."""
        node = MeshNode(node_id=0x33333333, long_name="Solo")
        state = ConfigState(node)
        responses = state.generate_config_response(NODEDB_NONCE)
        assert len(responses) == 2

        decoded = [decode_fromradio(r) for r in responses]
        assert "node_info" in decoded[0]
        assert decoded[0]["node_info"]["num"] == 0x33333333
        assert "config_complete_id" in decoded[-1]


class TestConfigStateLegacy:
    """Legacy nonces get combined behavior (both stages)."""

    def test_legacy_nonce_combined(self):
        """Unknown nonce sends config + nodedb + complete."""
        node = MeshNode(node_id=0xDDDDDDDD, long_name="Legacy")
        node.update_node(0xEEEEEEEE, long_name="Remote", short_name="RM")

        state = ConfigState(node)
        responses = state.generate_config_response(12345)

        decoded = [decode_fromradio(r) for r in responses]

        # Should contain my_info, metadata, configs, modules, channels, node_infos, config_complete
        assert "my_info" in decoded[0]
        node_infos = [d for d in decoded if "node_info" in d]
        assert len(node_infos) >= 2  # self + 1 remote
        assert "config_complete_id" in decoded[-1]
        assert decoded[-1]["config_complete_id"] == 12345
