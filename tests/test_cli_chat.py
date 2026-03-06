"""Tests for interactive chat mode."""

import sys
import time
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.cli.chat import MeshChat, _HISTORY_FILE
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.header import MeshtasticHeader
from meshtastic_sdr.protocol.portnums import PortNum
from meshtastic_sdr.mesh.node import NodeInfo


def _make_chat():
    """Create a MeshChat with mock interface."""
    iface = MagicMock()
    iface.node.node_id_str = "!abcd1234"
    iface.node.long_name = "TestNode"
    iface.node.short_name = "TST"
    iface.node.known_nodes = []
    iface.node._node_db = {}
    iface.region = "US"
    iface.preset.name = "LONG_FAST"
    iface.preset.spreading_factor = 11
    iface.preset.bandwidth = 250000
    iface.preset.cr_denom = 5
    iface.frequency = 906875000.0
    iface.channel.display_name = "LongFast"
    iface.channel.channel_hash = 0x08
    iface.channel.index = 0
    iface.channel.has_encryption.return_value = True
    iface.radio.device_name = "SimulatedRadio"

    chat = MeshChat(iface)
    return chat, iface


class TestPrecmd:
    def test_strips_slash(self):
        chat, _ = _make_chat()
        assert chat.precmd("/info") == "info"

    def test_strips_slash_with_args(self):
        chat, _ = _make_chat()
        assert chat.precmd("/send !1234 hello") == "send !1234 hello"

    def test_preserves_plain_text(self):
        chat, _ = _make_chat()
        assert chat.precmd("hello world") == "hello world"

    def test_preserves_empty(self):
        chat, _ = _make_chat()
        assert chat.precmd("") == ""

    def test_strips_slash_with_spaces(self):
        chat, _ = _make_chat()
        assert chat.precmd("  /quit  ") == "quit"


class TestDefault:
    def test_sends_broadcast_text(self):
        chat, iface = _make_chat()
        mock_pkt = MagicMock()
        mock_pkt.header.id = 0x12345678
        iface.send_text.return_value = mock_pkt

        chat.default("Hello mesh!")
        iface.send_text.assert_called_once_with("Hello mesh!")

    def test_ignores_empty(self):
        chat, iface = _make_chat()
        chat.default("")
        iface.send_text.assert_not_called()

    def test_ignores_whitespace(self):
        chat, iface = _make_chat()
        chat.default("   ")
        iface.send_text.assert_not_called()

    def test_handles_send_error(self, capsys):
        chat, iface = _make_chat()
        iface.send_text.side_effect = RuntimeError("radio fail")
        chat.default("test")
        # Should not raise


class TestDoQuit:
    def test_returns_true(self):
        chat, _ = _make_chat()
        assert chat.do_quit("") is True

    def test_exit_returns_true(self):
        chat, _ = _make_chat()
        assert chat.do_exit("") is True

    def test_eof_returns_true(self):
        chat, _ = _make_chat()
        assert chat.do_EOF("") is True


class TestDoInfo:
    def test_runs_without_error(self):
        chat, _ = _make_chat()
        chat.do_info("")


class TestDoNodes:
    def test_no_nodes(self, capsys):
        chat, iface = _make_chat()
        iface.node.known_nodes = []
        chat.do_nodes("")

    def test_with_nodes(self):
        chat, iface = _make_chat()
        node1 = NodeInfo(node_id=0x11111111, long_name="Alice", last_heard=time.time() - 30)
        node2 = NodeInfo(node_id=0x22222222, short_name="BOB", last_heard=time.time() - 3600)
        iface.node.known_nodes = [node1, node2]
        chat.do_nodes("")

    def test_node_never_heard(self):
        chat, iface = _make_chat()
        node = NodeInfo(node_id=0x33333333, last_heard=0)
        iface.node.known_nodes = [node]
        chat.do_nodes("")


class TestDoSend:
    def test_sends_dm_hex(self):
        chat, iface = _make_chat()
        mock_pkt = MagicMock()
        mock_pkt.header.id = 0xAABBCCDD
        iface.send_text.return_value = mock_pkt

        chat.do_send("!11223344 Hello DM")
        iface.send_text.assert_called_once_with("Hello DM", to=0x11223344)

    def test_sends_dm_decimal(self):
        chat, iface = _make_chat()
        mock_pkt = MagicMock()
        mock_pkt.header.id = 0x1234
        iface.send_text.return_value = mock_pkt

        chat.do_send("42 Hello decimal")
        iface.send_text.assert_called_once_with("Hello decimal", to=42)

    def test_missing_args(self):
        chat, iface = _make_chat()
        chat.do_send("")
        iface.send_text.assert_not_called()

    def test_missing_message(self):
        chat, iface = _make_chat()
        chat.do_send("!11223344")
        iface.send_text.assert_not_called()

    def test_invalid_node_id(self):
        chat, iface = _make_chat()
        chat.do_send("!zzzz Hello")
        iface.send_text.assert_not_called()


class TestDoChannel:
    def test_shows_channel_info(self):
        chat, _ = _make_chat()
        chat.do_channel("")


class TestCompleteSend:
    def test_returns_node_ids(self):
        chat, iface = _make_chat()
        node1 = NodeInfo(node_id=0x11111111)
        node2 = NodeInfo(node_id=0x22222222)
        iface.node.known_nodes = [node1, node2]

        result = chat.complete_send("", "", 0, 0)
        assert "!11111111" in result
        assert "!22222222" in result

    def test_filters_by_prefix(self):
        chat, iface = _make_chat()
        node1 = NodeInfo(node_id=0x11111111)
        node2 = NodeInfo(node_id=0x22222222)
        iface.node.known_nodes = [node1, node2]

        result = chat.complete_send("!11", "", 0, 0)
        assert "!11111111" in result
        assert "!22222222" not in result

    def test_empty_node_db(self):
        chat, iface = _make_chat()
        iface.node.known_nodes = []
        result = chat.complete_send("", "", 0, 0)
        assert result == []


class TestCommandMethods:
    """Verify all expected do_* methods exist."""

    def test_has_do_help(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_help")

    def test_has_do_info(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_info")

    def test_has_do_nodes(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_nodes")

    def test_has_do_send(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_send")

    def test_has_do_channel(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_channel")

    def test_has_do_quit(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_quit")

    def test_has_do_exit(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_exit")

    def test_has_do_EOF(self):
        chat, _ = _make_chat()
        assert hasattr(chat, "do_EOF")


class TestEmptyLine:
    def test_does_nothing(self):
        chat, iface = _make_chat()
        result = chat.emptyline()
        assert result is None
        iface.send_text.assert_not_called()


class TestOnPacket:
    def test_formats_and_prints(self):
        chat, iface = _make_chat()
        pkt = MeshPacket(
            header=MeshtasticHeader(from_node=0xDEADBEEF),
            data=DataPayload(portnum=PortNum.TEXT_MESSAGE_APP, payload=b"Incoming!"),
        )
        # Should not raise
        chat._on_packet(pkt)


class TestDoHelp:
    def test_help_output(self):
        chat, _ = _make_chat()
        # Should not raise
        chat.do_help("")

    def test_help_specific_command(self):
        chat, _ = _make_chat()
        chat.do_help("info")
