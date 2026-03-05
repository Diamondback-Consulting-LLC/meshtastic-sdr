"""Tests for meshtastic-sdr persistent config system."""

import base64
import os
import sys
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, "src")

from meshtastic_sdr.config import (
    SDRConfig,
    NodeConfig,
    RadioConfig,
    ChannelSettings,
    BLEConfig,
    MeshConfig,
    _UNSET,
    find_config_file,
    load_config,
    save_config,
    merge_cli_args,
    load_node_identity,
    save_node_identity,
    resolve_psk,
)
from meshtastic_sdr.protocol.encryption import DEFAULT_KEY


# --- SDRConfig.defaults() ---

class TestSDRConfigDefaults:
    def test_defaults_populates_all_fields(self):
        config = SDRConfig.defaults()
        assert config.mode == "ble-gateway"
        assert config.region == "EU_868"
        assert config.preset == "LONG_FAST"
        assert isinstance(config.node, NodeConfig)
        assert isinstance(config.radio, RadioConfig)
        assert isinstance(config.channel, ChannelSettings)
        assert isinstance(config.ble, BLEConfig)
        assert isinstance(config.mesh, MeshConfig)

    def test_defaults_node(self):
        config = SDRConfig.defaults()
        assert config.node.long_name == "SDR Gateway"
        assert config.node.short_name == "SDR"
        assert config.node.id is None

    def test_defaults_radio(self):
        config = SDRConfig.defaults()
        assert config.radio.backend == "bladerf"
        assert config.radio.xb200 == "auto"
        assert config.radio.xb200_filter == "auto_1db"
        assert config.radio.tx_gain == 30
        assert config.radio.rx_gain == 30

    def test_defaults_channel(self):
        config = SDRConfig.defaults()
        assert config.channel.name == "LongFast"
        assert config.channel.psk == "default"
        assert config.channel.index == 0

    def test_defaults_ble(self):
        config = SDRConfig.defaults()
        assert config.ble.gateway_name == "Meshtastic SDR"
        assert config.ble.scan_timeout == 5.0

    def test_defaults_mesh(self):
        config = SDRConfig.defaults()
        assert config.mesh.hop_limit == 3


# --- find_config_file ---

class TestFindConfigFile:
    def test_explicit_cli_path(self, tmp_path):
        cfg = tmp_path / "my.yaml"
        cfg.write_text("mode: listen\n")
        assert find_config_file(str(cfg)) == cfg

    def test_explicit_cli_path_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            find_config_file(str(tmp_path / "nonexistent.yaml"))

    def test_local_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        local = tmp_path / "meshtastic-sdr.yaml"
        local.write_text("mode: listen\n")
        assert find_config_file() == Path("meshtastic-sdr.yaml")

    def test_xdg_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        xdg_dir = tmp_path / "xdg_config" / "meshtastic-sdr"
        xdg_dir.mkdir(parents=True)
        xdg_cfg = xdg_dir / "config.yaml"
        xdg_cfg.write_text("mode: listen\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
        assert find_config_file() == xdg_cfg

    def test_no_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty_xdg"))
        assert find_config_file() is None

    def test_cli_overrides_local(self, tmp_path, monkeypatch):
        """CLI path takes precedence over local file."""
        monkeypatch.chdir(tmp_path)
        local = tmp_path / "meshtastic-sdr.yaml"
        local.write_text("mode: listen\n")
        explicit = tmp_path / "explicit.yaml"
        explicit.write_text("mode: send\n")
        assert find_config_file(str(explicit)) == explicit

    def test_local_overrides_xdg(self, tmp_path, monkeypatch):
        """Local file takes precedence over XDG."""
        monkeypatch.chdir(tmp_path)
        local = tmp_path / "meshtastic-sdr.yaml"
        local.write_text("mode: listen\n")
        xdg_dir = tmp_path / "xdg_config" / "meshtastic-sdr"
        xdg_dir.mkdir(parents=True)
        (xdg_dir / "config.yaml").write_text("mode: send\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
        # Should find local, not XDG
        assert find_config_file() == Path("meshtastic-sdr.yaml")


# --- load_config ---

class TestLoadConfig:
    def test_no_file_returns_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
        config = load_config()
        assert config.mode == "ble-gateway"
        assert config.region == "EU_868"

    def test_full_yaml(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.dump({
            "mode": "listen",
            "region": "US",
            "preset": "SHORT_FAST",
            "node": {"long_name": "Test", "short_name": "TST"},
            "radio": {"backend": "simulated", "tx_gain": 20},
            "channel": {"name": "MyChannel", "psk": "none", "index": 1},
            "ble": {"address": "AA:BB:CC:DD:EE:FF", "scan_timeout": 10.0},
            "mesh": {"hop_limit": 5},
        }))
        config = load_config(str(cfg))
        assert config.mode == "listen"
        assert config.region == "US"
        assert config.preset == "SHORT_FAST"
        assert config.node.long_name == "Test"
        assert config.node.short_name == "TST"
        assert config.radio.backend == "simulated"
        assert config.radio.tx_gain == 20
        assert config.channel.name == "MyChannel"
        assert config.channel.psk == "none"
        assert config.channel.index == 1
        assert config.ble.address == "AA:BB:CC:DD:EE:FF"
        assert config.ble.scan_timeout == 10.0
        assert config.mesh.hop_limit == 5

    def test_partial_yaml_fills_defaults(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("region: US\n")
        config = load_config(str(cfg))
        assert config.region == "US"
        # Everything else should be defaults
        assert config.mode == "ble-gateway"
        assert config.preset == "LONG_FAST"
        assert config.node.long_name == "SDR Gateway"
        assert config.radio.backend == "bladerf"
        assert config.channel.psk == "default"

    def test_empty_yaml_returns_defaults(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("")
        config = load_config(str(cfg))
        assert config.mode == "ble-gateway"

    def test_partial_nested_fills_defaults(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.dump({"radio": {"tx_gain": 15}}))
        config = load_config(str(cfg))
        assert config.radio.tx_gain == 15
        assert config.radio.backend == "bladerf"  # default filled
        assert config.radio.xb200 == "auto"  # default filled


# --- merge_cli_args ---

class TestMergeCLIArgs:
    def test_unset_args_preserved(self):
        config = SDRConfig.defaults()
        config.region = "EU_868"
        args = Namespace(region=_UNSET, preset=_UNSET, name=_UNSET,
                         device=_UNSET, simulate=False)
        merged = merge_cli_args(config, args)
        assert merged.region == "EU_868"

    def test_explicit_args_override(self):
        config = SDRConfig.defaults()
        args = Namespace(region="US", preset="SHORT_FAST", name="MyNode",
                         device="*:serial=abc", simulate=False)
        merged = merge_cli_args(config, args)
        assert merged.region == "US"
        assert merged.preset == "SHORT_FAST"
        assert merged.node.long_name == "MyNode"
        assert merged.radio.device == "*:serial=abc"

    def test_simulate_overrides_backend(self):
        config = SDRConfig.defaults()
        args = Namespace(region=_UNSET, preset=_UNSET, name=_UNSET,
                         device=_UNSET, simulate=True)
        merged = merge_cli_args(config, args)
        assert merged.radio.backend == "simulated"

    def test_mixed_set_and_unset(self):
        config = SDRConfig.defaults()
        config.region = "EU_868"
        config.preset = "LONG_SLOW"
        args = Namespace(region="US", preset=_UNSET, name=_UNSET,
                         device=_UNSET, simulate=False)
        merged = merge_cli_args(config, args)
        assert merged.region == "US"  # overridden
        assert merged.preset == "LONG_SLOW"  # preserved

    def test_missing_attrs_safe(self):
        """merge_cli_args should not crash if args lacks some attributes."""
        config = SDRConfig.defaults()
        args = Namespace(simulate=False)
        merged = merge_cli_args(config, args)
        assert merged.region == "EU_868"


# --- resolve_psk ---

class TestResolvePSK:
    def test_default(self):
        assert resolve_psk("default") == DEFAULT_KEY

    def test_none(self):
        assert resolve_psk("none") == b""

    def test_base64(self):
        key = os.urandom(16)
        encoded = base64.b64encode(key).decode()
        assert resolve_psk(encoded) == key

    def test_base64_32byte(self):
        key = os.urandom(32)
        encoded = base64.b64encode(key).decode()
        assert resolve_psk(encoded) == key


# --- Node identity persistence ---

class TestNodeIdentity:
    def test_save_load_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        save_node_identity(0x1A2B3C4D)
        loaded = load_node_identity()
        assert loaded == 0x1A2B3C4D

    def test_load_missing_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert load_node_identity() is None

    def test_save_creates_directory(self, tmp_path, monkeypatch):
        data_dir = tmp_path / "deep" / "nested"
        monkeypatch.setenv("XDG_DATA_HOME", str(data_dir))
        save_node_identity(0xDEADBEEF)
        assert (data_dir / "meshtastic-sdr" / "node_identity.yaml").is_file()

    def test_overwrite_identity(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        save_node_identity(0x11111111)
        save_node_identity(0x22222222)
        assert load_node_identity() == 0x22222222


# --- Config save/load round-trip ---

class TestConfigRoundTrip:
    def test_save_load_roundtrip(self, tmp_path):
        config = SDRConfig(
            mode="listen",
            region="US",
            preset="SHORT_FAST",
            node=NodeConfig(long_name="RT Node", short_name="RT", id="!deadbeef"),
            radio=RadioConfig(backend="simulated", tx_gain=15, rx_gain=20),
            channel=ChannelSettings(name="Test", psk="none", index=2),
            ble=BLEConfig(address="AA:BB:CC:DD:EE:FF", scan_timeout=3.0),
            mesh=MeshConfig(hop_limit=7),
        )
        path = tmp_path / "roundtrip.yaml"
        save_config(config, path)
        loaded = load_config(str(path))
        assert loaded.mode == "listen"
        assert loaded.region == "US"
        assert loaded.preset == "SHORT_FAST"
        assert loaded.node.long_name == "RT Node"
        assert loaded.node.id == "!deadbeef"
        assert loaded.radio.backend == "simulated"
        assert loaded.radio.tx_gain == 15
        assert loaded.channel.name == "Test"
        assert loaded.channel.psk == "none"
        assert loaded.channel.index == 2
        assert loaded.ble.address == "AA:BB:CC:DD:EE:FF"
        assert loaded.mesh.hop_limit == 7

    def test_save_creates_parent_dirs(self, tmp_path):
        config = SDRConfig.defaults()
        path = tmp_path / "a" / "b" / "config.yaml"
        save_config(config, path)
        assert path.is_file()

    def test_save_default_location(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        config = SDRConfig.defaults()
        path = save_config(config)
        assert path == tmp_path / "meshtastic-sdr" / "config.yaml"
        assert path.is_file()
