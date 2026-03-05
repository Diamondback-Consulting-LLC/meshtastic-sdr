"""Persistent YAML-based configuration for meshtastic-sdr.

Supports config file search order:
  1. --config <path>  (explicit CLI override)
  2. ./meshtastic-sdr.yaml  (project-local)
  3. ~/.config/meshtastic-sdr/config.yaml  (XDG standard)
  4. No file found -> SDRConfig.defaults()
"""

import base64
import os
from dataclasses import dataclass, field, fields, asdict
from pathlib import Path
from typing import Any

import yaml

from .protocol.encryption import DEFAULT_KEY


# Sentinel for detecting unset CLI args
class _Unset:
    """Sentinel value for unset CLI arguments."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "_UNSET"

    def __bool__(self):
        return False


_UNSET = _Unset()


# --- Dataclasses ---

@dataclass
class NodeConfig:
    long_name: str = "SDR Gateway"
    short_name: str = "SDR"
    id: str | None = None  # "!1a2b3c4d" or None for auto


@dataclass
class RadioConfig:
    backend: str = "bladerf"  # bladerf | soapy | simulated
    device: str = ""
    xb200: str = "auto"  # auto | true | false
    xb200_filter: str = "auto_1db"
    tx_gain: int = 47
    rx_gain: int = 49


@dataclass
class ChannelSettings:
    name: str = "LongFast"
    psk: str = "default"  # default | none | base64-encoded key
    index: int = 0


@dataclass
class BLEConfig:
    address: str = ""
    gateway_name: str = "Meshtastic SDR"
    scan_timeout: float = 5.0


@dataclass
class MeshConfig:
    hop_limit: int = 3


@dataclass
class SDRConfig:
    mode: str = "ble-gateway"
    region: str = "EU_868"
    preset: str = "LONG_FAST"
    node: NodeConfig = field(default_factory=NodeConfig)
    radio: RadioConfig = field(default_factory=RadioConfig)
    channel: ChannelSettings = field(default_factory=ChannelSettings)
    ble: BLEConfig = field(default_factory=BLEConfig)
    mesh: MeshConfig = field(default_factory=MeshConfig)
    # Phone-configurable settings persisted as named-field dicts.
    # Keys: "device", "position", "power", "network", "display", "bluetooth", "security"
    configs: dict = field(default_factory=dict)
    # Module config dicts. Keys: "mqtt", "serial", "telemetry", etc.
    modules: dict = field(default_factory=dict)

    @classmethod
    def defaults(cls) -> "SDRConfig":
        return cls()


# --- Config file search ---

def find_config_file(cli_path: str | Path | None = None) -> Path | None:
    """Find config file using search order: CLI > local > XDG > None."""
    if cli_path is not None:
        p = Path(cli_path)
        if p.is_file():
            return p
        raise FileNotFoundError(f"Config file not found: {cli_path}")

    # Project-local
    local = Path("meshtastic-sdr.yaml")
    if local.is_file():
        return local

    # XDG config
    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    xdg = Path(xdg_config) / "meshtastic-sdr" / "config.yaml"
    if xdg.is_file():
        return xdg

    return None


# --- YAML parsing helpers ---

def _dict_to_dataclass(dc_class, data: dict) -> Any:
    """Recursively map a dict to a dataclass, ignoring unknown keys."""
    if not isinstance(data, dict):
        return dc_class()
    kwargs = {}
    for f in fields(dc_class):
        if f.name in data:
            val = data[f.name]
            # Check if the field type is itself a dataclass
            if hasattr(f.type, "__dataclass_fields__") if isinstance(f.type, type) else False:
                kwargs[f.name] = _dict_to_dataclass(f.type, val if isinstance(val, dict) else {})
            else:
                kwargs[f.name] = val
    return dc_class(**kwargs)


def _merge_defaults(data: dict, defaults: SDRConfig) -> dict:
    """Ensure all top-level and nested keys exist by filling from defaults."""
    default_dict = _config_to_dict(defaults)
    return _deep_merge(default_dict, data)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins)."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _config_to_dict(config: SDRConfig) -> dict:
    """Convert SDRConfig to a plain dict suitable for YAML output."""
    return asdict(config)


# --- Load / Save ---

def load_config(path: str | Path | None = None) -> SDRConfig:
    """Load config from file, falling back to defaults for missing keys.

    Args:
        path: Explicit config file path, or None to search.
    """
    config_file = find_config_file(path)
    if config_file is None:
        return SDRConfig.defaults()

    with open(config_file, "r") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        return SDRConfig.defaults()

    # Merge with defaults so missing keys get filled
    merged = _merge_defaults(raw, SDRConfig.defaults())

    # Build nested dataclasses
    config = SDRConfig(
        mode=merged.get("mode", "ble-gateway"),
        region=merged.get("region", "EU_868"),
        preset=merged.get("preset", "LONG_FAST"),
        node=_dict_to_dataclass(NodeConfig, merged.get("node", {})),
        radio=_dict_to_dataclass(RadioConfig, merged.get("radio", {})),
        channel=_dict_to_dataclass(ChannelSettings, merged.get("channel", {})),
        ble=_dict_to_dataclass(BLEConfig, merged.get("ble", {})),
        mesh=_dict_to_dataclass(MeshConfig, merged.get("mesh", {})),
        configs=merged.get("configs", {}),
        modules=merged.get("modules", {}),
    )
    return config


def save_config(config: SDRConfig, path: str | Path | None = None) -> Path:
    """Save config to YAML file.

    Args:
        path: Explicit path, or None for XDG default location.

    Returns:
        Path where config was written.
    """
    if path is None:
        xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        path = Path(xdg_config) / "meshtastic-sdr" / "config.yaml"

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = _config_to_dict(config)
    with open(path, "w") as f:
        f.write("# meshtastic-sdr configuration\n")
        f.write("# See: meshtastic-sdr init\n\n")
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    return path


# --- CLI merge ---

def merge_cli_args(config: SDRConfig, args) -> SDRConfig:
    """Override config with explicitly-set CLI args (those that aren't _UNSET).

    Args:
        config: Base config loaded from file/defaults.
        args: argparse Namespace with _UNSET sentinels for unset args.

    Returns:
        Updated SDRConfig.
    """
    def _is_set(val) -> bool:
        return not isinstance(val, _Unset)

    if _is_set(getattr(args, "region", _UNSET)):
        config.region = args.region
    if _is_set(getattr(args, "preset", _UNSET)):
        config.preset = args.preset
    if _is_set(getattr(args, "name", _UNSET)):
        config.node.long_name = args.name
    if _is_set(getattr(args, "device", _UNSET)):
        config.radio.device = args.device
    if getattr(args, "simulate", False):
        config.radio.backend = "simulated"

    return config


# --- Node identity persistence ---

def _node_identity_path() -> Path:
    xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    return Path(xdg_data) / "meshtastic-sdr" / "node_identity.yaml"


def load_node_identity() -> int | None:
    """Load persisted node ID, or None if not yet saved."""
    p = _node_identity_path()
    if not p.is_file():
        return None
    with open(p, "r") as f:
        data = yaml.safe_load(f)
    if isinstance(data, dict) and "node_id" in data:
        val = data["node_id"]
        if isinstance(val, str) and val.startswith("!"):
            hex_part = val[1:]
            if not hex_part:
                return None
            return int(hex_part, 16)
        return int(val)
    return None


def save_node_identity(node_id: int) -> None:
    """Persist node ID to data directory."""
    p = _node_identity_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        yaml.dump({"node_id": f"!{node_id:08x}"}, f, default_flow_style=False)


# --- PSK resolution ---

def resolve_psk(psk_str: str) -> bytes:
    """Resolve PSK string to key bytes.

    "default" -> DEFAULT_KEY
    "none" -> b"" (no encryption)
    Otherwise -> base64-decode
    """
    if psk_str == "default":
        return DEFAULT_KEY
    if psk_str == "none":
        return b""
    try:
        return base64.b64decode(psk_str)
    except Exception:
        raise ValueError(f"Invalid PSK: {psk_str!r} — expected 'default', 'none', or base64-encoded key")
