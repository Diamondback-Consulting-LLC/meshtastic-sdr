"""BLE config handshake response generator for Peripheral (Gateway) mode.

Both iOS and Android apps use a two-stage handshake:
  Stage 1 (nonce 69420): MyNodeInfo, DeviceMetadata, all Config sections,
                          all ModuleConfig sections, all Channels, config_complete_id
  Stage 2 (nonce 69421): NodeInfo for each known node, config_complete_id

Between stages, the app sends a Heartbeat ToRadio message.
"""

import logging

from ..mesh.node import MeshNode
from ..protocol.channels import ChannelConfig
from ..protocol.encryption import DEFAULT_KEY
from .constants import (
    HW_MODEL_LINUX_NATIVE, CONFIG_NONCE, NODEDB_NONCE,
    REGION_NAME_TO_CODE, PRESET_NAME_TO_CODE,
)
from .protobuf_codec import (
    encode_fromradio_my_info,
    encode_fromradio_node_info,
    encode_fromradio_config_complete,
    encode_fromradio_metadata,
    encode_fromradio_config,
    encode_fromradio_module_config,
    encode_fromradio_channel,
    encode_config_device,
    encode_config_position,
    encode_config_power,
    encode_config_network,
    encode_config_display,
    encode_config_lora,
    encode_config_bluetooth,
    encode_config_security,
    encode_config_sessionkey,
    encode_module_mqtt,
    encode_module_serial,
    encode_module_extnotif,
    encode_module_store_forward,
    encode_module_range_test,
    encode_module_telemetry,
    encode_module_canned_message,
    encode_module_audio,
    encode_module_remote_hardware,
    encode_module_neighbor_info,
    encode_module_ambient_lighting,
    encode_module_detection_sensor,
    encode_module_paxcounter,
    encode_module_status_message,
    encode_module_traffic_management,
    encode_channel,
)

logger = logging.getLogger(__name__)


class ConfigState:
    """Generates the FromRadio config handshake response sequence."""

    def __init__(self, node: MeshNode, channel: ChannelConfig | None = None,
                 firmware_version: str = "2.5.0.sdr", config=None):
        self.node = node
        self.channel = channel or ChannelConfig.default()
        self.firmware_version = firmware_version
        self.config = config  # SDRConfig
        self._msg_counter = 0

    def _next_id(self) -> int:
        self._msg_counter += 1
        return self._msg_counter

    def generate_config_response(self, config_id: int) -> list[bytes]:
        """Generate the config response for a want_config_id request.

        Stage 1 (CONFIG_NONCE = 69420): Full config, no nodeDB
        Stage 2 (NODEDB_NONCE = 69421): NodeInfo entries only
        Any other nonce: Legacy behavior (both stages combined)
        """
        if config_id == NODEDB_NONCE:
            return self._generate_nodedb_response(config_id)
        elif config_id == CONFIG_NONCE:
            return self._generate_config_only_response(config_id)
        else:
            # Legacy/unknown nonce — send everything
            responses = self._generate_config_only_response(config_id)
            # Insert nodedb before config_complete
            complete_msg = responses.pop()
            responses.extend(self._generate_nodedb_entries())
            responses.append(complete_msg)
            return responses

    def _generate_config_only_response(self, config_id: int) -> list[bytes]:
        """Stage 1: MyInfo, Metadata, Config sections, ModuleConfig, Channels, complete."""
        responses = []

        # 1. MyNodeInfo
        nodedb_count = len(self.node.known_nodes) + 1
        responses.append(encode_fromradio_my_info(
            node_id=self.node.node_id,
            msg_id=self._next_id(),
            nodedb_count=nodedb_count,
        ))

        # 2. DeviceMetadata
        responses.append(encode_fromradio_metadata(
            firmware_version=self.firmware_version,
            hw_model=HW_MODEL_LINUX_NATIVE,
            has_bluetooth=True,
            has_wifi=False,
            msg_id=self._next_id(),
        ))

        # 3. All Config sections
        responses.extend(self._generate_config_sections())

        # 4. All ModuleConfig sections
        responses.extend(self._generate_module_config_sections())

        # 5. All Channels (8 max)
        responses.extend(self._generate_channel_responses())

        # 6. Config complete
        responses.append(encode_fromradio_config_complete(
            config_id=config_id,
            msg_id=self._next_id(),
        ))

        return responses

    def _generate_nodedb_response(self, config_id: int) -> list[bytes]:
        """Stage 2: NodeInfo for all known nodes, then complete."""
        responses = self._generate_nodedb_entries()
        responses.append(encode_fromradio_config_complete(
            config_id=config_id,
            msg_id=self._next_id(),
        ))
        return responses

    def _generate_nodedb_entries(self) -> list[bytes]:
        """Generate NodeInfo FromRadio entries for self + known nodes."""
        responses = []

        # Our own NodeInfo
        responses.append(encode_fromradio_node_info(
            node_id=self.node.node_id,
            long_name=self.node.long_name,
            short_name=self.node.short_name,
            hw_model=HW_MODEL_LINUX_NATIVE,
            msg_id=self._next_id(),
        ))

        # Known nodes
        for known_node in self.node.known_nodes:
            responses.append(encode_fromradio_node_info(
                node_id=known_node.node_id,
                long_name=known_node.long_name,
                short_name=known_node.short_name,
                hw_model=getattr(known_node, 'hardware_model', 0),
                msg_id=self._next_id(),
            ))

        return responses

    def _generate_config_sections(self) -> list[bytes]:
        """Generate FromRadio Config messages for all config types."""
        responses = []
        cfg = self.config

        # Device config
        tzdef = ""
        try:
            import time as _time
            tzdef = _time.tzname[0] if _time.tzname else ""
        except Exception:
            pass
        responses.append(encode_fromradio_config(
            encode_config_device(role=0, tzdef=tzdef),
            msg_id=self._next_id(),
        ))

        # Position config (GPS not present for SDR)
        responses.append(encode_fromradio_config(
            encode_config_position(gps_mode=2),  # NOT_PRESENT
            msg_id=self._next_id(),
        ))

        # Power config
        responses.append(encode_fromradio_config(
            encode_config_power(),
            msg_id=self._next_id(),
        ))

        # Network config
        responses.append(encode_fromradio_config(
            encode_config_network(wifi_enabled=False),
            msg_id=self._next_id(),
        ))

        # Display config
        responses.append(encode_fromradio_config(
            encode_config_display(),
            msg_id=self._next_id(),
        ))

        # LoRa config
        region_code = REGION_NAME_TO_CODE.get(cfg.region if cfg else "EU_868", 3)
        preset_code = PRESET_NAME_TO_CODE.get(cfg.preset if cfg else "LONG_FAST", 0)
        hop_limit = cfg.mesh.hop_limit if cfg else 3
        tx_power = cfg.radio.tx_gain if cfg else 0
        responses.append(encode_fromradio_config(
            encode_config_lora(
                region=region_code,
                modem_preset=preset_code,
                hop_limit=hop_limit,
                tx_enabled=True,
                tx_power=tx_power,
            ),
            msg_id=self._next_id(),
        ))

        # Bluetooth config
        responses.append(encode_fromradio_config(
            encode_config_bluetooth(enabled=True),
            msg_id=self._next_id(),
        ))

        # Security config
        responses.append(encode_fromradio_config(
            encode_config_security(),
            msg_id=self._next_id(),
        ))

        # Session key config (empty)
        responses.append(encode_fromradio_config(
            encode_config_sessionkey(),
            msg_id=self._next_id(),
        ))

        return responses

    def _generate_module_config_sections(self) -> list[bytes]:
        """Generate FromRadio ModuleConfig messages for all module types."""
        responses = []

        module_encoders = [
            encode_module_mqtt,
            encode_module_serial,
            encode_module_extnotif,
            encode_module_store_forward,
            encode_module_range_test,
            encode_module_telemetry,
            encode_module_canned_message,
            encode_module_audio,
            encode_module_remote_hardware,
            encode_module_neighbor_info,
            encode_module_ambient_lighting,
            encode_module_detection_sensor,
            encode_module_paxcounter,
            encode_module_status_message,
            encode_module_traffic_management,
        ]

        for encoder in module_encoders:
            responses.append(encode_fromradio_module_config(
                encoder(),
                msg_id=self._next_id(),
            ))

        return responses

    def _generate_channel_responses(self) -> list[bytes]:
        """Generate FromRadio Channel messages for all 8 channels."""
        responses = []

        # Channel 0 = PRIMARY with our actual config
        responses.append(encode_fromradio_channel(
            encode_channel(
                index=0,
                name=self.channel.name,
                psk=self.channel.psk,
                role=1,  # PRIMARY
            ),
            msg_id=self._next_id(),
        ))

        # Channels 1-7 = DISABLED
        for i in range(1, 8):
            responses.append(encode_fromradio_channel(
                encode_channel(index=i, role=0),  # DISABLED
                msg_id=self._next_id(),
            ))

        return responses
