"""AdminMessage handler for BLE Gateway mode.

Decodes AdminMessage packets from the Meshtastic app and applies
configuration changes to the running SDR interface. Handles all config
types, module configs, channel operations, owner, and device control.
"""

import logging
import os
import struct
from typing import Optional

from ..protocol.mesh_packet import MeshPacket, DataPayload, _encode_varint, _decode_varint
from ..protocol.portnums import PortNum
from ..protocol.header import MeshtasticHeader, BROADCAST_ADDR
from .constants import (
    ADMIN_GET_CHANNEL_REQUEST, ADMIN_GET_CHANNEL_RESPONSE,
    ADMIN_GET_OWNER_REQUEST, ADMIN_GET_OWNER_RESPONSE,
    ADMIN_GET_CONFIG_REQUEST, ADMIN_GET_CONFIG_RESPONSE,
    ADMIN_GET_MODULE_CONFIG_REQUEST, ADMIN_GET_MODULE_CONFIG_RESPONSE,
    ADMIN_GET_DEVICE_METADATA_REQUEST, ADMIN_GET_DEVICE_METADATA_RESPONSE,
    ADMIN_GET_CANNED_MSG_REQUEST, ADMIN_GET_CANNED_MSG_RESPONSE,
    ADMIN_GET_RINGTONE_REQUEST, ADMIN_GET_RINGTONE_RESPONSE,
    ADMIN_GET_DEVICE_CONN_STATUS_REQUEST,
    ADMIN_SET_OWNER, ADMIN_SET_CHANNEL, ADMIN_SET_CONFIG, ADMIN_SET_MODULE_CONFIG,
    ADMIN_SET_CANNED_MSG, ADMIN_SET_RINGTONE,
    ADMIN_REMOVE_BY_NODENUM, ADMIN_SET_FAVORITE_NODE, ADMIN_REMOVE_FAVORITE_NODE,
    ADMIN_SET_FIXED_POSITION, ADMIN_REMOVE_FIXED_POSITION, ADMIN_SET_TIME_ONLY,
    ADMIN_SET_IGNORED_NODE, ADMIN_REMOVE_IGNORED_NODE, ADMIN_TOGGLE_MUTED_NODE,
    ADMIN_BEGIN_EDIT, ADMIN_COMMIT_EDIT, ADMIN_ADD_CONTACT,
    ADMIN_FACTORY_RESET_DEVICE, ADMIN_FACTORY_RESET_CONFIG,
    ADMIN_REBOOT_SECONDS, ADMIN_REBOOT_OTA_SECONDS, ADMIN_SHUTDOWN_SECONDS,
    ADMIN_NODEDB_RESET, ADMIN_EXIT_SIMULATOR,
    CONFIG_DEVICE, CONFIG_POSITION, CONFIG_POWER, CONFIG_NETWORK,
    CONFIG_DISPLAY, CONFIG_LORA, CONFIG_BLUETOOTH, CONFIG_SECURITY,
    CONFIG_SESSIONKEY, CONFIG_DEVICEUI,
    MODULE_MQTT, MODULE_SERIAL, MODULE_EXTNOTIF, MODULE_STORE_FORWARD,
    MODULE_RANGE_TEST, MODULE_TELEMETRY, MODULE_CANNED_MSG, MODULE_AUDIO,
    MODULE_REMOTE_HW, MODULE_NEIGHBOR_INFO, MODULE_AMBIENT_LIGHTING,
    MODULE_DETECTION_SENSOR, MODULE_PAXCOUNTER, MODULE_STATUS_MESSAGE,
    MODULE_TRAFFIC_MANAGEMENT,
    HW_MODEL_LINUX_NATIVE,
    REGION_CODE_MAP, REGION_NAME_TO_CODE,
    MODEM_PRESET_MAP, PRESET_NAME_TO_CODE,
)
from .protobuf_codec import (
    encode_fromradio_packet,
    encode_config_device, encode_config_position, encode_config_power,
    encode_config_network, encode_config_display, encode_config_lora,
    encode_config_bluetooth, encode_config_security, encode_config_sessionkey,
    encode_module_mqtt, encode_module_serial, encode_module_extnotif,
    encode_module_store_forward, encode_module_range_test, encode_module_telemetry,
    encode_module_canned_message, encode_module_audio, encode_module_remote_hardware,
    encode_module_neighbor_info, encode_module_ambient_lighting,
    encode_module_detection_sensor, encode_module_paxcounter,
    encode_module_status_message, encode_module_traffic_management,
    encode_channel,
    _field_varint, _field_bool, _field_string, _field_bytes, _field_submsg,
    _tag,
)

logger = logging.getLogger(__name__)


# --- Protobuf decoders ---

def decode_admin_message(payload: bytes) -> dict:
    """Decode an AdminMessage protobuf payload.

    Returns dict with the decoded field. Handles all known AdminMessage field types.
    """
    pos = 0
    while pos < len(payload):
        tag_byte, pos = _decode_varint(payload, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # varint
            value, pos = _decode_varint(payload, pos)
            return _dispatch_varint(field_num, value)
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(payload, pos)
            blob = payload[pos:pos + length]
            pos += length
            return _dispatch_submsg(field_num, blob)
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return {}


def _dispatch_varint(field_num: int, value: int) -> dict:
    """Dispatch a varint AdminMessage field."""
    mapping = {
        ADMIN_GET_CHANNEL_REQUEST: ("get_channel_request", None),
        ADMIN_GET_OWNER_REQUEST: ("get_owner_request", True),
        ADMIN_GET_CONFIG_REQUEST: ("get_config_request", None),
        ADMIN_GET_MODULE_CONFIG_REQUEST: ("get_module_config_request", None),
        ADMIN_GET_CANNED_MSG_REQUEST: ("get_canned_message_request", True),
        ADMIN_GET_DEVICE_METADATA_REQUEST: ("get_device_metadata_request", True),
        ADMIN_GET_RINGTONE_REQUEST: ("get_ringtone_request", True),
        ADMIN_GET_DEVICE_CONN_STATUS_REQUEST: ("get_device_connection_status_request", True),
        ADMIN_BEGIN_EDIT: ("begin_edit_settings", True),
        ADMIN_COMMIT_EDIT: ("commit_edit_settings", True),
        ADMIN_REBOOT_SECONDS: ("reboot_seconds", None),
        ADMIN_REBOOT_OTA_SECONDS: ("reboot_ota_seconds", None),
        ADMIN_SHUTDOWN_SECONDS: ("shutdown_seconds", None),
        ADMIN_FACTORY_RESET_DEVICE: ("factory_reset_device", None),
        ADMIN_FACTORY_RESET_CONFIG: ("factory_reset_config", None),
        ADMIN_NODEDB_RESET: ("nodedb_reset", True),
        ADMIN_EXIT_SIMULATOR: ("exit_simulator", True),
        ADMIN_REMOVE_BY_NODENUM: ("remove_by_nodenum", None),
        ADMIN_SET_FAVORITE_NODE: ("set_favorite_node", None),
        ADMIN_REMOVE_FAVORITE_NODE: ("remove_favorite_node", None),
        ADMIN_SET_IGNORED_NODE: ("set_ignored_node", None),
        ADMIN_REMOVE_IGNORED_NODE: ("remove_ignored_node", None),
        ADMIN_TOGGLE_MUTED_NODE: ("toggle_muted_node", None),
        ADMIN_REMOVE_FIXED_POSITION: ("remove_fixed_position", True),
        ADMIN_SET_TIME_ONLY: ("set_time_only", None),
    }
    if field_num in mapping:
        key, fixed_value = mapping[field_num]
        return {key: fixed_value if fixed_value is not None else value}
    return {"unknown_varint_field": field_num, "value": value}


def _dispatch_submsg(field_num: int, blob: bytes) -> dict:
    """Dispatch a length-delimited AdminMessage field."""
    if field_num == ADMIN_SET_CONFIG:
        return {"set_config": _decode_config(blob)}
    elif field_num == ADMIN_SET_CHANNEL:
        return {"set_channel": _decode_channel(blob)}
    elif field_num == ADMIN_SET_OWNER:
        return {"set_owner": _decode_user(blob)}
    elif field_num == ADMIN_SET_MODULE_CONFIG:
        return {"set_module_config": _decode_module_config(blob)}
    elif field_num == ADMIN_GET_CONFIG_RESPONSE:
        return {"get_config_response": _decode_config(blob)}
    elif field_num == ADMIN_GET_CHANNEL_RESPONSE:
        return {"get_channel_response": _decode_channel(blob)}
    elif field_num == ADMIN_GET_OWNER_RESPONSE:
        return {"get_owner_response": _decode_user(blob)}
    elif field_num == ADMIN_GET_MODULE_CONFIG_RESPONSE:
        return {"get_module_config_response": _decode_module_config(blob)}
    elif field_num == ADMIN_SET_FIXED_POSITION:
        return {"set_fixed_position": _decode_generic(blob)}
    elif field_num == ADMIN_ADD_CONTACT:
        return {"add_contact": _decode_generic(blob)}
    elif field_num == ADMIN_SET_CANNED_MSG:
        return {"set_canned_message": blob.decode("utf-8", errors="replace")}
    elif field_num == ADMIN_SET_RINGTONE:
        return {"set_ringtone": blob.decode("utf-8", errors="replace")}
    return {"unknown_submsg_field": field_num, "raw_len": len(blob)}


# --- Config decoders ---

CONFIG_FIELD_TO_NAME = {
    1: "device", 2: "position", 3: "power", 4: "network",
    5: "display", 6: "lora", 7: "bluetooth", 8: "security",
    9: "sessionkey",
}

MODULE_FIELD_TO_NAME = {
    1: "mqtt", 2: "serial", 3: "external_notification", 4: "store_forward",
    5: "range_test", 6: "telemetry", 7: "canned_message", 8: "audio",
    9: "remote_hardware", 10: "neighbor_info", 11: "ambient_lighting",
    12: "detection_sensor", 13: "paxcounter", 14: "statusmessage",
    15: "traffic_management",
}


def _decode_config(data: bytes) -> dict:
    """Decode a Config protobuf (payload_variant oneof)."""
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            name = CONFIG_FIELD_TO_NAME.get(field_num)
            if name == "lora":
                return {"lora": _decode_lora_config(blob)}
            elif name:
                return {name: _decode_generic(blob)}
            return {"config_field": field_num, "raw": blob}
        elif wire_type == 0:
            _, pos = _decode_varint(data, pos)
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return {}


def _decode_module_config(data: bytes) -> dict:
    """Decode a ModuleConfig protobuf (payload_variant oneof)."""
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            name = MODULE_FIELD_TO_NAME.get(field_num, f"module_{field_num}")
            return {name: _decode_generic(blob)}
        elif wire_type == 0:
            _, pos = _decode_varint(data, pos)
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return {}


def _decode_lora_config(data: bytes) -> dict:
    """Decode Config.LoRaConfig fields."""
    result = {"modem_preset": 0, "modem_preset_name": "LONG_FAST",
              "region": 0, "region_name": "UNSET"}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 1:
                result["use_preset"] = bool(value)
            elif field_num == 2:
                result["modem_preset"] = value
                result["modem_preset_name"] = MODEM_PRESET_MAP.get(value, f"UNKNOWN_{value}")
            elif field_num == 3:
                result["bandwidth"] = value
            elif field_num == 4:
                result["spread_factor"] = value
            elif field_num == 5:
                result["coding_rate"] = value
            elif field_num == 7:
                result["region"] = value
                result["region_name"] = REGION_CODE_MAP.get(value, f"UNKNOWN_{value}")
            elif field_num == 8:
                result["hop_limit"] = value
            elif field_num == 9:
                result["tx_enabled"] = bool(value)
            elif field_num == 10:
                result["tx_power"] = value
            elif field_num == 11:
                result["channel_num"] = value
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            pos += length
        elif wire_type == 5:
            if pos + 4 > len(data):
                break
            if field_num == 6:
                result["frequency_offset"] = struct.unpack("<f", data[pos:pos+4])[0]
            elif field_num == 14:
                result["override_frequency"] = struct.unpack("<f", data[pos:pos+4])[0]
            pos += 4
        elif wire_type == 1:
            if pos + 8 > len(data):
                break
            pos += 8
        else:
            break
    return result


def _decode_channel(data: bytes) -> dict:
    """Decode a Channel protobuf."""
    result = {"index": 0, "settings": {}}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 1:
                result["index"] = value
            elif field_num == 3:
                result["role"] = value
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 2:
                result["settings"] = _decode_channel_settings(blob)
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return result


def _decode_channel_settings(data: bytes) -> dict:
    """Decode ChannelSettings fields."""
    result = {}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 1:
                result["channel_num"] = value
            elif field_num == 5:
                result["uplink_enabled"] = bool(value)
            elif field_num == 6:
                result["downlink_enabled"] = bool(value)
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 2:
                result["psk"] = blob
            elif field_num == 3:
                result["name"] = blob.decode("utf-8", errors="replace")
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return result


def _decode_user(data: bytes) -> dict:
    """Decode a User protobuf."""
    result = {}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 5:
                result["hw_model"] = value
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 1:
                result["id"] = blob.decode("utf-8", errors="replace")
            elif field_num == 2:
                result["long_name"] = blob.decode("utf-8", errors="replace")
            elif field_num == 3:
                result["short_name"] = blob.decode("utf-8", errors="replace")
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return result


def _decode_generic(data: bytes) -> dict:
    """Generic protobuf decoder — returns field_num -> value pairs."""
    result = {}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            result[f"field_{field_num}"] = value
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            try:
                result[f"field_{field_num}"] = blob.decode("utf-8")
            except UnicodeDecodeError:
                result[f"field_{field_num}"] = blob
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return result


# --- Response encoders ---

def encode_admin_response(admin_payload: bytes, from_node: int, to_node: int,
                          request_id: int, channel: int = 0) -> MeshPacket:
    """Wrap an AdminMessage response in a MeshPacket."""
    pkt_id = struct.unpack("<I", os.urandom(4))[0]
    header = MeshtasticHeader(
        to=to_node,
        from_node=from_node,
        id=pkt_id,
        hop_limit=3,
        hop_start=3,
        channel=channel,
    )
    data = DataPayload(
        portnum=PortNum.ADMIN_APP,
        payload=admin_payload,
        request_id=request_id,
    )
    return MeshPacket(header=header, data=data)


def encode_lora_config_response(region: str, preset: str, hop_limit: int = 3,
                                tx_power: int = 0, tx_enabled: bool = True) -> bytes:
    """Encode an AdminMessage get_config_response containing LoRaConfig."""
    config_bytes = encode_config_lora(
        region=REGION_NAME_TO_CODE.get(region, 0),
        modem_preset=PRESET_NAME_TO_CODE.get(preset, 0),
        hop_limit=hop_limit,
        tx_enabled=tx_enabled,
        tx_power=tx_power,
    )
    # AdminMessage field 6 = get_config_response (length-delimited)
    return _field_submsg(ADMIN_GET_CONFIG_RESPONSE, config_bytes)


def _encode_config_response(config_bytes: bytes) -> bytes:
    """Wrap Config bytes in AdminMessage get_config_response."""
    return _field_submsg(ADMIN_GET_CONFIG_RESPONSE, config_bytes)


def _encode_module_config_response(module_bytes: bytes) -> bytes:
    """Wrap ModuleConfig bytes in AdminMessage get_module_config_response."""
    return _field_submsg(ADMIN_GET_MODULE_CONFIG_RESPONSE, module_bytes)


def encode_owner_response(long_name: str, short_name: str, node_id: int,
                          hw_model: int = HW_MODEL_LINUX_NATIVE) -> bytes:
    """Encode an AdminMessage get_owner_response with User data."""
    user_parts = []
    user_parts.append(_field_string(1, f"!{node_id:08x}"))
    user_parts.append(_field_string(2, long_name))
    user_parts.append(_field_string(3, short_name))
    user_parts.append(_field_varint(5, hw_model))
    user_bytes = b"".join(user_parts)
    # AdminMessage field 4 = get_owner_response
    return _field_submsg(ADMIN_GET_OWNER_RESPONSE, user_bytes)


def encode_channel_response(index: int, name: str, psk: bytes,
                            role: int = 1) -> bytes:
    """Encode an AdminMessage get_channel_response with Channel data."""
    ch_bytes = encode_channel(index=index, name=name, psk=psk, role=role)
    # AdminMessage field 2 = get_channel_response
    return _field_submsg(ADMIN_GET_CHANNEL_RESPONSE, ch_bytes)


def encode_device_metadata_response(firmware_version: str = "2.5.0.sdr",
                                     hw_model: int = HW_MODEL_LINUX_NATIVE,
                                     has_bluetooth: bool = True,
                                     has_wifi: bool = False) -> bytes:
    """Encode an AdminMessage get_device_metadata_response."""
    parts = []
    parts.append(_field_string(1, firmware_version))
    parts.append(_field_bool(4, has_wifi))
    parts.append(_field_bool(5, has_bluetooth))
    parts.append(_field_varint(9, hw_model))
    meta_bytes = b"".join(parts)
    return _field_submsg(ADMIN_GET_DEVICE_METADATA_RESPONSE, meta_bytes)


# --- AdminHandler class ---

class AdminHandler:
    """Processes AdminMessage packets and applies config changes."""

    def __init__(self, gateway):
        self.gateway = gateway

    def handle_admin_packet(self, packet: MeshPacket) -> list[bytes]:
        """Process an AdminMessage packet and return FromRadio response bytes."""
        if not packet.data or packet.data.portnum != PortNum.ADMIN_APP:
            return []

        admin = decode_admin_message(packet.data.payload)
        if not admin:
            logger.warning("Failed to decode AdminMessage")
            return []

        logger.info("AdminMessage: %s", admin)
        responses = []

        # --- GET requests ---
        if "get_config_request" in admin:
            responses.extend(self._handle_get_config(admin["get_config_request"], packet))

        elif "get_module_config_request" in admin:
            responses.extend(self._handle_get_module_config(admin["get_module_config_request"], packet))

        elif "get_owner_request" in admin:
            responses.extend(self._handle_get_owner(packet))

        elif "get_channel_request" in admin:
            responses.extend(self._handle_get_channel(admin["get_channel_request"], packet))

        elif "get_device_metadata_request" in admin:
            responses.extend(self._handle_get_device_metadata(packet))

        elif "get_canned_message_request" in admin:
            responses.extend(self._handle_get_canned_message(packet))

        elif "get_ringtone_request" in admin:
            responses.extend(self._handle_get_ringtone(packet))

        elif "get_device_connection_status_request" in admin:
            logger.info("get_device_connection_status_request (not implemented)")

        # --- SET requests ---
        elif "set_config" in admin:
            self._handle_set_config(admin["set_config"])

        elif "set_module_config" in admin:
            self._handle_set_module_config(admin["set_module_config"])

        elif "set_owner" in admin:
            self._handle_set_owner(admin["set_owner"])

        elif "set_channel" in admin:
            self._handle_set_channel(admin["set_channel"])

        elif "set_time_only" in admin:
            logger.info("set_time_only: %d (acknowledged)", admin["set_time_only"])

        elif "set_fixed_position" in admin:
            logger.info("set_fixed_position (not applicable for SDR)")

        elif "remove_fixed_position" in admin:
            logger.info("remove_fixed_position (not applicable for SDR)")

        # --- Edit transactions ---
        elif "begin_edit_settings" in admin:
            logger.info("Begin edit settings")

        elif "commit_edit_settings" in admin:
            logger.info("Commit edit settings — persisting config")
            self._persist_config()

        # --- Node management ---
        elif "set_favorite_node" in admin:
            logger.info("set_favorite_node: %d", admin["set_favorite_node"])

        elif "remove_favorite_node" in admin:
            logger.info("remove_favorite_node: %d", admin["remove_favorite_node"])

        elif "set_ignored_node" in admin:
            logger.info("set_ignored_node: %d", admin["set_ignored_node"])

        elif "remove_ignored_node" in admin:
            logger.info("remove_ignored_node: %d", admin["remove_ignored_node"])

        elif "toggle_muted_node" in admin:
            logger.info("toggle_muted_node: %d", admin["toggle_muted_node"])

        elif "remove_by_nodenum" in admin:
            logger.info("remove_by_nodenum: %d", admin["remove_by_nodenum"])

        elif "add_contact" in admin:
            logger.info("add_contact (acknowledged)")

        # --- Device control ---
        elif "reboot_seconds" in admin:
            logger.info("Reboot requested in %ds (ignoring for SDR)", admin["reboot_seconds"])

        elif "shutdown_seconds" in admin:
            logger.info("Shutdown requested in %ds (ignoring for SDR)", admin["shutdown_seconds"])

        elif "factory_reset_device" in admin:
            logger.info("Factory reset requested (ignoring for SDR)")

        elif "factory_reset_config" in admin:
            logger.info("Config reset requested (ignoring for SDR)")

        elif "nodedb_reset" in admin:
            logger.info("NodeDB reset requested")
            self.gateway.node.known_nodes.clear()

        else:
            logger.info("Unhandled admin message: %s", admin)

        return responses

    # --- GET handlers ---

    def _handle_get_config(self, config_type: int, packet: MeshPacket) -> list[bytes]:
        """Respond to get_config_request for any config type."""
        gw = self.gateway
        cfg = gw.config

        config_encoders = {
            CONFIG_DEVICE: lambda: encode_config_device(role=0),
            CONFIG_POSITION: lambda: encode_config_position(gps_mode=2),
            CONFIG_POWER: lambda: encode_config_power(),
            CONFIG_NETWORK: lambda: encode_config_network(),
            CONFIG_DISPLAY: lambda: encode_config_display(),
            CONFIG_LORA: lambda: encode_config_lora(
                region=REGION_NAME_TO_CODE.get(cfg.region if cfg else "EU_868", 3),
                modem_preset=PRESET_NAME_TO_CODE.get(cfg.preset if cfg else "LONG_FAST", 0),
                hop_limit=cfg.mesh.hop_limit if cfg else 3,
                tx_power=cfg.radio.tx_gain if cfg else 0,
            ),
            CONFIG_BLUETOOTH: lambda: encode_config_bluetooth(enabled=True),
            CONFIG_SECURITY: lambda: encode_config_security(),
            CONFIG_SESSIONKEY: lambda: encode_config_sessionkey(),
        }

        encoder = config_encoders.get(config_type)
        if encoder is None:
            logger.info("Unhandled get_config type %d", config_type)
            return []

        admin_payload = _encode_config_response(encoder())
        return [self._make_admin_response(admin_payload, packet)]

    def _handle_get_module_config(self, module_type: int, packet: MeshPacket) -> list[bytes]:
        """Respond to get_module_config_request for any module type."""
        module_encoders = {
            MODULE_MQTT: encode_module_mqtt,
            MODULE_SERIAL: encode_module_serial,
            MODULE_EXTNOTIF: encode_module_extnotif,
            MODULE_STORE_FORWARD: encode_module_store_forward,
            MODULE_RANGE_TEST: encode_module_range_test,
            MODULE_TELEMETRY: encode_module_telemetry,
            MODULE_CANNED_MSG: encode_module_canned_message,
            MODULE_AUDIO: encode_module_audio,
            MODULE_REMOTE_HW: encode_module_remote_hardware,
            MODULE_NEIGHBOR_INFO: encode_module_neighbor_info,
            MODULE_AMBIENT_LIGHTING: encode_module_ambient_lighting,
            MODULE_DETECTION_SENSOR: encode_module_detection_sensor,
            MODULE_PAXCOUNTER: encode_module_paxcounter,
            MODULE_STATUS_MESSAGE: encode_module_status_message,
            MODULE_TRAFFIC_MANAGEMENT: encode_module_traffic_management,
        }

        encoder = module_encoders.get(module_type)
        if encoder is None:
            logger.info("Unhandled get_module_config type %d", module_type)
            return []

        admin_payload = _encode_module_config_response(encoder())
        return [self._make_admin_response(admin_payload, packet)]

    def _handle_get_owner(self, packet: MeshPacket) -> list[bytes]:
        gw = self.gateway
        admin_payload = encode_owner_response(
            long_name=gw.node.long_name,
            short_name=gw.node.short_name,
            node_id=gw.node.node_id,
        )
        return [self._make_admin_response(admin_payload, packet)]

    def _handle_get_channel(self, ch_index: int, packet: MeshPacket) -> list[bytes]:
        gw = self.gateway
        if ch_index == 0:
            # Primary channel (0-based indexing per Meshtastic standard)
            admin_payload = encode_channel_response(
                index=0,
                name=gw.channel.name,
                psk=gw.channel.psk,
            )
        else:
            # Secondary channels — we only support one channel, return empty
            admin_payload = encode_channel_response(index=ch_index, name="", psk=b"", role=0)

        return [self._make_admin_response(admin_payload, packet)]

    def _handle_get_device_metadata(self, packet: MeshPacket) -> list[bytes]:
        admin_payload = encode_device_metadata_response(
            firmware_version="2.5.0.sdr",
            hw_model=HW_MODEL_LINUX_NATIVE,
        )
        return [self._make_admin_response(admin_payload, packet)]

    def _handle_get_canned_message(self, packet: MeshPacket) -> list[bytes]:
        # AdminMessage field 11 = get_canned_message_response (string)
        # _field_string returns b"" for empty strings, so encode explicitly
        admin_payload = _tag(ADMIN_GET_CANNED_MSG_RESPONSE, 2) + b"\x00"
        return [self._make_admin_response(admin_payload, packet)]

    def _handle_get_ringtone(self, packet: MeshPacket) -> list[bytes]:
        # AdminMessage field 15 = get_ringtone_response (string)
        admin_payload = _tag(ADMIN_GET_RINGTONE_RESPONSE, 2) + b"\x00"
        return [self._make_admin_response(admin_payload, packet)]

    # --- SET handlers ---

    def _handle_set_config(self, config: dict) -> None:
        """Apply a set_config AdminMessage."""
        gw = self.gateway
        if "lora" in config:
            self._apply_lora_config(config["lora"])
        elif "device" in config:
            logger.info("set_config device: %s", config["device"])
        elif "bluetooth" in config:
            logger.info("set_config bluetooth: %s", config["bluetooth"])
        elif "position" in config:
            logger.info("set_config position: %s", config["position"])
        elif "power" in config:
            logger.info("set_config power: %s", config["power"])
        elif "network" in config:
            logger.info("set_config network: %s", config["network"])
        elif "display" in config:
            logger.info("set_config display: %s", config["display"])
        elif "security" in config:
            logger.info("set_config security: %s", config["security"])
        else:
            logger.info("set_config unrecognized: %s", config)

    def _apply_lora_config(self, lora: dict) -> None:
        """Apply LoRa config changes."""
        gw = self.gateway
        changed = False

        if "region_name" in lora and lora["region_name"] != "UNSET":
            new_region = lora["region_name"]
            if gw.config and new_region != gw.config.region:
                logger.info("Region: %s -> %s", gw.config.region, new_region)
                gw.config.region = new_region
                changed = True

        if "modem_preset_name" in lora:
            new_preset = lora["modem_preset_name"]
            if gw.config and new_preset != gw.config.preset:
                logger.info("Preset: %s -> %s", gw.config.preset, new_preset)
                gw.config.preset = new_preset
                changed = True

        if "hop_limit" in lora and gw.config:
            gw.config.mesh.hop_limit = lora["hop_limit"]

        if "tx_power" in lora and gw.config:
            gw.config.radio.tx_gain = lora["tx_power"]
            changed = True

        if changed and gw.interface:
            self._reconfigure_radio()

    def _handle_set_module_config(self, module_config: dict) -> None:
        """Apply a set_module_config AdminMessage."""
        logger.info("set_module_config: %s", module_config)

    def _handle_set_owner(self, user: dict) -> None:
        """Apply a set_owner AdminMessage."""
        gw = self.gateway
        if "long_name" in user:
            logger.info("Owner long_name: %s -> %s", gw.node.long_name, user["long_name"])
            gw.node.long_name = user["long_name"]
            if gw.config:
                gw.config.node.long_name = user["long_name"]
        if "short_name" in user:
            logger.info("Owner short_name: %s -> %s", gw.node.short_name, user["short_name"])
            gw.node.short_name = user["short_name"][:4]
            if gw.config:
                gw.config.node.short_name = user["short_name"][:4]

    def _handle_set_channel(self, channel_data: dict) -> None:
        """Apply a set_channel AdminMessage."""
        gw = self.gateway
        index = channel_data.get("index", 0)
        settings = channel_data.get("settings", {})

        if index != 0:
            logger.info("set_channel index %d (secondary channels stored but not used for radio)", index)
            return

        changed = False
        if "name" in settings:
            logger.info("Channel name: %s -> %s", gw.channel.name, settings["name"])
            gw.channel.name = settings["name"]
            if gw.config:
                gw.config.channel.name = settings["name"]
            changed = True

        if "psk" in settings:
            new_psk = settings["psk"]
            logger.info("Channel PSK updated (%d bytes)", len(new_psk))
            gw.channel.psk = new_psk
            changed = True

        if changed and gw.interface:
            from ..protocol.encryption import MeshtasticCrypto
            gw.interface.crypto = MeshtasticCrypto(gw.channel.psk)
            gw.interface.channel = gw.channel

    # --- Radio reconfiguration ---

    def _reconfigure_radio(self) -> None:
        """Reconfigure the SDR radio with new LoRa parameters."""
        gw = self.gateway
        interface = gw.interface
        if not interface or not gw.config:
            return

        from ..lora.params import get_preset
        from ..protocol.channels import get_default_frequency

        new_preset = get_preset(gw.config.preset)
        new_freq = get_default_frequency(gw.config.region, new_preset.bandwidth / 1000)

        logger.info("Reconfiguring radio: %s %s @ %.3f MHz",
                     gw.config.region, gw.config.preset, new_freq / 1e6)

        interface.preset = new_preset
        interface.region = gw.config.region
        interface.frequency = new_freq
        interface.sample_rate = new_preset.bandwidth
        interface.lora = interface.lora.__class__(new_preset, new_preset.bandwidth)
        interface.router.default_hop_limit = gw.config.mesh.hop_limit

        interface.radio.configure(
            frequency=new_freq,
            sample_rate=new_preset.bandwidth,
            bandwidth=new_preset.bandwidth,
            tx_gain=gw.config.radio.tx_gain,
            rx_gain=gw.config.radio.rx_gain,
        )
        logger.info("Radio reconfigured successfully")

    def _persist_config(self) -> None:
        """Persist current config to disk."""
        gw = self.gateway
        if gw.config:
            from ..config import save_config
            try:
                path = save_config(gw.config)
                logger.info("Config persisted to %s", path)
            except Exception as e:
                logger.error("Failed to persist config: %s", e)

    # --- Helpers ---

    def _make_admin_response(self, admin_payload: bytes, packet: MeshPacket) -> bytes:
        """Create a FromRadio-wrapped admin response packet."""
        gw = self.gateway
        resp_packet = encode_admin_response(
            admin_payload,
            from_node=gw.node.node_id,
            to_node=packet.header.from_node,
            request_id=packet.header.id,
            channel=packet.header.channel,
        )
        return encode_fromradio_packet(resp_packet)
