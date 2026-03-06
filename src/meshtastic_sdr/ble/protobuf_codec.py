"""BLE protobuf codec for ToRadio/FromRadio/MeshPacket messages.

Over LoRa, packets use a 16-byte binary header + encrypted payload.
Over BLE, packets use protobuf-encoded MeshPacket inside ToRadio/FromRadio wrappers.
This module converts between the internal MeshPacket representation and BLE protobuf format.

Supports dual-path: uses official meshtastic.protobuf if available, manual encoding as fallback.
"""

import struct
from typing import Optional

from ..protocol.header import MeshtasticHeader, BROADCAST_ADDR
from ..protocol.mesh_packet import MeshPacket, DataPayload, _encode_varint, _decode_varint

# Try to import official protobuf definitions
try:
    from meshtastic.protobuf.mesh_pb2 import (
        MeshPacket as PbMeshPacket,
        ToRadio as PbToRadio,
        FromRadio as PbFromRadio,
        MyNodeInfo as PbMyNodeInfo,
        NodeInfo as PbNodeInfo,
    )
    HAS_MESH_PB = True
except ImportError:
    HAS_MESH_PB = False


# --- Protobuf field tag helpers ---

def _tag(field_num: int, wire_type: int) -> bytes:
    """Encode a protobuf field tag."""
    return _encode_varint((field_num << 3) | wire_type)


def _field_varint(field_num: int, value: int) -> bytes:
    """Encode a varint field."""
    if value == 0:
        return b""
    return _tag(field_num, 0) + _encode_varint(value)


def _field_bool(field_num: int, value: bool) -> bytes:
    """Encode a bool field (only emits if True)."""
    if not value:
        return b""
    return _tag(field_num, 0) + b"\x01"


def _field_string(field_num: int, value: str) -> bytes:
    """Encode a string field."""
    if not value:
        return b""
    encoded = value.encode("utf-8")
    return _tag(field_num, 2) + _encode_varint(len(encoded)) + encoded


def _field_bytes(field_num: int, value: bytes) -> bytes:
    """Encode a bytes field."""
    if not value:
        return b""
    return _tag(field_num, 2) + _encode_varint(len(value)) + value


def _field_submsg(field_num: int, value: bytes) -> bytes:
    """Encode a sub-message field (always emits, even if empty)."""
    return _tag(field_num, 2) + _encode_varint(len(value)) + value


def _field_fixed32(field_num: int, value: int) -> bytes:
    """Encode a fixed32 field."""
    return _tag(field_num, 5) + struct.pack("<I", value)


def _field_float(field_num: int, value: float) -> bytes:
    """Encode a float field."""
    if value == 0.0:
        return b""
    return _tag(field_num, 5) + struct.pack("<f", value)


def _field_sfixed32(field_num: int, value: int) -> bytes:
    """Encode a sfixed32 field (signed 32-bit little-endian, wire type 5)."""
    return _tag(field_num, 5) + struct.pack("<i", value)


def _field_sint32(field_num: int, value: int) -> bytes:
    """Encode a sint32 field (zigzag encoding)."""
    if value == 0:
        return b""
    zigzag = (value << 1) ^ (value >> 31)
    return _tag(field_num, 0) + _encode_varint(zigzag & 0xFFFFFFFF)


def _field_int32(field_num: int, value: int) -> bytes:
    """Encode an int32 field (sign-extended varint for negative values)."""
    if value == 0:
        return b""
    if value < 0:
        value = value + (1 << 64)
    return _tag(field_num, 0) + _encode_varint(value)


def _field_uint64(field_num: int, value: int) -> bytes:
    """Encode a uint64 field (varint)."""
    if value == 0:
        return b""
    return _tag(field_num, 0) + _encode_varint(value)


# --- Field spec helpers for table-driven encoding ---

def _encode_extra(extra: dict, spec: dict) -> bytes:
    """Encode extra kwargs using a field spec: {name: (field_num, encode_fn)}.

    Emits fields in field-number order, skipping any names not in spec.
    """
    parts = []
    for name in sorted(spec, key=lambda n: spec[n][0]):
        if name in extra:
            field_num, encode_fn = spec[name]
            part = encode_fn(field_num, extra[name])
            if part:
                parts.append(part)
    return b"".join(parts)


def _fromradio_wrap(field_num: int, payload: bytes, msg_id: int = 0) -> bytes:
    """Wrap a payload in a FromRadio message."""
    parts = []
    if msg_id:
        parts.append(b"\x08" + _encode_varint(msg_id))
    parts.append(_field_submsg(field_num, payload))
    return b"".join(parts)


# --- Protobuf MeshPacket encoding/decoding ---

def mesh_packet_to_protobuf(packet: MeshPacket) -> bytes:
    """Encode an internal MeshPacket to protobuf MeshPacket bytes."""
    if HAS_MESH_PB:
        pb = PbMeshPacket()
        pb.from_field = packet.header.from_node
        pb.to = packet.header.to
        pb.channel = packet.header.channel
        pb.id = packet.header.id
        pb.hop_limit = packet.header.hop_limit
        pb.want_ack = packet.header.want_ack
        pb.hop_start = packet.header.hop_start
        if packet.header.via_mqtt:
            pb.via_mqtt = True
        if packet.encrypted:
            pb.encrypted = packet.encrypted
        elif packet.data:
            pb.decoded.portnum = packet.data.portnum
            pb.decoded.payload = packet.data.payload
            pb.decoded.want_response = packet.data.want_response
            if packet.data.dest:
                pb.decoded.dest = packet.data.dest
            if packet.data.source:
                pb.decoded.source = packet.data.source
            if packet.data.request_id:
                pb.decoded.request_id = packet.data.request_id
        return pb.SerializeToString()
    else:
        return _manual_encode_mesh_packet(packet)


def mesh_packet_from_protobuf(data: bytes) -> MeshPacket:
    """Decode protobuf MeshPacket bytes to internal MeshPacket."""
    if HAS_MESH_PB:
        pb = PbMeshPacket()
        pb.ParseFromString(data)
        header = MeshtasticHeader(
            to=pb.to,
            from_node=pb.from_field,
            id=pb.id,
            hop_limit=pb.hop_limit,
            want_ack=pb.want_ack,
            hop_start=pb.hop_start,
            channel=pb.channel,
            via_mqtt=pb.via_mqtt,
        )
        encrypted = bytes(pb.encrypted) if pb.encrypted else b""
        decoded = None
        if pb.HasField("decoded"):
            decoded = DataPayload(
                portnum=pb.decoded.portnum,
                payload=bytes(pb.decoded.payload),
                want_response=pb.decoded.want_response,
                dest=pb.decoded.dest,
                source=pb.decoded.source,
                request_id=pb.decoded.request_id,
            )
        return MeshPacket(header=header, data=decoded, encrypted=encrypted)
    else:
        return _manual_decode_mesh_packet(data)


# --- ToRadio encoding/decoding ---

def encode_toradio_packet(packet: MeshPacket) -> bytes:
    """Encode a MeshPacket wrapped in a ToRadio protobuf."""
    mesh_bytes = mesh_packet_to_protobuf(packet)
    if HAS_MESH_PB:
        tr = PbToRadio()
        tr.packet.ParseFromString(mesh_bytes)
        return tr.SerializeToString()
    return b"\x0a" + _encode_varint(len(mesh_bytes)) + mesh_bytes


def encode_toradio_want_config(config_id: int) -> bytes:
    """Encode a ToRadio want_config_id request."""
    if HAS_MESH_PB:
        tr = PbToRadio()
        tr.want_config_id = config_id
        return tr.SerializeToString()
    return b"\x18" + _encode_varint(config_id)


def encode_toradio_disconnect() -> bytes:
    """Encode a ToRadio disconnect request."""
    if HAS_MESH_PB:
        tr = PbToRadio()
        tr.disconnect = True
        return tr.SerializeToString()
    return b"\x20\x01"


def decode_toradio(data: bytes) -> dict:
    """Decode a ToRadio protobuf message.

    Returns a dict with one of:
      {"packet": MeshPacket}
      {"want_config_id": int}
      {"disconnect": True}
      {"heartbeat": True}
    """
    if HAS_MESH_PB:
        tr = PbToRadio()
        tr.ParseFromString(data)
        which = tr.WhichOneof("payload_variant")
        if which == "packet":
            return {"packet": mesh_packet_from_protobuf(tr.packet.SerializeToString())}
        elif which == "want_config_id":
            return {"want_config_id": tr.want_config_id}
        elif which == "disconnect":
            return {"disconnect": True}
        elif which == "heartbeat":
            return {"heartbeat": True}
        return {}
    return _manual_decode_toradio(data)


# --- FromRadio encoding/decoding ---

def encode_fromradio_packet(packet: MeshPacket, msg_id: int = 0) -> bytes:
    """Encode a FromRadio message containing a MeshPacket.

    FromRadio field 2: packet (MeshPacket, length-delimited)
    """
    mesh_bytes = mesh_packet_to_protobuf(packet)
    if HAS_MESH_PB:
        fr = PbFromRadio()
        fr.id = msg_id
        fr.packet.ParseFromString(mesh_bytes)
        return fr.SerializeToString()
    parts = []
    if msg_id:
        parts.append(b"\x08" + _encode_varint(msg_id))
    # Field 2 (length-delimited): tag = (2 << 3) | 2 = 0x12
    parts.append(b"\x12" + _encode_varint(len(mesh_bytes)) + mesh_bytes)
    return b"".join(parts)


def encode_fromradio_config_complete(config_id: int, msg_id: int = 0) -> bytes:
    """Encode a FromRadio config_complete_id message.

    FromRadio field 7: config_complete_id (varint)
    """
    if HAS_MESH_PB:
        fr = PbFromRadio()
        fr.id = msg_id
        fr.config_complete_id = config_id
        return fr.SerializeToString()
    parts = []
    if msg_id:
        parts.append(b"\x08" + _encode_varint(msg_id))
    # Field 7: tag = (7 << 3) | 0 = 0x38
    parts.append(b"\x38" + _encode_varint(config_id))
    return b"".join(parts)


def encode_fromradio_my_info(node_id: int, msg_id: int = 0,
                              nodedb_count: int = 0,
                              min_app_version: int = 30200,
                              reboot_count: int = 0,
                              device_id: bytes = b"",
                              pio_env: str = "",
                              firmware_edition: int = 0) -> bytes:
    """Encode a FromRadio message containing MyNodeInfo.

    MyNodeInfo fields (from proto):
      1: my_node_num (varint)
      8: reboot_count (varint)
      11: min_app_version (varint)
      12: device_id (bytes)
      13: pio_env (string)
      14: firmware_edition (varint)
      15: nodedb_count (varint)
    FromRadio field 3: my_info (length-delimited)
    """
    if HAS_MESH_PB:
        fr = PbFromRadio()
        fr.id = msg_id
        fr.my_info.my_node_num = node_id
        fr.my_info.min_app_version = min_app_version
        if nodedb_count:
            fr.my_info.nodedb_count = nodedb_count
        if reboot_count:
            fr.my_info.reboot_count = reboot_count
        if device_id:
            fr.my_info.device_id = device_id
        if pio_env:
            fr.my_info.pio_env = pio_env
        if firmware_edition:
            fr.my_info.firmware_edition = firmware_edition
        return fr.SerializeToString()
    # Manual encoding of MyNodeInfo
    info_parts = []
    info_parts.append(b"\x08" + _encode_varint(node_id))
    if reboot_count:
        info_parts.append(_field_varint(8, reboot_count))
    info_parts.append(_tag(11, 0) + _encode_varint(min_app_version))
    if device_id:
        info_parts.append(_field_bytes(12, device_id))
    if pio_env:
        info_parts.append(_field_string(13, pio_env))
    if firmware_edition:
        info_parts.append(_field_varint(14, firmware_edition))
    if nodedb_count:
        info_parts.append(_tag(15, 0) + _encode_varint(nodedb_count))
    info_bytes = b"".join(info_parts)
    return _fromradio_wrap(3, info_bytes, msg_id)


def encode_fromradio_node_info(node_id: int, long_name: str = "",
                                short_name: str = "", hw_model: int = 0,
                                msg_id: int = 0, role: int = 0,
                                public_key: bytes = b"",
                                is_licensed: bool = False,
                                last_heard: int = 0, snr: float = 0.0,
                                hops_away: int = 0, channel: int = 0,
                                via_mqtt: bool = False,
                                is_favorite: bool = False,
                                is_ignored: bool = False,
                                is_muted: bool = False) -> bytes:
    """Encode a FromRadio message containing NodeInfo.

    NodeInfo fields: 1=num, 2=user, 4=snr(float), 5=last_heard(fixed32),
      7=channel, 8=via_mqtt, 9=hops_away, 10=is_favorite, 11=is_ignored, 13=is_muted
    User fields: 1=id, 2=long_name, 3=short_name, 5=hw_model, 6=is_licensed,
      7=role, 8=public_key
    FromRadio field 4: node_info (length-delimited)
    """
    if HAS_MESH_PB:
        fr = PbFromRadio()
        fr.id = msg_id
        fr.node_info.num = node_id
        fr.node_info.user.id = f"!{node_id:08x}"
        fr.node_info.user.long_name = long_name
        fr.node_info.user.short_name = short_name
        fr.node_info.user.hw_model = hw_model
        if role:
            fr.node_info.user.role = role
        if public_key:
            fr.node_info.user.public_key = public_key
        if is_licensed:
            fr.node_info.user.is_licensed = True
        if snr:
            fr.node_info.snr = snr
        if last_heard:
            fr.node_info.last_heard = last_heard
        if channel:
            fr.node_info.channel = channel
        if via_mqtt:
            fr.node_info.via_mqtt = True
        if hops_away:
            fr.node_info.hops_away = hops_away
        if is_favorite:
            fr.node_info.is_favorite = True
        if is_ignored:
            fr.node_info.is_ignored = True
        if is_muted:
            fr.node_info.is_muted = True
        return fr.SerializeToString()
    # Manual: User sub-message
    user_parts = []
    user_id = f"!{node_id:08x}".encode("utf-8")
    user_parts.append(b"\x0a" + _encode_varint(len(user_id)) + user_id)
    if long_name:
        ln = long_name.encode("utf-8")
        user_parts.append(b"\x12" + _encode_varint(len(ln)) + ln)
    if short_name:
        sn = short_name.encode("utf-8")
        user_parts.append(b"\x1a" + _encode_varint(len(sn)) + sn)
    if hw_model:
        user_parts.append(b"\x28" + _encode_varint(hw_model))
    if is_licensed:
        user_parts.append(_field_bool(6, True))
    if role:
        user_parts.append(_field_varint(7, role))
    if public_key:
        user_parts.append(_field_bytes(8, public_key))
    user_bytes = b"".join(user_parts)

    # NodeInfo
    ni_parts = []
    ni_parts.append(b"\x08" + _encode_varint(node_id))
    ni_parts.append(b"\x12" + _encode_varint(len(user_bytes)) + user_bytes)
    if snr:
        ni_parts.append(_field_float(4, snr))
    if last_heard:
        ni_parts.append(_field_fixed32(5, last_heard))
    if channel:
        ni_parts.append(_field_varint(7, channel))
    if via_mqtt:
        ni_parts.append(_field_bool(8, True))
    if hops_away:
        ni_parts.append(_field_varint(9, hops_away))
    if is_favorite:
        ni_parts.append(_field_bool(10, True))
    if is_ignored:
        ni_parts.append(_field_bool(11, True))
    if is_muted:
        ni_parts.append(_field_bool(13, True))
    ni_bytes = b"".join(ni_parts)

    return _fromradio_wrap(4, ni_bytes, msg_id)


def encode_fromradio_metadata(firmware_version: str = "2.6.0.sdr",
                               hw_model: int = 37,
                               has_bluetooth: bool = True,
                               has_wifi: bool = False,
                               has_ethernet: bool = False,
                               can_shutdown: bool = False,
                               has_remote_hardware: bool = False,
                               has_pkc: bool = False,
                               role: int = 0,
                               position_flags: int = 0,
                               excluded_modules: int = 0,
                               device_state_version: int = 24,
                               msg_id: int = 0) -> bytes:
    """Encode a FromRadio DeviceMetadata message.

    DeviceMetadata fields:
      1: firmware_version (string)
      2: device_state_version (varint) — config schema version
      3: canShutdown (bool)
      4: hasWifi (bool)
      5: hasBluetooth (bool)
      6: hasEthernet (bool)
      7: role (DeviceConfig.Role enum, varint)
      8: position_flags (uint32)
      9: hw_model (HardwareModel enum, varint)
      10: hasRemoteHardware (bool)
      11: hasPKC (bool)
      12: excluded_modules (uint32)
    FromRadio field 13: metadata (length-delimited)
    """
    if HAS_MESH_PB:
        fr = PbFromRadio()
        fr.id = msg_id
        fr.metadata.firmware_version = firmware_version
        fr.metadata.device_state_version = device_state_version
        fr.metadata.canShutdown = can_shutdown
        fr.metadata.hasWifi = has_wifi
        fr.metadata.hasBluetooth = has_bluetooth
        fr.metadata.hasEthernet = has_ethernet
        if role:
            fr.metadata.role = role
        if position_flags:
            fr.metadata.position_flags = position_flags
        fr.metadata.hw_model = hw_model
        fr.metadata.hasRemoteHardware = has_remote_hardware
        fr.metadata.hasPKC = has_pkc
        if excluded_modules:
            fr.metadata.excluded_modules = excluded_modules
        return fr.SerializeToString()
    parts = []
    parts.append(_field_string(1, firmware_version))
    parts.append(_tag(2, 0) + _encode_varint(device_state_version))
    parts.append(_field_bool(3, can_shutdown))
    parts.append(_field_bool(4, has_wifi))
    parts.append(_field_bool(5, has_bluetooth))
    parts.append(_field_bool(6, has_ethernet))
    if role:
        parts.append(_field_varint(7, role))
    if position_flags:
        parts.append(_field_varint(8, position_flags))
    parts.append(_tag(9, 0) + _encode_varint(hw_model))
    parts.append(_field_bool(10, has_remote_hardware))
    parts.append(_field_bool(11, has_pkc))
    if excluded_modules:
        parts.append(_field_varint(12, excluded_modules))
    meta_bytes = b"".join(parts)
    return _fromradio_wrap(13, meta_bytes, msg_id)


def encode_fromradio_config(config_payload: bytes, msg_id: int = 0) -> bytes:
    """Encode a FromRadio Config message.

    FromRadio field 5: config (Config, length-delimited)
    """
    return _fromradio_wrap(5, config_payload, msg_id)


def encode_fromradio_module_config(module_payload: bytes, msg_id: int = 0) -> bytes:
    """Encode a FromRadio ModuleConfig message.

    FromRadio field 9: moduleConfig (ModuleConfig, length-delimited)
    """
    return _fromradio_wrap(9, module_payload, msg_id)


def encode_fromradio_channel(channel_payload: bytes, msg_id: int = 0) -> bytes:
    """Encode a FromRadio Channel message.

    FromRadio field 10: channel (Channel, length-delimited)
    """
    return _fromradio_wrap(10, channel_payload, msg_id)


def encode_fromradio_queue_status(free: int = 16, max_to_send: int = 16,
                                   mesh_packet_id: int = 0,
                                   msg_id: int = 0) -> bytes:
    """Encode a FromRadio QueueStatus message.

    QueueStatus fields:
      1: res (int32) - 0 = success
      2: free (uint32)
      3: maxlen (uint32)
      4: mesh_packet_id (uint32)
    FromRadio field 11: queueStatus (length-delimited)
    """
    qs_parts = []
    qs_parts.append(_field_varint(2, free))
    qs_parts.append(_field_varint(3, max_to_send))
    if mesh_packet_id:
        qs_parts.append(_field_varint(4, mesh_packet_id))
    qs_bytes = b"".join(qs_parts)
    return _fromradio_wrap(11, qs_bytes, msg_id)


# --- Config section field specs ---
# Each spec: {param_name: (field_num, encode_fn)}

_DEVICE_EXTRA = {
    "serial_enabled": (2, _field_bool),
    "button_gpio": (4, _field_varint),
    "buzzer_gpio": (5, _field_varint),
    "double_tap_as_button_press": (8, _field_bool),
    "is_managed": (9, _field_bool),
    "disable_triple_click": (10, _field_bool),
    "led_heartbeat_disabled": (12, _field_bool),
    "buzzer_mode": (13, _field_varint),
}

_POSITION_EXTRA = {
    "fixed_position": (3, _field_bool),
    "gps_enabled": (4, _field_bool),
    "gps_update_interval": (5, _field_varint),
    "gps_attempt_time": (6, _field_varint),
    "position_flags": (7, _field_varint),
    "rx_gpio": (8, _field_varint),
    "tx_gpio": (9, _field_varint),
    "broadcast_smart_minimum_distance": (10, _field_varint),
    "broadcast_smart_minimum_interval_secs": (11, _field_varint),
    "gps_en_gpio": (12, _field_varint),
}

_POWER_EXTRA = {
    "adc_multiplier_override": (3, _field_float),
    "wait_bluetooth_secs": (4, _field_varint),
    "sds_secs": (6, _field_varint),
    "ls_secs": (7, _field_varint),
    "min_wake_secs": (8, _field_varint),
    "device_battery_ina_address": (9, _field_varint),
    "powermon_enables": (32, _field_uint64),
}

_NETWORK_EXTRA = {
    "wifi_ssid": (3, _field_string),
    "wifi_psk": (4, _field_string),
    "ntp_server": (5, _field_string),
    "eth_enabled": (6, _field_bool),
    "address_mode": (7, _field_varint),
    # ipv4_config (field 8) is a sub-message — handled specially
    "rsyslog_server": (9, _field_string),
    "enabled_protocols": (10, _field_varint),
    "ipv6_enabled": (11, _field_bool),
}

_DISPLAY_EXTRA = {
    "gps_format": (2, _field_varint),
    "auto_screen_carousel_secs": (3, _field_varint),
    "compass_north_top": (4, _field_bool),
    "flip_screen": (5, _field_bool),
    "oled": (7, _field_varint),
    "displaymode": (8, _field_varint),
    "heading_bold": (9, _field_bool),
    "wake_on_tap_or_motion": (10, _field_bool),
    "compass_orientation": (11, _field_varint),
    "use_12h_clock": (12, _field_bool),
    "use_long_node_name": (13, _field_bool),
    "enable_message_bubbles": (14, _field_bool),
}

_LORA_EXTRA = {
    "override_duty_cycle": (12, _field_bool),
    "sx126x_rx_boosted_gain": (13, _field_bool),
    "pa_fan_disabled": (15, _field_bool),
    "ignore_mqtt": (104, _field_bool),
    "config_ok_to_mqtt": (105, _field_bool),
}

_SECURITY_EXTRA = {
    "public_key": (1, _field_bytes),
    "private_key": (2, _field_bytes),
    # admin_key (field 3) is repeated bytes — handled specially
    "is_managed": (4, _field_bool),
}


# --- Config section encoders ---

def encode_config_device(role: int = 0, tzdef: str = "",
                          node_info_broadcast_secs: int = 900,
                          rebroadcast_mode: int = 0, **extra) -> bytes:
    """Encode Config with DeviceConfig payload.

    Config field 1: device (DeviceConfig, length-delimited)
    """
    parts = []
    parts.append(_field_varint(1, role))
    if rebroadcast_mode:
        parts.append(_field_varint(6, rebroadcast_mode))
    if node_info_broadcast_secs:
        parts.append(_field_varint(7, node_info_broadcast_secs))
    parts.append(_field_string(11, tzdef))
    parts.append(_encode_extra(extra, _DEVICE_EXTRA))
    device_bytes = b"".join(parts)
    return _field_submsg(1, device_bytes)


def encode_config_position(position_broadcast_secs: int = 900,
                            position_broadcast_smart_enabled: bool = True,
                            gps_mode: int = 2, **extra) -> bytes:
    """Encode Config with PositionConfig payload.

    Config field 2: position (PositionConfig, length-delimited)
    """
    parts = []
    if position_broadcast_secs:
        parts.append(_field_varint(1, position_broadcast_secs))
    parts.append(_field_bool(2, position_broadcast_smart_enabled))
    parts.append(_field_varint(13, gps_mode))
    parts.append(_encode_extra(extra, _POSITION_EXTRA))
    pos_bytes = b"".join(parts)
    return _field_submsg(2, pos_bytes)


def encode_config_power(is_power_saving: bool = False,
                         on_battery_shutdown_after_secs: int = 0,
                         **extra) -> bytes:
    """Encode Config with PowerConfig payload.

    Config field 3: power (PowerConfig, length-delimited)
    """
    parts = []
    parts.append(_field_bool(1, is_power_saving))
    if on_battery_shutdown_after_secs:
        parts.append(_field_varint(2, on_battery_shutdown_after_secs))
    parts.append(_encode_extra(extra, _POWER_EXTRA))
    power_bytes = b"".join(parts)
    return _field_submsg(3, power_bytes)


def encode_config_network(wifi_enabled: bool = False, **extra) -> bytes:
    """Encode Config with NetworkConfig payload.

    Config field 4: network (NetworkConfig, length-delimited)
    """
    parts = []
    parts.append(_field_bool(1, wifi_enabled))
    parts.append(_encode_extra(extra, _NETWORK_EXTRA))
    net_bytes = b"".join(parts)
    return _field_submsg(4, net_bytes)


def encode_config_display(screen_on_secs: int = 60,
                           units: int = 0, **extra) -> bytes:
    """Encode Config with DisplayConfig payload.

    Config field 5: display (DisplayConfig, length-delimited)
    """
    parts = []
    if screen_on_secs:
        parts.append(_field_varint(1, screen_on_secs))
    if units:
        parts.append(_field_varint(6, units))
    parts.append(_encode_extra(extra, _DISPLAY_EXTRA))
    display_bytes = b"".join(parts)
    return _field_submsg(5, display_bytes)


def encode_config_lora(region: int = 3, modem_preset: int = 0,
                        hop_limit: int = 3, tx_enabled: bool = True,
                        tx_power: int = 0, use_preset: bool = True,
                        bandwidth: int = 0, spread_factor: int = 0,
                        coding_rate: int = 0, channel_num: int = 0,
                        frequency_offset: float = 0.0,
                        override_frequency: float = 0.0, **extra) -> bytes:
    """Encode Config with LoRaConfig payload.

    Config field 6: lora (LoRaConfig, length-delimited)
    """
    parts = []
    parts.append(_field_bool(1, use_preset))
    # Always emit modem_preset and region (even when 0) so the app populates its UI
    parts.append(_tag(2, 0) + _encode_varint(modem_preset))
    if bandwidth:
        parts.append(_field_varint(3, bandwidth))
    if spread_factor:
        parts.append(_field_varint(4, spread_factor))
    if coding_rate:
        parts.append(_field_varint(5, coding_rate))
    if frequency_offset:
        parts.append(_field_float(6, frequency_offset))
    parts.append(_tag(7, 0) + _encode_varint(region))
    parts.append(_tag(8, 0) + _encode_varint(hop_limit))
    parts.append(_field_bool(9, tx_enabled))
    parts.append(_field_int32(10, tx_power))
    if channel_num:
        parts.append(_field_varint(11, channel_num))
    if override_frequency:
        parts.append(_field_float(14, override_frequency))
    parts.append(_encode_extra(extra, _LORA_EXTRA))
    # ignore_incoming (field 103) is repeated uint32
    if "ignore_incoming" in extra:
        for node_id in extra["ignore_incoming"]:
            parts.append(_field_varint(103, node_id))
    lora_bytes = b"".join(parts)
    return _field_submsg(6, lora_bytes)


def encode_config_bluetooth(enabled: bool = True, mode: int = 0,
                              fixed_pin: int = 123456, **extra) -> bytes:
    """Encode Config with BluetoothConfig payload.

    Config field 7: bluetooth (BluetoothConfig, length-delimited)
    BluetoothConfig: 1=enabled, 2=mode, 3=fixed_pin
    """
    parts = []
    parts.append(_field_bool(1, enabled))
    if mode:
        parts.append(_field_varint(2, mode))
    if fixed_pin:
        parts.append(_field_varint(3, fixed_pin))
    bt_bytes = b"".join(parts)
    return _field_submsg(7, bt_bytes)


def encode_config_security(serial_enabled: bool = True,
                            debug_log_api_enabled: bool = True,
                            admin_channel_enabled: bool = False,
                            **extra) -> bytes:
    """Encode Config with SecurityConfig payload.

    Config field 8: security (SecurityConfig, length-delimited)
    """
    parts = []
    parts.append(_encode_extra(extra, _SECURITY_EXTRA))
    # admin_key (field 3) is repeated bytes
    if "admin_key" in extra:
        for key in extra["admin_key"]:
            parts.append(_field_bytes(3, key))
    parts.append(_field_bool(5, serial_enabled))
    parts.append(_field_bool(6, debug_log_api_enabled))
    parts.append(_field_bool(8, admin_channel_enabled))
    sec_bytes = b"".join(parts)
    return _field_submsg(8, sec_bytes)


def encode_config_sessionkey() -> bytes:
    """Encode Config with empty SessionkeyConfig payload.

    Config field 9: sessionkey (SessionkeyConfig, length-delimited)
    """
    return _field_submsg(9, b"")


def encode_config_deviceui() -> bytes:
    """Encode Config with empty DeviceUIConfig payload.

    Config field 10: deviceui (DeviceUIConfig, length-delimited)
    """
    return _field_submsg(10, b"")


# --- ModuleConfig field specs ---

_MQTT_EXTRA = {
    "address": (2, _field_string),
    "username": (3, _field_string),
    "password": (4, _field_string),
    "encryption_enabled": (5, _field_bool),
    "json_enabled": (6, _field_bool),
    "tls_enabled": (7, _field_bool),
    "root": (8, _field_string),
    "map_reporting_enabled": (10, _field_bool),
    # map_report_settings (field 11) is a sub-message — stored as raw if set
}

_SERIAL_EXTRA = {
    "echo": (2, _field_bool),
    "rxd": (3, _field_varint),
    "txd": (4, _field_varint),
    "baud": (5, _field_varint),
    "timeout": (6, _field_varint),
    "mode": (7, _field_varint),
    "override_console_serial_port": (8, _field_bool),
}

_EXTNOTIF_EXTRA = {
    "output_ms": (2, _field_varint),
    "output": (3, _field_varint),
    "active": (4, _field_bool),
    "alert_message": (5, _field_bool),
    "alert_bell": (6, _field_bool),
    "use_pwm": (7, _field_bool),
    "output_vibra": (8, _field_varint),
    "output_buzzer": (9, _field_varint),
    "alert_message_vibra": (10, _field_bool),
    "alert_message_buzzer": (11, _field_bool),
    "alert_bell_vibra": (12, _field_bool),
    "alert_bell_buzzer": (13, _field_bool),
    "nag_timeout": (14, _field_varint),
    "use_i2s_as_buzzer": (15, _field_bool),
}

_STORE_FORWARD_EXTRA = {
    "heartbeat": (2, _field_bool),
    "records": (3, _field_varint),
    "history_return_max": (4, _field_varint),
    "history_return_window": (5, _field_varint),
    "is_server": (6, _field_bool),
}

_RANGE_TEST_EXTRA = {
    "sender": (2, _field_varint),
    "save": (3, _field_bool),
    "clear_on_reboot": (4, _field_bool),
}

_TELEMETRY_EXTRA = {
    "environment_measurement_enabled": (3, _field_bool),
    "environment_screen_enabled": (4, _field_bool),
    "environment_display_fahrenheit": (5, _field_bool),
    "air_quality_enabled": (6, _field_bool),
    "air_quality_interval": (7, _field_varint),
    "power_measurement_enabled": (8, _field_bool),
    "power_update_interval": (9, _field_varint),
    "power_screen_enabled": (10, _field_bool),
    "health_measurement_enabled": (11, _field_bool),
    "health_update_interval": (12, _field_varint),
    "health_screen_enabled": (13, _field_bool),
    "device_telemetry_enabled": (14, _field_bool),
    "air_quality_screen_enabled": (15, _field_bool),
}

_CANNED_MSG_EXTRA = {
    "rotary1_enabled": (1, _field_bool),
    "inputbroker_pin_a": (2, _field_varint),
    "inputbroker_pin_b": (3, _field_varint),
    "inputbroker_pin_press": (4, _field_varint),
    "inputbroker_event_cw": (5, _field_varint),
    "inputbroker_event_ccw": (6, _field_varint),
    "inputbroker_event_press": (7, _field_varint),
    "updown1_enabled": (8, _field_bool),
    "allow_input_source": (10, _field_string),
    "send_bell": (11, _field_bool),
}

_AUDIO_EXTRA = {
    "ptt_pin": (2, _field_varint),
    "bitrate": (3, _field_varint),
    "i2s_ws": (4, _field_varint),
    "i2s_sd": (5, _field_varint),
    "i2s_din": (6, _field_varint),
    "i2s_sck": (7, _field_varint),
}

_REMOTE_HW_EXTRA = {
    "allow_undefined_pin_access": (2, _field_bool),
    # available_pins (field 3) is repeated sub-message — not handled
}

_NEIGHBOR_INFO_EXTRA = {
    "transmit_over_lora": (3, _field_bool),
}

_AMBIENT_LIGHTING_FIELDS = {
    "led_state": (1, _field_bool),
    "current": (2, _field_varint),
    "red": (3, _field_varint),
    "green": (4, _field_varint),
    "blue": (5, _field_varint),
}

_DETECTION_SENSOR_EXTRA = {
    "minimum_broadcast_secs": (2, _field_varint),
    "state_broadcast_secs": (3, _field_varint),
    "send_bell": (4, _field_bool),
    "name": (5, _field_string),
    "monitor_pin": (6, _field_varint),
    "detection_trigger_type": (7, _field_varint),
    "use_pullup": (8, _field_bool),
}

_PAXCOUNTER_EXTRA = {
    "paxcounter_update_interval": (2, _field_varint),
    "wifi_threshold": (3, _field_int32),
    "ble_threshold": (4, _field_int32),
}

_TRAFFIC_MGMT_EXTRA = {
    "position_dedup_enabled": (2, _field_bool),
    "position_precision_bits": (3, _field_varint),
    "position_min_interval_secs": (4, _field_varint),
    "nodeinfo_direct_response": (5, _field_bool),
    "nodeinfo_direct_response_max_hops": (6, _field_varint),
    "rate_limit_enabled": (7, _field_bool),
    "rate_limit_window_secs": (8, _field_varint),
    "rate_limit_max_packets": (9, _field_varint),
    "drop_unknown_enabled": (10, _field_bool),
    "unknown_packet_threshold": (11, _field_varint),
    "exhaust_hop_telemetry": (12, _field_bool),
    "exhaust_hop_position": (13, _field_bool),
    "router_preserve_hops": (14, _field_bool),
}


# --- ModuleConfig section encoders ---

def encode_module_mqtt(enabled: bool = False,
                        proxy_to_client_enabled: bool = False,
                        **extra) -> bytes:
    """Encode ModuleConfig with MQTTConfig.

    ModuleConfig field 1: mqtt (length-delimited)
    MQTTConfig: 1=enabled, 9=proxy_to_client_enabled
    """
    parts = []
    parts.append(_field_bool(1, enabled))
    parts.append(_field_bool(9, proxy_to_client_enabled))
    parts.append(_encode_extra(extra, _MQTT_EXTRA))
    mqtt_bytes = b"".join(parts)
    return _field_submsg(1, mqtt_bytes)


def encode_module_serial(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 2: serial"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _SERIAL_EXTRA)]
    return _field_submsg(2, b"".join(parts))


def encode_module_extnotif(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 3: external_notification"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _EXTNOTIF_EXTRA)]
    return _field_submsg(3, b"".join(parts))


def encode_module_store_forward(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 4: store_forward"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _STORE_FORWARD_EXTRA)]
    return _field_submsg(4, b"".join(parts))


def encode_module_range_test(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 5: range_test"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _RANGE_TEST_EXTRA)]
    return _field_submsg(5, b"".join(parts))


def encode_module_telemetry(device_update_interval: int = 900,
                             environment_update_interval: int = 900,
                             **extra) -> bytes:
    """ModuleConfig field 6: telemetry"""
    parts = []
    if device_update_interval:
        parts.append(_field_varint(1, device_update_interval))
    if environment_update_interval:
        parts.append(_field_varint(2, environment_update_interval))
    parts.append(_encode_extra(extra, _TELEMETRY_EXTRA))
    return _field_submsg(6, b"".join(parts))


def encode_module_canned_message(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 7: canned_message"""
    parts = [_encode_extra(extra, _CANNED_MSG_EXTRA), _field_bool(9, enabled)]
    return _field_submsg(7, b"".join(parts))


def encode_module_audio(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 8: audio (codec2_enabled=field 1)"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _AUDIO_EXTRA)]
    return _field_submsg(8, b"".join(parts))


def encode_module_remote_hardware(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 9: remote_hardware"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _REMOTE_HW_EXTRA)]
    return _field_submsg(9, b"".join(parts))


def encode_module_neighbor_info(enabled: bool = False,
                                 update_interval: int = 900,
                                 **extra) -> bytes:
    """ModuleConfig field 10: neighbor_info"""
    parts = []
    parts.append(_field_bool(1, enabled))
    if update_interval:
        parts.append(_field_varint(2, update_interval))
    parts.append(_encode_extra(extra, _NEIGHBOR_INFO_EXTRA))
    return _field_submsg(10, b"".join(parts))


def encode_module_ambient_lighting(**kwargs) -> bytes:
    """ModuleConfig field 11: ambient_lighting"""
    return _field_submsg(11, _encode_extra(kwargs, _AMBIENT_LIGHTING_FIELDS))


def encode_module_detection_sensor(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 12: detection_sensor"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _DETECTION_SENSOR_EXTRA)]
    return _field_submsg(12, b"".join(parts))


def encode_module_paxcounter(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 13: paxcounter"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _PAXCOUNTER_EXTRA)]
    return _field_submsg(13, b"".join(parts))


def encode_module_status_message(node_status: str = "", **extra) -> bytes:
    """ModuleConfig field 14: statusmessage"""
    return _field_submsg(14, _field_string(1, node_status))


def encode_module_traffic_management(enabled: bool = False, **extra) -> bytes:
    """ModuleConfig field 15: traffic_management"""
    parts = [_field_bool(1, enabled), _encode_extra(extra, _TRAFFIC_MGMT_EXTRA)]
    return _field_submsg(15, b"".join(parts))


# --- Channel encoder ---

def encode_channel(index: int, name: str = "", psk: bytes = b"",
                    role: int = 0, uplink_enabled: bool = False,
                    downlink_enabled: bool = False,
                    channel_num: int = 0, id: int = 0) -> bytes:
    """Encode a Channel protobuf message.

    Channel: 1=index, 2=settings, 3=role
    ChannelSettings: 1=channel_num, 2=psk, 3=name, 4=id(fixed32),
                     5=uplink_enabled, 6=downlink_enabled
    """
    settings_parts = []
    if channel_num:
        settings_parts.append(_field_varint(1, channel_num))
    if psk:
        settings_parts.append(_field_bytes(2, psk))
    if name:
        settings_parts.append(_field_string(3, name))
    if id:
        settings_parts.append(_field_fixed32(4, id))
    if uplink_enabled:
        settings_parts.append(_field_bool(5, uplink_enabled))
    if downlink_enabled:
        settings_parts.append(_field_bool(6, downlink_enabled))
    settings_bytes = b"".join(settings_parts)

    ch_parts = []
    # Always emit index and role (even when 0) so the app knows which channel
    ch_parts.append(_tag(1, 0) + _encode_varint(index))
    if settings_bytes:
        ch_parts.append(_field_submsg(2, settings_bytes))
    ch_parts.append(_tag(3, 0) + _encode_varint(role))
    return b"".join(ch_parts)


# --- FromRadio decode ---

def decode_fromradio(data: bytes) -> dict:
    """Decode a FromRadio protobuf message."""
    if HAS_MESH_PB:
        fr = PbFromRadio()
        fr.ParseFromString(data)
        result = {"id": fr.id}
        which = fr.WhichOneof("payload_variant")
        if which == "packet":
            result["packet"] = mesh_packet_from_protobuf(fr.packet.SerializeToString())
        elif which == "config_complete_id":
            result["config_complete_id"] = fr.config_complete_id
        elif which == "my_info":
            mi = fr.my_info
            info = {
                "my_node_num": mi.my_node_num,
                "nodedb_count": getattr(mi, "nodedb_count", 0),
            }
            if mi.reboot_count:
                info["reboot_count"] = mi.reboot_count
            if mi.min_app_version:
                info["min_app_version"] = mi.min_app_version
            if mi.device_id:
                info["device_id"] = bytes(mi.device_id)
            if mi.pio_env:
                info["pio_env"] = mi.pio_env
            if mi.firmware_edition:
                info["firmware_edition"] = mi.firmware_edition
            result["my_info"] = info
        elif which == "node_info":
            ni = fr.node_info
            info = {"num": ni.num, "long_name": "", "short_name": ""}
            if ni.HasField("user"):
                info["long_name"] = ni.user.long_name
                info["short_name"] = ni.user.short_name
                if ni.user.hw_model:
                    info["hw_model"] = ni.user.hw_model
                if ni.user.role:
                    info["role"] = ni.user.role
                if ni.user.public_key:
                    info["public_key"] = bytes(ni.user.public_key)
                if ni.user.is_licensed:
                    info["is_licensed"] = True
            if ni.snr:
                info["snr"] = ni.snr
            if ni.last_heard:
                info["last_heard"] = ni.last_heard
            if ni.channel:
                info["channel"] = ni.channel
            if ni.via_mqtt:
                info["via_mqtt"] = True
            if ni.hops_away:
                info["hops_away"] = ni.hops_away
            if ni.is_favorite:
                info["is_favorite"] = True
            if ni.is_ignored:
                info["is_ignored"] = True
            if ni.is_muted:
                info["is_muted"] = True
            result["node_info"] = info
        elif which == "config":
            result["config"] = fr.config.SerializeToString()
        elif which == "moduleConfig":
            result["moduleConfig"] = fr.moduleConfig.SerializeToString()
        elif which == "channel":
            result["channel"] = fr.channel.SerializeToString()
        elif which == "metadata":
            result["metadata"] = fr.metadata.SerializeToString()
        elif which == "queueStatus":
            result["queueStatus"] = fr.queueStatus.SerializeToString()
        return result
    return _manual_decode_fromradio(data)


# --- Manual protobuf encoding/decoding helpers ---

def _manual_encode_mesh_packet(packet: MeshPacket) -> bytes:
    """Manual protobuf encoding for MeshPacket."""
    parts = []
    parts.append(b"\x0d" + struct.pack("<I", packet.header.from_node))
    parts.append(b"\x15" + struct.pack("<I", packet.header.to))
    if packet.header.channel:
        parts.append(b"\x18" + _encode_varint(packet.header.channel))
    if packet.encrypted:
        parts.append(b"\x2a" + _encode_varint(len(packet.encrypted)) + packet.encrypted)
    elif packet.data:
        data_bytes = packet.data.to_bytes()
        parts.append(b"\x22" + _encode_varint(len(data_bytes)) + data_bytes)
    parts.append(b"\x35" + struct.pack("<I", packet.header.id))
    if packet.header.hop_limit:
        parts.append(b"\x48" + _encode_varint(packet.header.hop_limit))
    if packet.header.want_ack:
        parts.append(b"\x50\x01")
    if packet.header.via_mqtt:
        parts.append(b"\x70\x01")  # field 14, varint, value 1
    if packet.header.hop_start:
        parts.append(b"\x78" + _encode_varint(packet.header.hop_start))
    return b"".join(parts)


def _manual_decode_mesh_packet(data: bytes) -> MeshPacket:
    """Manual protobuf decoding for MeshPacket."""
    from_node = 0
    to_node = BROADCAST_ADDR
    channel = 0
    pkt_id = 0
    hop_limit = 3
    want_ack = False
    via_mqtt = False
    hop_start = 3
    encrypted = b""
    decoded_data = None
    pos = 0

    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # varint
            value, pos = _decode_varint(data, pos)
            if field_num == 3:
                channel = value
            elif field_num == 9:
                hop_limit = value
            elif field_num == 10:
                want_ack = bool(value)
            elif field_num == 14:
                via_mqtt = bool(value)
            elif field_num == 15:
                hop_start = value
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 5:
                encrypted = blob
            elif field_num == 4:
                decoded_data = DataPayload.from_bytes(blob)
        elif wire_type == 5:  # 32-bit fixed
            value = struct.unpack("<I", data[pos:pos + 4])[0]
            pos += 4
            if field_num == 1:
                from_node = value
            elif field_num == 2:
                to_node = value
            elif field_num == 6:
                pkt_id = value
        elif wire_type == 1:  # 64-bit fixed
            pos += 8
        else:
            break

    header = MeshtasticHeader(
        to=to_node,
        from_node=from_node,
        id=pkt_id,
        hop_limit=hop_limit,
        want_ack=want_ack,
        via_mqtt=via_mqtt,
        hop_start=hop_start,
        channel=channel,
    )
    return MeshPacket(header=header, data=decoded_data, encrypted=encrypted)


def _manual_decode_toradio(data: bytes) -> dict:
    """Manual protobuf decoding for ToRadio."""
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # varint
            value, pos = _decode_varint(data, pos)
            if field_num == 3:
                return {"want_config_id": value}
            elif field_num == 4:
                return {"disconnect": bool(value)}
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 1:
                return {"packet": _manual_decode_mesh_packet(blob)}
            elif field_num == 7:
                return {"heartbeat": True}
        elif wire_type == 5:  # 32-bit
            pos += 4
        elif wire_type == 1:  # 64-bit
            pos += 8
        else:
            break
    return {}


def _manual_decode_fromradio(data: bytes) -> dict:
    """Manual protobuf decoding for FromRadio."""
    result = {"id": 0}
    pos = 0

    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # varint
            value, pos = _decode_varint(data, pos)
            if field_num == 1:
                result["id"] = value
            elif field_num == 7:
                result["config_complete_id"] = value
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 2:
                result["packet"] = _manual_decode_mesh_packet(blob)
            elif field_num == 3:
                result["my_info"] = _decode_my_info(blob)
            elif field_num == 4:
                result["node_info"] = _decode_node_info(blob)
            elif field_num == 5:
                result["config"] = blob
            elif field_num == 9:
                result["moduleConfig"] = blob
            elif field_num == 10:
                result["channel"] = blob
            elif field_num == 11:
                result["queueStatus"] = blob
            elif field_num == 13:
                result["metadata"] = blob
        elif wire_type == 5:  # 32-bit
            pos += 4
        elif wire_type == 1:  # 64-bit
            pos += 8
        else:
            break

    return result


def _decode_my_info(data: bytes) -> dict:
    """Decode MyNodeInfo sub-message.

    Proto fields: 1=my_node_num, 8=reboot_count, 11=min_app_version,
    12=device_id, 13=pio_env, 14=firmware_edition, 15=nodedb_count
    """
    info = {"my_node_num": 0, "nodedb_count": 0}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 1:
                info["my_node_num"] = value
            elif field_num == 8:
                info["reboot_count"] = value
            elif field_num == 11:
                info["min_app_version"] = value
            elif field_num == 14:
                info["firmware_edition"] = value
            elif field_num == 15:
                info["nodedb_count"] = value
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 12:
                info["device_id"] = blob
            elif field_num == 13:
                info["pio_env"] = blob.decode("utf-8", errors="replace")
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return info


def _decode_node_info(data: bytes) -> dict:
    """Decode NodeInfo sub-message.

    NodeInfo fields: 1=num, 2=user, 4=snr(float), 5=last_heard(fixed32),
      7=channel, 8=via_mqtt, 9=hops_away, 10=is_favorite, 11=is_ignored,
      12=is_key_manually_verified, 13=is_muted
    """
    info = {"num": 0, "long_name": "", "short_name": ""}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 1:
                info["num"] = value
            elif field_num == 7:
                info["channel"] = value
            elif field_num == 8:
                info["via_mqtt"] = bool(value)
            elif field_num == 9:
                info["hops_away"] = value
            elif field_num == 10:
                info["is_favorite"] = bool(value)
            elif field_num == 11:
                info["is_ignored"] = bool(value)
            elif field_num == 12:
                info["is_key_manually_verified"] = bool(value)
            elif field_num == 13:
                info["is_muted"] = bool(value)
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 2:
                user = _decode_user(blob)
                info["long_name"] = user.get("long_name", "")
                info["short_name"] = user.get("short_name", "")
                if "hw_model" in user and user["hw_model"]:
                    info["hw_model"] = user["hw_model"]
                if "role" in user and user["role"]:
                    info["role"] = user["role"]
                if "public_key" in user:
                    info["public_key"] = user["public_key"]
                if user.get("is_licensed"):
                    info["is_licensed"] = True
        elif wire_type == 5:
            if pos + 4 > len(data):
                break
            if field_num == 5:
                info["last_heard"] = struct.unpack("<I", data[pos:pos + 4])[0]
            elif field_num == 4:
                info["snr"] = struct.unpack("<f", data[pos:pos + 4])[0]
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return info


def _decode_user(data: bytes) -> dict:
    """Decode User sub-message.

    User fields: 1=id, 2=long_name, 3=short_name, 4=macaddr,
    5=hw_model, 6=is_licensed, 7=role, 8=public_key, 9=is_unmessagable
    """
    user = {"id": "", "long_name": "", "short_name": "", "hw_model": 0}
    pos = 0
    while pos < len(data):
        tag_byte, pos = _decode_varint(data, pos)
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
            if field_num == 5:
                user["hw_model"] = value
            elif field_num == 6:
                user["is_licensed"] = bool(value)
            elif field_num == 7:
                user["role"] = value
            elif field_num == 9:
                user["is_unmessagable"] = bool(value)
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            blob = data[pos:pos + length]
            pos += length
            if field_num == 1:
                user["id"] = blob.decode("utf-8", errors="replace")
            elif field_num == 2:
                user["long_name"] = blob.decode("utf-8", errors="replace")
            elif field_num == 3:
                user["short_name"] = blob.decode("utf-8", errors="replace")
            elif field_num == 4:
                user["macaddr"] = blob
            elif field_num == 8:
                user["public_key"] = blob
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return user
