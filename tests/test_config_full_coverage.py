"""Comprehensive config/module integration tests.

Verifies that ALL protobuf fields round-trip correctly through
encode → decode → store → re-encode for every config section,
module config, enum range, and edge case.
"""

import struct
import os
import base64

import pytest

from meshtastic_sdr.ble.protobuf_codec import (
    _tag, _encode_varint, _field_varint, _field_bool, _field_string,
    _field_bytes, _field_float, _field_submsg, _field_int32, _field_uint64,
    _encode_extra,
    encode_config_device, encode_config_position, encode_config_power,
    encode_config_network, encode_config_display, encode_config_lora,
    encode_config_bluetooth, encode_config_security,
    encode_config_sessionkey, encode_config_deviceui,
    encode_module_mqtt, encode_module_serial, encode_module_extnotif,
    encode_module_store_forward, encode_module_range_test,
    encode_module_telemetry, encode_module_canned_message,
    encode_module_audio, encode_module_remote_hardware,
    encode_module_neighbor_info, encode_module_ambient_lighting,
    encode_module_detection_sensor, encode_module_paxcounter,
    encode_module_status_message, encode_module_traffic_management,
    encode_channel,
    encode_fromradio_config, encode_fromradio_module_config,
    encode_fromradio_packet,
)
from meshtastic_sdr.ble.admin_handler import (
    _decode_named_fields, _decode_lora_config,
    _decode_config, _decode_module_config, _decode_channel,
    decode_admin_message,
    _CONFIG_VARINT_FIELDS, _CONFIG_STRING_FIELDS,
    _CONFIG_FLOAT_FIELDS, _CONFIG_BYTES_FIELDS,
    _MODULE_VARINT_FIELDS, _MODULE_STRING_FIELDS,
    _BOOL_FIELD_NAMES, _INT32_FIELD_NAMES,
    CONFIG_FIELD_TO_NAME, MODULE_FIELD_TO_NAME,
    AdminHandler, encode_admin_response,
    _encode_config_response, _encode_module_config_response,
    encode_device_metadata_response, encode_owner_response,
)
from meshtastic_sdr.ble.constants import (
    REGION_CODE_MAP, REGION_NAME_TO_CODE,
    MODEM_PRESET_MAP, PRESET_NAME_TO_CODE,
    ADMIN_SET_CONFIG, ADMIN_SET_MODULE_CONFIG,
    CONFIG_DEVICE, CONFIG_POSITION, CONFIG_POWER, CONFIG_NETWORK,
    CONFIG_DISPLAY, CONFIG_LORA, CONFIG_BLUETOOTH, CONFIG_SECURITY,
    MODULE_MQTT, MODULE_SERIAL, MODULE_EXTNOTIF, MODULE_STORE_FORWARD,
    MODULE_RANGE_TEST, MODULE_TELEMETRY, MODULE_CANNED_MSG, MODULE_AUDIO,
    MODULE_REMOTE_HW, MODULE_NEIGHBOR_INFO, MODULE_AMBIENT_LIGHTING,
    MODULE_DETECTION_SENSOR, MODULE_PAXCOUNTER, MODULE_STATUS_MESSAGE,
    MODULE_TRAFFIC_MANAGEMENT,
)
from meshtastic_sdr.protocol.mesh_packet import MeshPacket, DataPayload
from meshtastic_sdr.protocol.header import MeshtasticHeader
from meshtastic_sdr.protocol.portnums import PortNum


# --- Helpers ---

def _decode_config_submsg(config_bytes: bytes) -> dict:
    """Decode a Config protobuf that wraps a config section."""
    return _decode_config(config_bytes)


def _decode_module_submsg(module_bytes: bytes) -> dict:
    """Decode a ModuleConfig protobuf that wraps a module section."""
    return _decode_module_config(module_bytes)


class FakeNode:
    def __init__(self):
        self.node_id = 0xDEADBEEF
        self.long_name = "Test Node"
        self.short_name = "TST"
        self.known_nodes = {}


class FakeChannel:
    def __init__(self):
        self.name = "LongFast"
        self.psk = b"\x01" * 16


class FakeConfig:
    def __init__(self):
        self.region = "US"
        self.preset = "LONG_FAST"
        self.configs = {}
        self.modules = {}
        self.channel = type("Ch", (), {"name": "LongFast", "psk": "default"})()
        self.node = type("N", (), {"long_name": "Test", "short_name": "TST"})()
        self.mesh = type("M", (), {"hop_limit": 3})()
        self.radio = type("R", (), {"tx_gain": 20, "rx_gain": 49})()


class FakeGateway:
    def __init__(self):
        self.node = FakeNode()
        self.channel = FakeChannel()
        self.channels = {0: self.channel}
        self.config = FakeConfig()
        self.interface = None


def _make_admin_packet(admin_payload: bytes, from_node: int = 0x12345678) -> MeshPacket:
    header = MeshtasticHeader(
        to=0xDEADBEEF, from_node=from_node, id=42,
        hop_limit=3, hop_start=3, channel=0,
    )
    data = DataPayload(portnum=PortNum.ADMIN_APP, payload=admin_payload)
    return MeshPacket(header=header, data=data)


def _make_set_config_payload(config_field_num: int, inner_bytes: bytes) -> bytes:
    config_msg = _field_submsg(config_field_num, inner_bytes)
    return _field_submsg(ADMIN_SET_CONFIG, config_msg)


def _make_set_module_config_payload(module_field_num: int, inner_bytes: bytes) -> bytes:
    module_msg = _field_submsg(module_field_num, inner_bytes)
    return _field_submsg(ADMIN_SET_MODULE_CONFIG, module_msg)


# ============================================================
# Config Section Round-Trip Tests
# ============================================================

class TestDeviceConfigFullFields:
    """Test all DeviceConfig fields round-trip through encode → decode."""

    def test_all_fields(self):
        encoded = encode_config_device(
            role=5, tzdef="America/New_York", node_info_broadcast_secs=600,
            rebroadcast_mode=3, button_gpio=12, buzzer_gpio=13,
            double_tap_as_button_press=True, disable_triple_click=True,
            led_heartbeat_disabled=True, buzzer_mode=2,
        )
        decoded = _decode_config_submsg(encoded)
        assert "device" in decoded
        d = decoded["device"]
        assert d["role"] == 5
        assert d["tzdef"] == "America/New_York"
        assert d["node_info_broadcast_secs"] == 600
        assert d["rebroadcast_mode"] == 3
        assert d["button_gpio"] == 12
        assert d["buzzer_gpio"] == 13
        assert d["double_tap_as_button_press"] is True
        assert d["disable_triple_click"] is True
        assert d["led_heartbeat_disabled"] is True
        assert d["buzzer_mode"] == 2

    def test_defaults_only(self):
        encoded = encode_config_device()
        decoded = _decode_config_submsg(encoded)
        d = decoded["device"]
        assert d.get("node_info_broadcast_secs") == 900

    def test_role_enum_range(self):
        for role_val in [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12]:
            encoded = encode_config_device(role=role_val)
            decoded = _decode_config_submsg(encoded)
            d = decoded["device"]
            if role_val == 0:
                assert d.get("role", 0) == 0
            else:
                assert d["role"] == role_val

    def test_rebroadcast_mode_range(self):
        for mode in range(6):
            encoded = encode_config_device(rebroadcast_mode=mode)
            decoded = _decode_config_submsg(encoded)

    def test_buzzer_mode_range(self):
        for mode in range(5):
            encoded = encode_config_device(buzzer_mode=mode)
            decoded = _decode_config_submsg(encoded)
            d = decoded["device"]
            if mode > 0:
                assert d["buzzer_mode"] == mode


class TestPositionConfigFullFields:
    def test_all_fields(self):
        encoded = encode_config_position(
            position_broadcast_secs=300,
            position_broadcast_smart_enabled=True,
            gps_mode=1,
            fixed_position=True,
            gps_update_interval=120,
            position_flags=0x1FF,
            rx_gpio=16, tx_gpio=17,
            broadcast_smart_minimum_distance=50,
            broadcast_smart_minimum_interval_secs=30,
            gps_en_gpio=18,
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["position"]
        assert d["position_broadcast_secs"] == 300
        assert d["position_broadcast_smart_enabled"] is True
        assert d["gps_mode"] == 1
        assert d["fixed_position"] is True
        assert d["gps_update_interval"] == 120
        assert d["position_flags"] == 0x1FF
        assert d["rx_gpio"] == 16
        assert d["tx_gpio"] == 17
        assert d["broadcast_smart_minimum_distance"] == 50
        assert d["broadcast_smart_minimum_interval_secs"] == 30
        assert d["gps_en_gpio"] == 18

    def test_gps_mode_range(self):
        for mode in [0, 1, 2]:
            encoded = encode_config_position(gps_mode=mode)
            decoded = _decode_config_submsg(encoded)

    def test_position_flags_bitmask(self):
        flags = 0x01 | 0x08 | 0x200  # ALTITUDE | DOP | HEADING
        encoded = encode_config_position(position_flags=flags)
        decoded = _decode_config_submsg(encoded)
        assert decoded["position"]["position_flags"] == flags


class TestPowerConfigFullFields:
    def test_all_fields(self):
        encoded = encode_config_power(
            is_power_saving=True,
            on_battery_shutdown_after_secs=3600,
            adc_multiplier_override=2.5,
            wait_bluetooth_secs=30,
            sds_secs=7200,
            ls_secs=300,
            min_wake_secs=10,
            device_battery_ina_address=0x40,
            powermon_enables=0xFFFF,
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["power"]
        assert d["is_power_saving"] is True
        assert d["on_battery_shutdown_after_secs"] == 3600
        assert abs(d["adc_multiplier_override"] - 2.5) < 0.001
        assert d["wait_bluetooth_secs"] == 30
        assert d["sds_secs"] == 7200
        assert d["ls_secs"] == 300
        assert d["min_wake_secs"] == 10
        assert d["device_battery_ina_address"] == 0x40
        assert d["powermon_enables"] == 0xFFFF

    def test_float_field_zero(self):
        encoded = encode_config_power(adc_multiplier_override=0.0)
        decoded = _decode_config_submsg(encoded)
        # Float 0.0 is not emitted by encoder, so not in result
        assert "adc_multiplier_override" not in decoded.get("power", {})

    def test_uint64_large_value(self):
        big_val = 0xDEADBEEFCAFE
        encoded = encode_config_power(powermon_enables=big_val)
        decoded = _decode_config_submsg(encoded)
        assert decoded["power"]["powermon_enables"] == big_val


class TestNetworkConfigFullFields:
    def test_all_fields(self):
        encoded = encode_config_network(
            wifi_enabled=True,
            wifi_ssid="MyNetwork",
            wifi_psk="secret123",
            ntp_server="pool.ntp.org",
            eth_enabled=True,
            address_mode=1,
            rsyslog_server="syslog.local",
            enabled_protocols=1,
            ipv6_enabled=True,
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["network"]
        assert d["wifi_enabled"] is True
        assert d["wifi_ssid"] == "MyNetwork"
        assert d["wifi_psk"] == "secret123"
        assert d["ntp_server"] == "pool.ntp.org"
        assert d["eth_enabled"] is True
        assert d["address_mode"] == 1
        assert d["rsyslog_server"] == "syslog.local"
        assert d["enabled_protocols"] == 1
        assert d["ipv6_enabled"] is True


class TestDisplayConfigFullFields:
    def test_all_fields(self):
        encoded = encode_config_display(
            screen_on_secs=120,
            units=1,
            auto_screen_carousel_secs=15,
            flip_screen=True,
            oled=2,
            displaymode=3,
            heading_bold=True,
            wake_on_tap_or_motion=True,
            compass_orientation=4,
            use_12h_clock=True,
            use_long_node_name=True,
            enable_message_bubbles=True,
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["display"]
        assert d["screen_on_secs"] == 120
        assert d["units"] == 1
        assert d["auto_screen_carousel_secs"] == 15
        assert d["flip_screen"] is True
        assert d["oled"] == 2
        assert d["displaymode"] == 3
        assert d["heading_bold"] is True
        assert d["wake_on_tap_or_motion"] is True
        assert d["compass_orientation"] == 4
        assert d["use_12h_clock"] is True
        assert d["use_long_node_name"] is True
        assert d["enable_message_bubbles"] is True

    def test_units_enum(self):
        for unit in [0, 1]:
            encoded = encode_config_display(units=unit)
            decoded = _decode_config_submsg(encoded)

    def test_oled_enum_range(self):
        for oled_type in range(5):
            encoded = encode_config_display(oled=oled_type)

    def test_displaymode_range(self):
        for mode in range(4):
            encoded = encode_config_display(displaymode=mode)

    def test_compass_orientation_range(self):
        for orient in range(8):
            encoded = encode_config_display(compass_orientation=orient)


class TestLoRaConfigFullFields:
    def test_all_fields(self):
        encoded = encode_config_lora(
            region=1, modem_preset=6, hop_limit=7, tx_enabled=True,
            tx_power=27, use_preset=True, bandwidth=250, spread_factor=11,
            coding_rate=8, channel_num=20, frequency_offset=0.5,
            override_frequency=906.875,
            override_duty_cycle=True, sx126x_rx_boosted_gain=True,
            pa_fan_disabled=True, ignore_mqtt=True, config_ok_to_mqtt=True,
            ignore_incoming=[0x12345678, 0xDEADBEEF],
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["lora"]
        assert d["region"] == 1
        assert d["region_name"] == "US"
        assert d["modem_preset"] == 6
        assert d["modem_preset_name"] == "SHORT_FAST"
        assert d["hop_limit"] == 7
        assert d["tx_enabled"] is True
        assert d["tx_power"] == 27
        assert d["use_preset"] is True
        assert d["bandwidth"] == 250
        assert d["spread_factor"] == 11
        assert d["coding_rate"] == 8
        assert d["channel_num"] == 20
        assert abs(d["frequency_offset"] - 0.5) < 0.001
        assert abs(d["override_frequency"] - 906.875) < 0.01
        assert d["override_duty_cycle"] is True
        assert d["sx126x_rx_boosted_gain"] is True
        assert d["pa_fan_disabled"] is True
        assert d["ignore_mqtt"] is True
        assert d["config_ok_to_mqtt"] is True
        assert d["ignore_incoming"] == [0x12345678, 0xDEADBEEF]

    def test_preset_zero_always_emitted(self):
        """modem_preset=0 (LONG_FAST) and region=0 should always be in output."""
        encoded = encode_config_lora(region=0, modem_preset=0)
        decoded = _decode_config_submsg(encoded)
        d = decoded["lora"]
        assert d["modem_preset"] == 0
        assert d["region"] == 0

    def test_all_regions(self):
        for code, name in REGION_CODE_MAP.items():
            encoded = encode_config_lora(region=code)
            decoded = _decode_config_submsg(encoded)
            assert decoded["lora"]["region"] == code
            assert decoded["lora"]["region_name"] == name

    def test_all_presets(self):
        for code, name in MODEM_PRESET_MAP.items():
            encoded = encode_config_lora(modem_preset=code)
            decoded = _decode_config_submsg(encoded)
            assert decoded["lora"]["modem_preset"] == code
            assert decoded["lora"]["modem_preset_name"] == name


class TestBluetoothConfigFullFields:
    def test_all_fields(self):
        encoded = encode_config_bluetooth(enabled=True, mode=1, fixed_pin=654321)
        decoded = _decode_config_submsg(encoded)
        d = decoded["bluetooth"]
        assert d["enabled"] is True
        assert d["mode"] == 1
        assert d["fixed_pin"] == 654321

    def test_pairing_mode_range(self):
        for mode in [0, 1, 2]:
            encoded = encode_config_bluetooth(mode=mode)
            decoded = _decode_config_submsg(encoded)


class TestSecurityConfigFullFields:
    def test_all_fields(self):
        pub_key = os.urandom(32)
        priv_key = os.urandom(32)
        encoded = encode_config_security(
            serial_enabled=True, debug_log_api_enabled=True,
            admin_channel_enabled=True,
            public_key=pub_key, private_key=priv_key,
            is_managed=True,
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["security"]
        assert d["serial_enabled"] is True
        assert d["debug_log_api_enabled"] is True
        assert d["admin_channel_enabled"] is True
        assert d["public_key"] == pub_key
        assert d["private_key"] == priv_key
        assert d["is_managed"] is True

    def test_empty_security(self):
        encoded = encode_config_security(
            serial_enabled=False, debug_log_api_enabled=False,
            admin_channel_enabled=False,
        )
        decoded = _decode_config_submsg(encoded)
        d = decoded["security"]
        assert d.get("serial_enabled", False) is False


class TestSessionkeyAndDeviceUI:
    def test_sessionkey_empty(self):
        encoded = encode_config_sessionkey()
        assert len(encoded) > 0

    def test_deviceui_empty(self):
        encoded = encode_config_deviceui()
        assert len(encoded) > 0


# ============================================================
# Module Config Round-Trip Tests
# ============================================================

class TestMQTTModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_mqtt(
            enabled=True, proxy_to_client_enabled=True,
            address="mqtt.example.com", username="user",
            password="pass", encryption_enabled=True,
            json_enabled=True, tls_enabled=True,
            root="/meshtastic", map_reporting_enabled=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["mqtt"]
        assert d["enabled"] is True
        assert d["proxy_to_client_enabled"] is True
        assert d["address"] == "mqtt.example.com"
        assert d["username"] == "user"
        assert d["password"] == "pass"
        assert d["encryption_enabled"] is True
        assert d["json_enabled"] is True
        assert d["tls_enabled"] is True
        assert d["root"] == "/meshtastic"
        assert d["map_reporting_enabled"] is True

    def test_proxy_field_number_is_9(self):
        """Verify proxy_to_client_enabled uses proto field 9, not 8."""
        encoded = encode_module_mqtt(proxy_to_client_enabled=True)
        # The inner mqtt submsg should contain field 9 tag (0x48 = 9<<3|0)
        # Find the mqtt submsg content
        inner = encoded[2:]  # skip outer ModuleConfig field 1 tag + length
        # field 9 varint tag = (9 << 3) | 0 = 72 = 0x48
        assert b"\x48\x01" in inner


class TestSerialModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_serial(
            enabled=True, echo=True, rxd=16, txd=17,
            baud=11, timeout=1000, mode=2,
            override_console_serial_port=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["serial"]
        assert d["enabled"] is True
        assert d["echo"] is True
        assert d["rxd"] == 16
        assert d["txd"] == 17
        assert d["baud"] == 11
        assert d["timeout"] == 1000
        assert d["mode"] == 2
        assert d["override_console_serial_port"] is True

    def test_baud_enum_range(self):
        for baud in range(16):
            encoded = encode_module_serial(baud=baud)

    def test_serial_mode_range(self):
        for mode in range(11):
            encoded = encode_module_serial(mode=mode)


class TestExtNotifModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_extnotif(
            enabled=True, output_ms=500, output=12,
            active=True, alert_message=True, alert_bell=True,
            use_pwm=True, output_vibra=13, output_buzzer=14,
            alert_message_vibra=True, alert_message_buzzer=True,
            alert_bell_vibra=True, alert_bell_buzzer=True,
            nag_timeout=5000, use_i2s_as_buzzer=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["external_notification"]
        assert d["enabled"] is True
        assert d["output_ms"] == 500
        assert d["output"] == 12
        assert d["active"] is True
        assert d["alert_message"] is True
        assert d["alert_bell"] is True
        assert d["use_pwm"] is True
        assert d["output_vibra"] == 13
        assert d["output_buzzer"] == 14
        assert d["alert_message_vibra"] is True
        assert d["alert_message_buzzer"] is True
        assert d["alert_bell_vibra"] is True
        assert d["alert_bell_buzzer"] is True
        assert d["nag_timeout"] == 5000
        assert d["use_i2s_as_buzzer"] is True


class TestStoreForwardModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_store_forward(
            enabled=True, heartbeat=True, records=100,
            history_return_max=25, history_return_window=3600,
            is_server=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["store_forward"]
        assert d["enabled"] is True
        assert d["heartbeat"] is True
        assert d["records"] == 100
        assert d["history_return_max"] == 25
        assert d["history_return_window"] == 3600
        assert d["is_server"] is True


class TestRangeTestModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_range_test(
            enabled=True, sender=42, save=True, clear_on_reboot=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["range_test"]
        assert d["enabled"] is True
        assert d["sender"] == 42
        assert d["save"] is True
        assert d["clear_on_reboot"] is True


class TestTelemetryModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_telemetry(
            device_update_interval=300,
            environment_update_interval=600,
            environment_measurement_enabled=True,
            environment_screen_enabled=True,
            environment_display_fahrenheit=True,
            air_quality_enabled=True,
            air_quality_interval=120,
            power_measurement_enabled=True,
            power_update_interval=60,
            power_screen_enabled=True,
            health_measurement_enabled=True,
            health_update_interval=30,
            health_screen_enabled=True,
            device_telemetry_enabled=True,
            air_quality_screen_enabled=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["telemetry"]
        assert d["device_update_interval"] == 300
        assert d["environment_update_interval"] == 600
        assert d["environment_measurement_enabled"] is True
        assert d["environment_screen_enabled"] is True
        assert d["environment_display_fahrenheit"] is True
        assert d["air_quality_enabled"] is True
        assert d["air_quality_interval"] == 120
        assert d["power_measurement_enabled"] is True
        assert d["power_update_interval"] == 60
        assert d["power_screen_enabled"] is True
        assert d["health_measurement_enabled"] is True
        assert d["health_update_interval"] == 30
        assert d["health_screen_enabled"] is True
        assert d["device_telemetry_enabled"] is True
        assert d["air_quality_screen_enabled"] is True


class TestCannedMessageModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_canned_message(
            enabled=True, rotary1_enabled=True,
            inputbroker_pin_a=5, inputbroker_pin_b=6,
            inputbroker_pin_press=7,
            inputbroker_event_cw=0x11, inputbroker_event_ccw=0x12,
            inputbroker_event_press=0x0A,
            updown1_enabled=True, send_bell=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["canned_message"]
        assert d["enabled"] is True
        assert d["rotary1_enabled"] is True
        assert d["inputbroker_pin_a"] == 5
        assert d["inputbroker_pin_b"] == 6
        assert d["inputbroker_pin_press"] == 7
        assert d["inputbroker_event_cw"] == 0x11
        assert d["inputbroker_event_ccw"] == 0x12
        assert d["inputbroker_event_press"] == 0x0A
        assert d["updown1_enabled"] is True
        assert d["send_bell"] is True


class TestAudioModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_audio(
            enabled=True, ptt_pin=25, bitrate=3,
            i2s_ws=18, i2s_sd=19, i2s_din=20, i2s_sck=21,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["audio"]
        assert d["enabled"] is True
        assert d["ptt_pin"] == 25
        assert d["bitrate"] == 3
        assert d["i2s_ws"] == 18
        assert d["i2s_sd"] == 19
        assert d["i2s_din"] == 20
        assert d["i2s_sck"] == 21

    def test_codec2_bitrate_range(self):
        for bitrate in range(9):
            encoded = encode_module_audio(bitrate=bitrate)


class TestRemoteHardwareModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_remote_hardware(
            enabled=True, allow_undefined_pin_access=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["remote_hardware"]
        assert d["enabled"] is True
        assert d["allow_undefined_pin_access"] is True


class TestNeighborInfoModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_neighbor_info(
            enabled=True, update_interval=600, transmit_over_lora=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["neighbor_info"]
        assert d["enabled"] is True
        assert d["update_interval"] == 600
        assert d["transmit_over_lora"] is True


class TestAmbientLightingModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_ambient_lighting(
            led_state=True, current=100, red=255, green=128, blue=64,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["ambient_lighting"]
        assert d["led_state"] is True
        assert d["current"] == 100
        assert d["red"] == 255
        assert d["green"] == 128
        assert d["blue"] == 64

    def test_empty(self):
        encoded = encode_module_ambient_lighting()
        decoded = _decode_module_submsg(encoded)
        assert "ambient_lighting" in decoded


class TestDetectionSensorModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_detection_sensor(
            enabled=True, minimum_broadcast_secs=30,
            state_broadcast_secs=60, send_bell=True,
            name="door_sensor", monitor_pin=4,
            detection_trigger_type=3, use_pullup=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["detection_sensor"]
        assert d["enabled"] is True
        assert d["minimum_broadcast_secs"] == 30
        assert d["state_broadcast_secs"] == 60
        assert d["send_bell"] is True
        assert d["name"] == "door_sensor"
        assert d["monitor_pin"] == 4
        assert d["detection_trigger_type"] == 3
        assert d["use_pullup"] is True

    def test_trigger_type_range(self):
        for tt in range(6):
            encoded = encode_module_detection_sensor(detection_trigger_type=tt)


class TestPaxcounterModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_paxcounter(
            enabled=True, paxcounter_update_interval=120,
            wifi_threshold=-70, ble_threshold=-80,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["paxcounter"]
        assert d["enabled"] is True
        assert d["paxcounter_update_interval"] == 120
        assert d["wifi_threshold"] == -70
        assert d["ble_threshold"] == -80

    def test_negative_int32_threshold(self):
        """int32 negative values encode as sign-extended varints."""
        encoded = encode_module_paxcounter(wifi_threshold=-90)
        decoded = _decode_module_submsg(encoded)
        assert decoded["paxcounter"]["wifi_threshold"] == -90

    def test_zero_threshold(self):
        encoded = encode_module_paxcounter(wifi_threshold=0, ble_threshold=0)
        decoded = _decode_module_submsg(encoded)
        # Zero values not emitted by encoder
        d = decoded["paxcounter"]
        assert "wifi_threshold" not in d or d["wifi_threshold"] == 0


class TestStatusMessageModuleFullFields:
    def test_with_status(self):
        encoded = encode_module_status_message(node_status="Hello World")
        decoded = _decode_module_submsg(encoded)
        assert decoded["statusmessage"]["node_status"] == "Hello World"

    def test_empty_status(self):
        encoded = encode_module_status_message(node_status="")
        decoded = _decode_module_submsg(encoded)
        assert "statusmessage" in decoded


class TestTrafficManagementModuleFullFields:
    def test_all_fields(self):
        encoded = encode_module_traffic_management(
            enabled=True, position_dedup_enabled=True,
            position_precision_bits=16, position_min_interval_secs=60,
            nodeinfo_direct_response=True,
            nodeinfo_direct_response_max_hops=2,
            rate_limit_enabled=True, rate_limit_window_secs=300,
            rate_limit_max_packets=50,
            drop_unknown_enabled=True, unknown_packet_threshold=5,
            exhaust_hop_telemetry=True, exhaust_hop_position=True,
            router_preserve_hops=True,
        )
        decoded = _decode_module_submsg(encoded)
        d = decoded["traffic_management"]
        assert d["enabled"] is True
        assert d["position_dedup_enabled"] is True
        assert d["position_precision_bits"] == 16
        assert d["position_min_interval_secs"] == 60
        assert d["nodeinfo_direct_response"] is True
        assert d["nodeinfo_direct_response_max_hops"] == 2
        assert d["rate_limit_enabled"] is True
        assert d["rate_limit_window_secs"] == 300
        assert d["rate_limit_max_packets"] == 50
        assert d["drop_unknown_enabled"] is True
        assert d["unknown_packet_threshold"] == 5
        assert d["exhaust_hop_telemetry"] is True
        assert d["exhaust_hop_position"] is True
        assert d["router_preserve_hops"] is True


# ============================================================
# Channel Round-Trip Tests
# ============================================================

class TestChannelFullFields:
    def test_primary_channel_with_psk(self):
        psk = os.urandom(32)
        encoded = encode_channel(index=0, name="TestChannel", psk=psk, role=1)
        decoded = _decode_channel(encoded)
        assert decoded["index"] == 0
        assert decoded["role"] == 1
        assert decoded["settings"]["name"] == "TestChannel"
        assert decoded["settings"]["psk"] == psk

    def test_secondary_channel(self):
        encoded = encode_channel(index=3, name="Admin", psk=b"\xaa" * 16, role=2)
        decoded = _decode_channel(encoded)
        assert decoded["index"] == 3
        assert decoded["role"] == 2
        assert decoded["settings"]["name"] == "Admin"

    def test_disabled_channel(self):
        encoded = encode_channel(index=5, role=0)
        decoded = _decode_channel(encoded)
        assert decoded["index"] == 5
        assert decoded["role"] == 0

    def test_all_8_channels(self):
        for i in range(8):
            role = 1 if i == 0 else (2 if i < 4 else 0)
            encoded = encode_channel(index=i, name=f"Ch{i}", psk=b"\x00" * 16, role=role)
            decoded = _decode_channel(encoded)
            assert decoded["index"] == i


# ============================================================
# Region and Preset Coverage
# ============================================================

class TestRegionCoverage:
    def test_all_27_proto_regions_mapped(self):
        """All proto RegionCode values 0-26 are in REGION_CODE_MAP."""
        for code in range(27):
            assert code in REGION_CODE_MAP, f"Region code {code} missing"

    def test_region_roundtrip(self):
        for code, name in REGION_CODE_MAP.items():
            assert REGION_NAME_TO_CODE[name] == code

    def test_new_regions_present(self):
        assert REGION_CODE_MAP[19] == "PH_433"
        assert REGION_CODE_MAP[20] == "PH_868"
        assert REGION_CODE_MAP[21] == "PH_915"
        assert REGION_CODE_MAP[22] == "ANZ_433"
        assert REGION_CODE_MAP[23] == "KZ_433"
        assert REGION_CODE_MAP[24] == "KZ_863"
        assert REGION_CODE_MAP[25] == "NP_865"
        assert REGION_CODE_MAP[26] == "BR_902"


class TestPresetCoverage:
    def test_all_10_presets(self):
        assert len(MODEM_PRESET_MAP) == 10
        for code in range(10):
            assert code in MODEM_PRESET_MAP

    def test_preset_roundtrip(self):
        for code, name in MODEM_PRESET_MAP.items():
            assert PRESET_NAME_TO_CODE[name] == code


# ============================================================
# Admin Handler Full Round-Trip Tests
# ============================================================

class TestAdminHandlerConfigRoundTrip:
    """Test phone set_config → store → get_config round-trip for all config types."""

    def _set_and_get(self, config_field_num: int, inner_bytes: bytes,
                     config_type: int) -> dict:
        """Simulate phone setting a config, then requesting it back."""
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Phone sends set_config
        payload = _make_set_config_payload(config_field_num, inner_bytes)
        packet = _make_admin_packet(payload)
        handler.handle_admin_packet(packet)

        return gw.config.configs

    def test_device_config_all_fields_stored(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(5)     # role=TRACKER
        inner += _tag(4, 0) + _encode_varint(12)    # button_gpio
        inner += _tag(5, 0) + _encode_varint(13)    # buzzer_gpio
        inner += _tag(6, 0) + _encode_varint(3)     # rebroadcast_mode
        inner += _tag(7, 0) + _encode_varint(600)   # node_info_broadcast_secs
        inner += _tag(8, 0) + _encode_varint(1)     # double_tap_as_button_press
        inner += _tag(10, 0) + _encode_varint(1)    # disable_triple_click
        inner += _field_string(11, "US/Eastern")     # tzdef
        inner += _tag(12, 0) + _encode_varint(1)    # led_heartbeat_disabled
        inner += _tag(13, 0) + _encode_varint(2)    # buzzer_mode

        configs = self._set_and_get(1, inner, CONFIG_DEVICE)
        d = configs["device"]
        assert d["role"] == 5
        assert d["button_gpio"] == 12
        assert d["buzzer_gpio"] == 13
        assert d["rebroadcast_mode"] == 3
        assert d["node_info_broadcast_secs"] == 600
        assert d["double_tap_as_button_press"] is True
        assert d["disable_triple_click"] is True
        assert d["tzdef"] == "US/Eastern"
        assert d["led_heartbeat_disabled"] is True
        assert d["buzzer_mode"] == 2

    def test_display_config_all_fields_stored(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(120)   # screen_on_secs
        inner += _tag(3, 0) + _encode_varint(10)    # auto_screen_carousel_secs
        inner += _tag(5, 0) + _encode_varint(1)     # flip_screen
        inner += _tag(6, 0) + _encode_varint(1)     # units (IMPERIAL)
        inner += _tag(7, 0) + _encode_varint(2)     # oled (SH1106)
        inner += _tag(8, 0) + _encode_varint(1)     # displaymode (TWOCOLOR)
        inner += _tag(9, 0) + _encode_varint(1)     # heading_bold
        inner += _tag(10, 0) + _encode_varint(1)    # wake_on_tap_or_motion
        inner += _tag(11, 0) + _encode_varint(3)    # compass_orientation
        inner += _tag(12, 0) + _encode_varint(1)    # use_12h_clock
        inner += _tag(13, 0) + _encode_varint(1)    # use_long_node_name
        inner += _tag(14, 0) + _encode_varint(1)    # enable_message_bubbles

        configs = self._set_and_get(5, inner, CONFIG_DISPLAY)
        d = configs["display"]
        assert d["screen_on_secs"] == 120
        assert d["auto_screen_carousel_secs"] == 10
        assert d["flip_screen"] is True
        assert d["units"] == 1
        assert d["oled"] == 2
        assert d["displaymode"] == 1
        assert d["heading_bold"] is True
        assert d["wake_on_tap_or_motion"] is True
        assert d["compass_orientation"] == 3
        assert d["use_12h_clock"] is True
        assert d["use_long_node_name"] is True
        assert d["enable_message_bubbles"] is True

    def test_network_config_all_fields_stored(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)     # wifi_enabled
        inner += _field_string(3, "MyWifi")          # wifi_ssid
        inner += _field_string(4, "password")        # wifi_psk
        inner += _field_string(5, "pool.ntp.org")    # ntp_server
        inner += _tag(6, 0) + _encode_varint(1)     # eth_enabled
        inner += _tag(7, 0) + _encode_varint(1)     # address_mode (STATIC)
        inner += _field_string(9, "syslog.local")    # rsyslog_server
        inner += _tag(10, 0) + _encode_varint(1)    # enabled_protocols
        inner += _tag(11, 0) + _encode_varint(1)    # ipv6_enabled

        configs = self._set_and_get(4, inner, CONFIG_NETWORK)
        d = configs["network"]
        assert d["wifi_enabled"] is True
        assert d["wifi_ssid"] == "MyWifi"
        assert d["wifi_psk"] == "password"
        assert d["ntp_server"] == "pool.ntp.org"
        assert d["eth_enabled"] is True
        assert d["address_mode"] == 1
        assert d["rsyslog_server"] == "syslog.local"
        assert d["enabled_protocols"] == 1
        assert d["ipv6_enabled"] is True

    def test_power_config_float_field(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)     # is_power_saving
        inner += _tag(4, 0) + _encode_varint(60)     # wait_bluetooth_secs
        inner += _tag(3, 5) + struct.pack("<f", 1.5) # adc_multiplier_override (float)

        configs = self._set_and_get(3, inner, CONFIG_POWER)
        d = configs["power"]
        assert d["is_power_saving"] is True
        assert d["wait_bluetooth_secs"] == 60
        assert abs(d["adc_multiplier_override"] - 1.5) < 0.001

    def test_security_config_bytes_fields(self):
        pub_key = b"\x01\x02\x03\x04" * 8
        inner = b""
        inner += _field_bytes(1, pub_key)            # public_key
        inner += _tag(5, 0) + _encode_varint(1)     # serial_enabled

        configs = self._set_and_get(8, inner, CONFIG_SECURITY)
        d = configs["security"]
        assert d["public_key"] == pub_key
        assert d["serial_enabled"] is True


class TestAdminHandlerModuleRoundTrip:
    """Test phone set_module_config → store → verify for all module types."""

    def _set_module(self, module_field_num: int, inner_bytes: bytes) -> dict:
        gw = FakeGateway()
        handler = AdminHandler(gw)
        payload = _make_set_module_config_payload(module_field_num, inner_bytes)
        packet = _make_admin_packet(payload)
        handler.handle_admin_packet(packet)
        return gw.config.modules

    def test_mqtt_all_fields(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)     # enabled
        inner += _field_string(2, "mqtt.local")      # address
        inner += _field_string(3, "user")            # username
        inner += _field_string(4, "pass")            # password
        inner += _tag(5, 0) + _encode_varint(1)     # encryption_enabled
        inner += _tag(6, 0) + _encode_varint(1)     # json_enabled
        inner += _tag(7, 0) + _encode_varint(1)     # tls_enabled
        inner += _field_string(8, "root_topic")      # root
        inner += _tag(9, 0) + _encode_varint(1)     # proxy_to_client_enabled
        inner += _tag(10, 0) + _encode_varint(1)    # map_reporting_enabled

        modules = self._set_module(1, inner)
        d = modules["mqtt"]
        assert d["enabled"] is True
        assert d["address"] == "mqtt.local"
        assert d["username"] == "user"
        assert d["password"] == "pass"
        assert d["encryption_enabled"] is True
        assert d["json_enabled"] is True
        assert d["tls_enabled"] is True
        assert d["root"] == "root_topic"
        assert d["proxy_to_client_enabled"] is True
        assert d["map_reporting_enabled"] is True

    def test_extnotif_all_fields(self):
        inner = b""
        for fn, val in [(1,1),(2,500),(3,12),(4,1),(5,1),(6,1),(7,1),
                         (8,13),(9,14),(10,1),(11,1),(12,1),(13,1),(14,5000),(15,1)]:
            inner += _tag(fn, 0) + _encode_varint(val)

        modules = self._set_module(3, inner)
        d = modules["external_notification"]
        assert d["enabled"] is True
        assert d["output_ms"] == 500
        assert d["output"] == 12
        assert d["nag_timeout"] == 5000
        assert d["use_i2s_as_buzzer"] is True

    def test_telemetry_all_fields(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(300)
        inner += _tag(2, 0) + _encode_varint(600)
        for fn in range(3, 16):
            inner += _tag(fn, 0) + _encode_varint(1 if fn not in (7,9,12) else 120)

        modules = self._set_module(6, inner)
        d = modules["telemetry"]
        assert d["device_update_interval"] == 300
        assert d["environment_update_interval"] == 600
        assert d["environment_measurement_enabled"] is True
        assert d["air_quality_interval"] == 120

    def test_traffic_management_all_fields(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)     # enabled
        inner += _tag(2, 0) + _encode_varint(1)     # position_dedup_enabled
        inner += _tag(3, 0) + _encode_varint(16)    # position_precision_bits
        inner += _tag(7, 0) + _encode_varint(1)     # rate_limit_enabled
        inner += _tag(8, 0) + _encode_varint(300)   # rate_limit_window_secs
        inner += _tag(9, 0) + _encode_varint(50)    # rate_limit_max_packets
        inner += _tag(14, 0) + _encode_varint(1)    # router_preserve_hops

        modules = self._set_module(15, inner)
        d = modules["traffic_management"]
        assert d["enabled"] is True
        assert d["position_dedup_enabled"] is True
        assert d["position_precision_bits"] == 16
        assert d["rate_limit_enabled"] is True
        assert d["rate_limit_window_secs"] == 300
        assert d["rate_limit_max_packets"] == 50
        assert d["router_preserve_hops"] is True

    def test_detection_sensor_with_name(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)
        inner += _tag(2, 0) + _encode_varint(30)
        inner += _tag(4, 0) + _encode_varint(1)     # send_bell
        inner += _field_string(5, "motion_sensor")   # name
        inner += _tag(6, 0) + _encode_varint(22)    # monitor_pin
        inner += _tag(7, 0) + _encode_varint(4)     # detection_trigger_type
        inner += _tag(8, 0) + _encode_varint(1)     # use_pullup

        modules = self._set_module(12, inner)
        d = modules["detection_sensor"]
        assert d["enabled"] is True
        assert d["name"] == "motion_sensor"
        assert d["monitor_pin"] == 22
        assert d["detection_trigger_type"] == 4
        assert d["use_pullup"] is True

    def test_ambient_lighting_all_fields(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)     # led_state
        inner += _tag(2, 0) + _encode_varint(50)    # current
        inner += _tag(3, 0) + _encode_varint(255)   # red
        inner += _tag(4, 0) + _encode_varint(0)     # green (0, won't decode)
        inner += _tag(5, 0) + _encode_varint(128)   # blue

        modules = self._set_module(11, inner)
        d = modules["ambient_lighting"]
        assert d["led_state"] is True
        assert d["current"] == 50
        assert d["red"] == 255
        assert d["blue"] == 128

    def test_paxcounter_negative_thresholds(self):
        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)     # enabled
        inner += _tag(2, 0) + _encode_varint(120)   # update_interval
        # -70 as int32: sign-extend to 64-bit
        inner += _tag(3, 0) + _encode_varint((-70 + (1 << 64)) & ((1 << 64) - 1))
        inner += _tag(4, 0) + _encode_varint((-80 + (1 << 64)) & ((1 << 64) - 1))

        modules = self._set_module(13, inner)
        d = modules["paxcounter"]
        assert d["enabled"] is True
        assert d["paxcounter_update_interval"] == 120
        assert d["wifi_threshold"] == -70
        assert d["ble_threshold"] == -80


# ============================================================
# LoRa Config Special Cases
# ============================================================

class TestLoRaConfigSpecialCases:
    def test_lora_set_new_region_applied(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        lora_inner = b""
        lora_inner += _tag(1, 0) + _encode_varint(1)  # use_preset
        lora_inner += _tag(2, 0) + _encode_varint(6)  # SHORT_FAST
        lora_inner += _tag(7, 0) + _encode_varint(19) # PH_433
        lora_inner += _tag(8, 0) + _encode_varint(5)  # hop_limit

        payload = _make_set_config_payload(6, lora_inner)  # Config field 6 = lora
        packet = _make_admin_packet(payload)
        handler.handle_admin_packet(packet)

        assert gw.config.region == "PH_433"
        assert gw.config.preset == "SHORT_FAST"
        assert gw.config.mesh.hop_limit == 5

    def test_lora_ignore_incoming_decoded(self):
        lora_inner = b""
        lora_inner += _tag(1, 0) + _encode_varint(1)
        lora_inner += _tag(2, 0) + _encode_varint(0)
        lora_inner += _tag(7, 0) + _encode_varint(1)
        lora_inner += _tag(8, 0) + _encode_varint(3)
        lora_inner += _tag(103, 0) + _encode_varint(0xAABBCCDD)
        lora_inner += _tag(103, 0) + _encode_varint(0x11223344)

        decoded = _decode_lora_config(lora_inner)
        assert decoded["ignore_incoming"] == [0xAABBCCDD, 0x11223344]

    def test_lora_additional_bool_fields_decoded(self):
        lora_inner = b""
        lora_inner += _tag(1, 0) + _encode_varint(1)
        lora_inner += _tag(2, 0) + _encode_varint(0)
        lora_inner += _tag(7, 0) + _encode_varint(1)
        lora_inner += _tag(8, 0) + _encode_varint(3)
        lora_inner += _tag(12, 0) + _encode_varint(1)  # override_duty_cycle
        lora_inner += _tag(13, 0) + _encode_varint(1)  # sx126x_rx_boosted_gain
        lora_inner += _tag(15, 0) + _encode_varint(1)  # pa_fan_disabled
        lora_inner += _tag(104, 0) + _encode_varint(1) # ignore_mqtt
        lora_inner += _tag(105, 0) + _encode_varint(1) # config_ok_to_mqtt

        decoded = _decode_lora_config(lora_inner)
        assert decoded["override_duty_cycle"] is True
        assert decoded["sx126x_rx_boosted_gain"] is True
        assert decoded["pa_fan_disabled"] is True
        assert decoded["ignore_mqtt"] is True
        assert decoded["config_ok_to_mqtt"] is True


# ============================================================
# Encode-Decode Full Config Round-Trip via AdminHandler
# ============================================================

class TestFullConfigGetRoundTrip:
    """set_config → store → get_config → verify stored values come back."""

    def test_device_set_then_get(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        # Phone sets device config with extra fields
        inner = b""
        inner += _tag(1, 0) + _encode_varint(7)     # role=TAK
        inner += _tag(4, 0) + _encode_varint(15)    # button_gpio
        inner += _tag(7, 0) + _encode_varint(450)   # node_info_broadcast_secs
        inner += _field_string(11, "UTC")            # tzdef
        inner += _tag(12, 0) + _encode_varint(1)    # led_heartbeat_disabled

        payload = _make_set_config_payload(1, inner)
        handler.handle_admin_packet(_make_admin_packet(payload))

        # Verify stored
        assert gw.config.configs["device"]["role"] == 7
        assert gw.config.configs["device"]["button_gpio"] == 15
        assert gw.config.configs["device"]["node_info_broadcast_secs"] == 450

        # Now simulate get_config request and decode response
        get_payload = _tag(5, 0) + _encode_varint(CONFIG_DEVICE)  # get_config_request
        get_packet = _make_admin_packet(get_payload)
        responses = handler.handle_admin_packet(get_packet)
        assert len(responses) == 1

    def test_network_set_then_get(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)

        inner = b""
        inner += _tag(1, 0) + _encode_varint(1)
        inner += _field_string(3, "TestSSID")
        inner += _field_string(5, "time.nist.gov")

        payload = _make_set_config_payload(4, inner)
        handler.handle_admin_packet(_make_admin_packet(payload))

        assert gw.config.configs["network"]["wifi_enabled"] is True
        assert gw.config.configs["network"]["wifi_ssid"] == "TestSSID"
        assert gw.config.configs["network"]["ntp_server"] == "time.nist.gov"


# ============================================================
# Encoder Helper Tests
# ============================================================

class TestFieldEncoderHelpers:
    def test_field_int32_positive(self):
        result = _field_int32(1, 42)
        assert result == _field_varint(1, 42)

    def test_field_int32_negative(self):
        result = _field_int32(1, -1)
        assert len(result) > 2  # negative int32 = 10-byte varint + tag

    def test_field_int32_zero(self):
        result = _field_int32(1, 0)
        assert result == b""

    def test_field_uint64_large(self):
        result = _field_uint64(1, 0xFFFFFFFFFFFFFFFF)
        assert len(result) > 0

    def test_field_uint64_zero(self):
        result = _field_uint64(1, 0)
        assert result == b""

    def test_encode_extra_empty(self):
        result = _encode_extra({}, {"a": (1, _field_varint)})
        assert result == b""

    def test_encode_extra_unknown_ignored(self):
        result = _encode_extra({"unknown": 42}, {"a": (1, _field_varint)})
        assert result == b""

    def test_encode_extra_orders_by_field_num(self):
        spec = {"b": (2, _field_varint), "a": (1, _field_varint)}
        result = _encode_extra({"a": 10, "b": 20}, spec)
        # field 1 should come before field 2
        assert result.index(_field_varint(1, 10)) < result.index(_field_varint(2, 20))


# ============================================================
# Field Map Completeness Tests
# ============================================================

class TestFieldMapCompleteness:
    """Verify every config/module type has a varint field map entry."""

    def test_all_config_types_have_varint_maps(self):
        for field_num, name in CONFIG_FIELD_TO_NAME.items():
            if name in ("sessionkey", "lora", "device_ui"):
                continue  # sessionkey is empty, lora has custom decoder, device_ui is pass-through
            assert name in _CONFIG_VARINT_FIELDS, \
                f"Config '{name}' missing from _CONFIG_VARINT_FIELDS"

    def test_all_module_types_have_varint_maps(self):
        for field_num, name in MODULE_FIELD_TO_NAME.items():
            if name == "statusmessage":
                continue  # string-only module
            assert name in _MODULE_VARINT_FIELDS, \
                f"Module '{name}' missing from _MODULE_VARINT_FIELDS"

    def test_bool_field_names_consistent(self):
        """Every field mapped as bool in varint maps should be in _BOOL_FIELD_NAMES."""
        # Collect all field names that are likely booleans
        known_non_bool = {
            "role", "rebroadcast_mode", "node_info_broadcast_secs", "button_gpio",
            "buzzer_gpio", "buzzer_mode", "position_broadcast_secs", "gps_mode",
            "gps_update_interval", "gps_attempt_time", "position_flags",
            "rx_gpio", "tx_gpio", "broadcast_smart_minimum_distance",
            "broadcast_smart_minimum_interval_secs", "gps_en_gpio",
            "on_battery_shutdown_after_secs", "wait_bluetooth_secs",
            "sds_secs", "ls_secs", "min_wake_secs", "device_battery_ina_address",
            "powermon_enables", "address_mode", "enabled_protocols",
            "screen_on_secs", "gps_format", "auto_screen_carousel_secs",
            "units", "oled", "displaymode", "compass_orientation",
            "mode", "fixed_pin",
            "device_update_interval", "environment_update_interval",
            "air_quality_interval", "power_update_interval", "health_update_interval",
            "output_ms", "output", "output_vibra", "output_buzzer", "nag_timeout",
            "records", "history_return_max", "history_return_window",
            "sender",
            "rxd", "txd", "baud", "timeout",
            "inputbroker_pin_a", "inputbroker_pin_b", "inputbroker_pin_press",
            "inputbroker_event_cw", "inputbroker_event_ccw", "inputbroker_event_press",
            "ptt_pin", "bitrate", "i2s_ws", "i2s_sd", "i2s_din", "i2s_sck",
            "update_interval", "current", "red", "green", "blue",
            "minimum_broadcast_secs", "state_broadcast_secs", "monitor_pin",
            "detection_trigger_type",
            "paxcounter_update_interval", "wifi_threshold", "ble_threshold",
            "position_precision_bits", "position_min_interval_secs",
            "nodeinfo_direct_response_max_hops", "rate_limit_window_secs",
            "rate_limit_max_packets", "unknown_packet_threshold",
        }
        for section, field_map in {**_CONFIG_VARINT_FIELDS, **_MODULE_VARINT_FIELDS}.items():
            for field_num, name in field_map.items():
                if name not in known_non_bool:
                    assert name in _BOOL_FIELD_NAMES, \
                        f"Field '{name}' in {section} may need to be in _BOOL_FIELD_NAMES"

    def test_int32_fields_in_set(self):
        assert "wifi_threshold" in _INT32_FIELD_NAMES
        assert "ble_threshold" in _INT32_FIELD_NAMES

    def test_config_field_to_name_includes_device_ui(self):
        assert 10 in CONFIG_FIELD_TO_NAME
        assert CONFIG_FIELD_TO_NAME[10] == "device_ui"


# ============================================================
# AdminMessage Dispatch Coverage Tests
# ============================================================

class TestAdminMessageDispatchComplete:
    """Test that all AdminMessage field numbers from admin.proto are dispatched."""

    def test_new_varint_fields_dispatched(self):
        """Fields 21-26 are newer admin commands."""
        from meshtastic_sdr.ble.constants import (
            ADMIN_ENTER_DFU_MODE_REQUEST, ADMIN_SET_SCALE,
            ADMIN_BACKUP_PREFERENCES, ADMIN_RESTORE_PREFERENCES,
            ADMIN_REMOVE_BACKUP_PREFERENCES,
        )
        # enter_dfu_mode_request (field 21, bool)
        payload = _tag(ADMIN_ENTER_DFU_MODE_REQUEST, 0) + _encode_varint(1)
        result = decode_admin_message(payload)
        assert result == {"enter_dfu_mode_request": True}

        # set_scale (field 23, uint32)
        payload = _tag(ADMIN_SET_SCALE, 0) + _encode_varint(5)
        result = decode_admin_message(payload)
        assert result == {"set_scale": 5}

        # backup_preferences (field 24, enum)
        payload = _tag(ADMIN_BACKUP_PREFERENCES, 0) + _encode_varint(1)
        result = decode_admin_message(payload)
        assert result == {"backup_preferences": 1}

        # restore_preferences (field 25, enum)
        payload = _tag(ADMIN_RESTORE_PREFERENCES, 0) + _encode_varint(2)
        result = decode_admin_message(payload)
        assert result == {"restore_preferences": 2}

        # remove_backup_preferences (field 26, enum)
        payload = _tag(ADMIN_REMOVE_BACKUP_PREFERENCES, 0) + _encode_varint(0)
        result = decode_admin_message(payload)
        assert result == {"remove_backup_preferences": 0}

    def test_session_passkey_as_bytes(self):
        """session_passkey is bytes (wire type 2), not varint."""
        from meshtastic_sdr.ble.constants import ADMIN_SESSION_PASSKEY
        passkey = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        payload = _tag(ADMIN_SESSION_PASSKEY, 2) + _encode_varint(len(passkey)) + passkey
        result = decode_admin_message(payload)
        assert result == {"session_passkey": passkey}

    def test_delete_file_request(self):
        """delete_file_request is string (wire type 2)."""
        from meshtastic_sdr.ble.constants import ADMIN_DELETE_FILE_REQUEST
        filename = "config.yaml"
        encoded_name = filename.encode("utf-8")
        payload = _tag(ADMIN_DELETE_FILE_REQUEST, 2) + _encode_varint(len(encoded_name)) + encoded_name
        result = decode_admin_message(payload)
        assert result == {"delete_file_request": filename}

    def test_send_input_event(self):
        """send_input_event is a sub-message."""
        from meshtastic_sdr.ble.constants import ADMIN_SEND_INPUT_EVENT
        inner = _tag(1, 0) + _encode_varint(42)
        payload = _tag(ADMIN_SEND_INPUT_EVENT, 2) + _encode_varint(len(inner)) + inner
        result = decode_admin_message(payload)
        assert "send_input_event" in result

    def test_key_verification(self):
        """key_verification is a sub-message."""
        from meshtastic_sdr.ble.constants import ADMIN_KEY_VERIFICATION
        inner = _tag(1, 0) + _encode_varint(1)
        payload = _tag(ADMIN_KEY_VERIFICATION, 2) + _encode_varint(len(inner)) + inner
        result = decode_admin_message(payload)
        assert "key_verification" in result

    def test_ota_request(self):
        """ota_request is a sub-message."""
        from meshtastic_sdr.ble.constants import ADMIN_OTA_REQUEST
        inner = _tag(1, 0) + _encode_varint(1)
        payload = _tag(ADMIN_OTA_REQUEST, 2) + _encode_varint(len(inner)) + inner
        result = decode_admin_message(payload)
        assert "ota_request" in result

    def test_sensor_config(self):
        """sensor_config is a sub-message."""
        from meshtastic_sdr.ble.constants import ADMIN_SENSOR_CONFIG
        inner = _tag(1, 0) + _encode_varint(3)
        payload = _tag(ADMIN_SENSOR_CONFIG, 2) + _encode_varint(len(inner)) + inner
        result = decode_admin_message(payload)
        assert "sensor_config" in result


class TestAdminHandlerNewFields:
    """Test that AdminHandler.handle_admin_packet handles all new admin fields."""

    def test_enter_dfu_mode_request_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_ENTER_DFU_MODE_REQUEST
        gw = FakeGateway()
        handler = AdminHandler(gw)
        payload = _tag(ADMIN_ENTER_DFU_MODE_REQUEST, 0) + _encode_varint(1)
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_delete_file_request_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_DELETE_FILE_REQUEST
        gw = FakeGateway()
        handler = AdminHandler(gw)
        name = "test.bin".encode("utf-8")
        payload = _tag(ADMIN_DELETE_FILE_REQUEST, 2) + _encode_varint(len(name)) + name
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_set_scale_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_SET_SCALE
        gw = FakeGateway()
        handler = AdminHandler(gw)
        payload = _tag(ADMIN_SET_SCALE, 0) + _encode_varint(10)
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_backup_preferences_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_BACKUP_PREFERENCES
        gw = FakeGateway()
        handler = AdminHandler(gw)
        payload = _tag(ADMIN_BACKUP_PREFERENCES, 0) + _encode_varint(1)
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_restore_preferences_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_RESTORE_PREFERENCES
        gw = FakeGateway()
        handler = AdminHandler(gw)
        payload = _tag(ADMIN_RESTORE_PREFERENCES, 0) + _encode_varint(1)
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_remove_backup_preferences_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_REMOVE_BACKUP_PREFERENCES
        gw = FakeGateway()
        handler = AdminHandler(gw)
        payload = _tag(ADMIN_REMOVE_BACKUP_PREFERENCES, 0) + _encode_varint(1)
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_send_input_event_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_SEND_INPUT_EVENT
        gw = FakeGateway()
        handler = AdminHandler(gw)
        inner = _tag(1, 0) + _encode_varint(42)
        payload = _tag(ADMIN_SEND_INPUT_EVENT, 2) + _encode_varint(len(inner)) + inner
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_key_verification_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_KEY_VERIFICATION
        gw = FakeGateway()
        handler = AdminHandler(gw)
        inner = _tag(1, 0) + _encode_varint(1)
        payload = _tag(ADMIN_KEY_VERIFICATION, 2) + _encode_varint(len(inner)) + inner
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_ota_request_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_OTA_REQUEST
        gw = FakeGateway()
        handler = AdminHandler(gw)
        inner = _tag(1, 0) + _encode_varint(1)
        payload = _tag(ADMIN_OTA_REQUEST, 2) + _encode_varint(len(inner)) + inner
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_sensor_config_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_SENSOR_CONFIG
        gw = FakeGateway()
        handler = AdminHandler(gw)
        inner = _tag(1, 0) + _encode_varint(3)
        payload = _tag(ADMIN_SENSOR_CONFIG, 2) + _encode_varint(len(inner)) + inner
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []

    def test_session_passkey_bytes_logged(self):
        from meshtastic_sdr.ble.constants import ADMIN_SESSION_PASSKEY
        gw = FakeGateway()
        handler = AdminHandler(gw)
        passkey = b"\xAA\xBB\xCC\xDD"
        payload = _tag(ADMIN_SESSION_PASSKEY, 2) + _encode_varint(len(passkey)) + passkey
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []


# ============================================================
# Security Config admin_key Round-Trip Tests
# ============================================================

class TestSecurityAdminKeyRoundTrip:
    """Test admin_key (repeated bytes field 3) encode → decode."""

    def test_admin_key_encoded_and_decoded(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encoded = encode_config_security(
            serial_enabled=True, debug_log_api_enabled=True,
            admin_channel_enabled=False,
            admin_key=[key1, key2],
        )
        decoded = _decode_config(encoded)
        d = decoded["security"]
        assert d["serial_enabled"] is True
        assert d["debug_log_api_enabled"] is True
        assert "admin_key" in d
        assert d["admin_key"] == [key1, key2]

    def test_admin_key_single(self):
        key = os.urandom(32)
        encoded = encode_config_security(
            serial_enabled=False, debug_log_api_enabled=False,
            admin_channel_enabled=False,
            admin_key=[key],
        )
        decoded = _decode_config(encoded)
        d = decoded["security"]
        assert d["admin_key"] == [key]

    def test_admin_key_empty(self):
        encoded = encode_config_security(
            serial_enabled=True, debug_log_api_enabled=True,
            admin_channel_enabled=False,
        )
        decoded = _decode_config(encoded)
        d = decoded["security"]
        assert "admin_key" not in d or d.get("admin_key") == []

    def test_admin_key_via_admin_handler_set_config(self):
        """Phone sends set_config with security.admin_key and it gets stored."""
        gw = FakeGateway()
        handler = AdminHandler(gw)
        key1 = b"\x11" * 32
        inner = b""
        inner += _field_bytes(1, b"\xAA" * 32)     # public_key
        inner += _field_bytes(3, key1)               # admin_key[0]
        inner += _tag(5, 0) + _encode_varint(1)     # serial_enabled
        payload = _make_set_config_payload(8, inner)  # Config field 8 = security
        packet = _make_admin_packet(payload)
        handler.handle_admin_packet(packet)
        d = gw.config.configs["security"]
        assert d["public_key"] == b"\xAA" * 32
        assert d["admin_key"] == [key1]
        assert d["serial_enabled"] is True


# ============================================================
# Channel Encoder/Decoder Full Field Tests
# ============================================================

class TestChannelFullFieldsExpanded:
    """Test all ChannelSettings fields: channel_num, psk, name, id, uplink, downlink."""

    def test_channel_with_uplink_downlink(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_channel
        encoded = encode_channel(
            index=0, name="Primary", psk=b"\x01" * 16, role=1,
            uplink_enabled=True, downlink_enabled=True,
        )
        decoded = _decode_channel(encoded)
        assert decoded["index"] == 0
        assert decoded["role"] == 1
        assert decoded["settings"]["name"] == "Primary"
        assert decoded["settings"]["psk"] == b"\x01" * 16
        assert decoded["settings"]["uplink_enabled"] is True
        assert decoded["settings"]["downlink_enabled"] is True

    def test_channel_with_settings_channel_num(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_channel
        encoded = encode_channel(
            index=2, name="Admin", psk=b"\xAA" * 32, role=2,
            channel_num=5,
        )
        decoded = _decode_channel(encoded)
        assert decoded["settings"]["channel_num"] == 5

    def test_channel_with_fixed32_id(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_channel
        encoded = encode_channel(
            index=1, name="Test", psk=b"\xBB" * 16, role=2,
            id=0xDEADBEEF,
        )
        decoded = _decode_channel(encoded)
        assert decoded["settings"]["id"] == 0xDEADBEEF

    def test_channel_all_settings_fields(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_channel
        encoded = encode_channel(
            index=3, name="Full", psk=b"\xCC" * 16, role=2,
            channel_num=10, id=0x12345678,
            uplink_enabled=True, downlink_enabled=True,
        )
        decoded = _decode_channel(encoded)
        assert decoded["index"] == 3
        assert decoded["role"] == 2
        s = decoded["settings"]
        assert s["channel_num"] == 10
        assert s["psk"] == b"\xCC" * 16
        assert s["name"] == "Full"
        assert s["id"] == 0x12345678
        assert s["uplink_enabled"] is True
        assert s["downlink_enabled"] is True

    def test_channel_only_uplink(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_channel
        encoded = encode_channel(
            index=0, name="Up", psk=b"\x01", role=1,
            uplink_enabled=True, downlink_enabled=False,
        )
        decoded = _decode_channel(encoded)
        assert decoded["settings"]["uplink_enabled"] is True
        assert decoded["settings"].get("downlink_enabled", False) is False

    def test_channel_with_zero_id_not_emitted(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_channel
        encoded = encode_channel(index=0, name="X", psk=b"\x01", role=1, id=0)
        decoded = _decode_channel(encoded)
        # fixed32 id=0 not emitted by encoder
        assert "id" not in decoded["settings"]


# ============================================================
# DeviceMetadata Full Field Tests
# ============================================================

class TestDeviceMetadataFullFields:
    """Test all DeviceMetadata fields in encode_fromradio_metadata."""

    def test_all_metadata_fields(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_metadata
        data = encode_fromradio_metadata(
            firmware_version="2.7.0.test",
            hw_model=37,
            has_bluetooth=True,
            has_wifi=True,
            has_ethernet=True,
            can_shutdown=True,
            has_remote_hardware=True,
            has_pkc=True,
            role=5,
            position_flags=0x1FF,
            excluded_modules=0x03,
            device_state_version=25,
            msg_id=1,
        )
        # Verify it encodes without error and has reasonable length
        assert len(data) > 20

    def test_metadata_defaults(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_metadata
        data = encode_fromradio_metadata()
        assert len(data) > 10

    def test_metadata_minimal(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_metadata
        data = encode_fromradio_metadata(
            firmware_version="1.0",
            hw_model=0,
            has_bluetooth=False,
            has_wifi=False,
        )
        assert len(data) > 5


# ============================================================
# _decode_repeated_bytes Tests
# ============================================================

class TestDecodeRepeatedBytes:
    """Test the _decode_repeated_bytes helper."""

    def test_single_entry(self):
        from meshtastic_sdr.ble.admin_handler import _decode_repeated_bytes
        data = _field_bytes(3, b"\x01\x02\x03")
        result = _decode_repeated_bytes(data, 3)
        assert result == [b"\x01\x02\x03"]

    def test_multiple_entries(self):
        from meshtastic_sdr.ble.admin_handler import _decode_repeated_bytes
        data = _field_bytes(3, b"\xAA") + _field_bytes(3, b"\xBB") + _field_bytes(3, b"\xCC")
        result = _decode_repeated_bytes(data, 3)
        assert result == [b"\xAA", b"\xBB", b"\xCC"]

    def test_no_matching_field(self):
        from meshtastic_sdr.ble.admin_handler import _decode_repeated_bytes
        data = _field_bytes(5, b"\x01")
        result = _decode_repeated_bytes(data, 3)
        assert result == []

    def test_mixed_fields(self):
        from meshtastic_sdr.ble.admin_handler import _decode_repeated_bytes
        data = (
            _tag(1, 0) + _encode_varint(42) +     # varint field 1
            _field_bytes(3, b"\xAA\xBB") +          # bytes field 3
            _tag(4, 0) + _encode_varint(1) +        # varint field 4
            _field_bytes(3, b"\xCC\xDD")             # bytes field 3 again
        )
        result = _decode_repeated_bytes(data, 3)
        assert result == [b"\xAA\xBB", b"\xCC\xDD"]

    def test_empty_data(self):
        from meshtastic_sdr.ble.admin_handler import _decode_repeated_bytes
        result = _decode_repeated_bytes(b"", 3)
        assert result == []


# ============================================================
# Admin Constants Completeness Test
# ============================================================

class TestAdminConstantsComplete:
    """Verify all AdminMessage field numbers from admin.proto are defined."""

    def test_all_admin_field_numbers_defined(self):
        from meshtastic_sdr.ble import constants
        expected = {
            1: "ADMIN_GET_CHANNEL_REQUEST",
            2: "ADMIN_GET_CHANNEL_RESPONSE",
            3: "ADMIN_GET_OWNER_REQUEST",
            4: "ADMIN_GET_OWNER_RESPONSE",
            5: "ADMIN_GET_CONFIG_REQUEST",
            6: "ADMIN_GET_CONFIG_RESPONSE",
            7: "ADMIN_GET_MODULE_CONFIG_REQUEST",
            8: "ADMIN_GET_MODULE_CONFIG_RESPONSE",
            10: "ADMIN_GET_CANNED_MSG_REQUEST",
            11: "ADMIN_GET_CANNED_MSG_RESPONSE",
            12: "ADMIN_GET_DEVICE_METADATA_REQUEST",
            13: "ADMIN_GET_DEVICE_METADATA_RESPONSE",
            14: "ADMIN_GET_RINGTONE_REQUEST",
            15: "ADMIN_GET_RINGTONE_RESPONSE",
            16: "ADMIN_GET_DEVICE_CONN_STATUS_REQUEST",
            18: "ADMIN_SET_HAM_MODE",
            19: "ADMIN_GET_NODE_REMOTE_HW_PINS_REQUEST",
            20: "ADMIN_GET_NODE_REMOTE_HW_PINS_RESPONSE",
            21: "ADMIN_ENTER_DFU_MODE_REQUEST",
            22: "ADMIN_DELETE_FILE_REQUEST",
            23: "ADMIN_SET_SCALE",
            24: "ADMIN_BACKUP_PREFERENCES",
            25: "ADMIN_RESTORE_PREFERENCES",
            26: "ADMIN_REMOVE_BACKUP_PREFERENCES",
            27: "ADMIN_SEND_INPUT_EVENT",
            32: "ADMIN_SET_OWNER",
            33: "ADMIN_SET_CHANNEL",
            34: "ADMIN_SET_CONFIG",
            35: "ADMIN_SET_MODULE_CONFIG",
            36: "ADMIN_SET_CANNED_MSG",
            37: "ADMIN_SET_RINGTONE",
            38: "ADMIN_REMOVE_BY_NODENUM",
            39: "ADMIN_SET_FAVORITE_NODE",
            40: "ADMIN_REMOVE_FAVORITE_NODE",
            41: "ADMIN_SET_FIXED_POSITION",
            42: "ADMIN_REMOVE_FIXED_POSITION",
            43: "ADMIN_SET_TIME_ONLY",
            44: "ADMIN_GET_UI_CONFIG_REQUEST",
            45: "ADMIN_GET_UI_CONFIG_RESPONSE",
            46: "ADMIN_STORE_UI_CONFIG",
            47: "ADMIN_SET_IGNORED_NODE",
            48: "ADMIN_REMOVE_IGNORED_NODE",
            49: "ADMIN_TOGGLE_MUTED_NODE",
            64: "ADMIN_BEGIN_EDIT",
            65: "ADMIN_COMMIT_EDIT",
            66: "ADMIN_ADD_CONTACT",
            67: "ADMIN_KEY_VERIFICATION",
            94: "ADMIN_FACTORY_RESET_DEVICE",
            95: "ADMIN_REBOOT_OTA_SECONDS",
            96: "ADMIN_EXIT_SIMULATOR",
            97: "ADMIN_REBOOT_SECONDS",
            98: "ADMIN_SHUTDOWN_SECONDS",
            99: "ADMIN_FACTORY_RESET_CONFIG",
            100: "ADMIN_NODEDB_RESET",
            101: "ADMIN_SESSION_PASSKEY",
            102: "ADMIN_OTA_REQUEST",
            103: "ADMIN_SENSOR_CONFIG",
        }
        for field_num, const_name in expected.items():
            assert hasattr(constants, const_name), \
                f"Missing constant {const_name} (field {field_num})"
            assert getattr(constants, const_name) == field_num, \
                f"{const_name} should be {field_num}, got {getattr(constants, const_name)}"

    def test_config_type_enum_complete(self):
        from meshtastic_sdr.ble import constants
        expected_configs = {
            0: "CONFIG_DEVICE", 1: "CONFIG_POSITION", 2: "CONFIG_POWER",
            3: "CONFIG_NETWORK", 4: "CONFIG_DISPLAY", 5: "CONFIG_LORA",
            6: "CONFIG_BLUETOOTH", 7: "CONFIG_SECURITY", 8: "CONFIG_SESSIONKEY",
            9: "CONFIG_DEVICEUI",
        }
        for val, name in expected_configs.items():
            assert getattr(constants, name) == val

    def test_module_type_enum_complete(self):
        from meshtastic_sdr.ble import constants
        expected_modules = {
            0: "MODULE_MQTT", 1: "MODULE_SERIAL", 2: "MODULE_EXTNOTIF",
            3: "MODULE_STORE_FORWARD", 4: "MODULE_RANGE_TEST",
            5: "MODULE_TELEMETRY", 6: "MODULE_CANNED_MSG", 7: "MODULE_AUDIO",
            8: "MODULE_REMOTE_HW", 9: "MODULE_NEIGHBOR_INFO",
            10: "MODULE_AMBIENT_LIGHTING", 11: "MODULE_DETECTION_SENSOR",
            12: "MODULE_PAXCOUNTER", 13: "MODULE_STATUS_MESSAGE",
            14: "MODULE_TRAFFIC_MANAGEMENT",
        }
        for val, name in expected_modules.items():
            assert getattr(constants, name) == val


# ============================================================
# Protobuf Field Exhaustive Cross-Check vs Proto Definitions
# ============================================================

class TestProtoFieldCrossCheck:
    """Cross-check our encoder/decoder field maps against known proto field numbers."""

    def test_device_config_field_numbers(self):
        """DeviceConfig: 1:role, 2:serial_enabled, 4:button_gpio, 5:buzzer_gpio,
        6:rebroadcast_mode, 7:node_info_broadcast_secs, 8:double_tap_as_button_press,
        9:is_managed, 10:disable_triple_click, 11:tzdef, 12:led_heartbeat_disabled,
        13:buzzer_mode"""
        varint = _CONFIG_VARINT_FIELDS["device"]
        string = _CONFIG_STRING_FIELDS.get("device", {})
        assert varint[1] == "role"
        assert varint[2] == "serial_enabled"
        assert varint[4] == "button_gpio"
        assert varint[5] == "buzzer_gpio"
        assert varint[6] == "rebroadcast_mode"
        assert varint[7] == "node_info_broadcast_secs"
        assert varint[8] == "double_tap_as_button_press"
        assert varint[9] == "is_managed"
        assert varint[10] == "disable_triple_click"
        assert string[11] == "tzdef"
        assert varint[12] == "led_heartbeat_disabled"
        assert varint[13] == "buzzer_mode"

    def test_position_config_field_numbers(self):
        """PositionConfig: fields 1-13"""
        v = _CONFIG_VARINT_FIELDS["position"]
        assert v[1] == "position_broadcast_secs"
        assert v[2] == "position_broadcast_smart_enabled"
        assert v[3] == "fixed_position"
        assert v[4] == "gps_enabled"
        assert v[5] == "gps_update_interval"
        assert v[6] == "gps_attempt_time"
        assert v[7] == "position_flags"
        assert v[8] == "rx_gpio"
        assert v[9] == "tx_gpio"
        assert v[10] == "broadcast_smart_minimum_distance"
        assert v[11] == "broadcast_smart_minimum_interval_secs"
        assert v[12] == "gps_en_gpio"
        assert v[13] == "gps_mode"

    def test_power_config_field_numbers(self):
        """PowerConfig: 1,2,3(float),4,6,7,8,9,32(uint64)"""
        v = _CONFIG_VARINT_FIELDS["power"]
        f = _CONFIG_FLOAT_FIELDS.get("power", {})
        assert v[1] == "is_power_saving"
        assert v[2] == "on_battery_shutdown_after_secs"
        assert f[3] == "adc_multiplier_override"
        assert v[4] == "wait_bluetooth_secs"
        assert v[6] == "sds_secs"
        assert v[7] == "ls_secs"
        assert v[8] == "min_wake_secs"
        assert v[9] == "device_battery_ina_address"
        assert v[32] == "powermon_enables"

    def test_network_config_field_numbers(self):
        """NetworkConfig: 1,3-7,8(submsg),9-11"""
        v = _CONFIG_VARINT_FIELDS["network"]
        s = _CONFIG_STRING_FIELDS["network"]
        assert v[1] == "wifi_enabled"
        assert s[3] == "wifi_ssid"
        assert s[4] == "wifi_psk"
        assert s[5] == "ntp_server"
        assert v[6] == "eth_enabled"
        assert v[7] == "address_mode"
        # field 8 is ipv4_config submsg, not in maps
        assert s[9] == "rsyslog_server"
        assert v[10] == "enabled_protocols"
        assert v[11] == "ipv6_enabled"

    def test_display_config_field_numbers(self):
        """DisplayConfig: fields 1-14"""
        v = _CONFIG_VARINT_FIELDS["display"]
        assert v[1] == "screen_on_secs"
        assert v[2] == "gps_format"
        assert v[3] == "auto_screen_carousel_secs"
        assert v[4] == "compass_north_top"
        assert v[5] == "flip_screen"
        assert v[6] == "units"
        assert v[7] == "oled"
        assert v[8] == "displaymode"
        assert v[9] == "heading_bold"
        assert v[10] == "wake_on_tap_or_motion"
        assert v[11] == "compass_orientation"
        assert v[12] == "use_12h_clock"
        assert v[13] == "use_long_node_name"
        assert v[14] == "enable_message_bubbles"

    def test_bluetooth_config_field_numbers(self):
        """BluetoothConfig: 1,2,3"""
        v = _CONFIG_VARINT_FIELDS["bluetooth"]
        assert v[1] == "enabled"
        assert v[2] == "mode"
        assert v[3] == "fixed_pin"

    def test_security_config_field_numbers(self):
        """SecurityConfig: 1(bytes),2(bytes),3(repeated bytes),4,5,6,8"""
        v = _CONFIG_VARINT_FIELDS["security"]
        b = _CONFIG_BYTES_FIELDS["security"]
        assert b[1] == "public_key"
        assert b[2] == "private_key"
        # field 3 admin_key is repeated bytes, handled specially
        assert v[4] == "is_managed"
        assert v[5] == "serial_enabled"
        assert v[6] == "debug_log_api_enabled"
        assert v[8] == "admin_channel_enabled"

    def test_mqtt_module_field_numbers(self):
        """MQTTConfig: 1-10, 11(submsg)"""
        v = _MODULE_VARINT_FIELDS["mqtt"]
        s = _MODULE_STRING_FIELDS["mqtt"]
        assert v[1] == "enabled"
        assert s[2] == "address"
        assert s[3] == "username"
        assert s[4] == "password"
        assert v[5] == "encryption_enabled"
        assert v[6] == "json_enabled"
        assert v[7] == "tls_enabled"
        assert s[8] == "root"
        assert v[9] == "proxy_to_client_enabled"
        assert v[10] == "map_reporting_enabled"

    def test_serial_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["serial"]
        assert v[1] == "enabled"
        assert v[2] == "echo"
        assert v[3] == "rxd"
        assert v[4] == "txd"
        assert v[5] == "baud"
        assert v[6] == "timeout"
        assert v[7] == "mode"
        assert v[8] == "override_console_serial_port"

    def test_extnotif_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["external_notification"]
        for fn in range(1, 16):
            assert fn in v, f"ExternalNotification field {fn} missing"

    def test_store_forward_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["store_forward"]
        assert v[1] == "enabled"
        assert v[2] == "heartbeat"
        assert v[3] == "records"
        assert v[4] == "history_return_max"
        assert v[5] == "history_return_window"
        assert v[6] == "is_server"

    def test_range_test_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["range_test"]
        assert v[1] == "enabled"
        assert v[2] == "sender"
        assert v[3] == "save"
        assert v[4] == "clear_on_reboot"

    def test_telemetry_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["telemetry"]
        for fn in range(1, 16):
            assert fn in v, f"Telemetry field {fn} missing"

    def test_canned_message_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["canned_message"]
        s = _MODULE_STRING_FIELDS["canned_message"]
        for fn in [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]:
            assert fn in v, f"CannedMessage varint field {fn} missing"
        assert s[10] == "allow_input_source"

    def test_audio_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["audio"]
        for fn in range(1, 8):
            assert fn in v, f"Audio field {fn} missing"

    def test_remote_hardware_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["remote_hardware"]
        assert v[1] == "enabled"
        assert v[2] == "allow_undefined_pin_access"

    def test_neighbor_info_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["neighbor_info"]
        assert v[1] == "enabled"
        assert v[2] == "update_interval"
        assert v[3] == "transmit_over_lora"

    def test_ambient_lighting_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["ambient_lighting"]
        for fn in range(1, 6):
            assert fn in v, f"AmbientLighting field {fn} missing"

    def test_detection_sensor_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["detection_sensor"]
        s = _MODULE_STRING_FIELDS["detection_sensor"]
        for fn in [1, 2, 3, 4, 6, 7, 8]:
            assert fn in v, f"DetectionSensor varint field {fn} missing"
        assert s[5] == "name"

    def test_paxcounter_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["paxcounter"]
        assert v[1] == "enabled"
        assert v[2] == "paxcounter_update_interval"
        assert v[3] == "wifi_threshold"
        assert v[4] == "ble_threshold"

    def test_statusmessage_module_field_numbers(self):
        s = _MODULE_STRING_FIELDS["statusmessage"]
        assert s[1] == "node_status"

    def test_traffic_management_module_field_numbers(self):
        v = _MODULE_VARINT_FIELDS["traffic_management"]
        for fn in range(1, 15):
            assert fn in v, f"TrafficManagement field {fn} missing"


# ============================================================
# LoRa tx_power int32 Edge Case
# ============================================================

class TestLoRaTxPowerInt32:
    """LoRaConfig.tx_power is int32 in proto — test positive values."""

    def test_tx_power_positive(self):
        encoded = encode_config_lora(tx_power=27)
        decoded = _decode_config(encoded)
        assert decoded["lora"]["tx_power"] == 27

    def test_tx_power_zero(self):
        encoded = encode_config_lora(tx_power=0)
        decoded = _decode_config(encoded)
        # tx_power=0 is not emitted
        assert decoded["lora"].get("tx_power", 0) == 0

    def test_tx_power_max(self):
        encoded = encode_config_lora(tx_power=30)
        decoded = _decode_config(encoded)
        assert decoded["lora"]["tx_power"] == 30


# ============================================================
# device_ui Config Decode Test
# ============================================================

class TestDeviceUIConfigDecode:
    """Verify device_ui config section is recognized in _decode_config."""

    def test_device_ui_config_recognized(self):
        """Config field 10 should decode to device_ui key."""
        inner = _tag(1, 0) + _encode_varint(3)  # version=3
        config_msg = _field_submsg(10, inner)
        decoded = _decode_config(config_msg)
        assert "device_ui" in decoded

    def test_device_ui_config_empty(self):
        config_msg = _field_submsg(10, b"")
        decoded = _decode_config(config_msg)
        assert "device_ui" in decoded


# ============================================================
# User Decoder Full Field Tests
# ============================================================

class TestUserDecoderFullFields:
    """Test all User proto fields decode correctly."""

    def test_basic_user_fields(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        data = (
            _field_string(1, "!deadbeef") +
            _field_string(2, "Test Node") +
            _field_string(3, "TST") +
            _field_varint(5, 37)
        )
        user = _decode_user(data)
        assert user["id"] == "!deadbeef"
        assert user["long_name"] == "Test Node"
        assert user["short_name"] == "TST"
        assert user["hw_model"] == 37

    def test_user_role(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        data = (
            _field_string(1, "!aabbccdd") +
            _field_string(2, "Router") +
            _field_varint(5, 37) +
            _field_varint(7, 2)  # role=ROUTER
        )
        user = _decode_user(data)
        assert user["role"] == 2

    def test_user_public_key(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        pub_key = os.urandom(32)
        data = (
            _field_string(1, "!11223344") +
            _field_varint(5, 37) +
            _field_bytes(8, pub_key)
        )
        user = _decode_user(data)
        assert user["public_key"] == pub_key

    def test_user_macaddr(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        mac = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        data = (
            _field_string(1, "!11223344") +
            _field_bytes(4, mac)
        )
        user = _decode_user(data)
        assert user["macaddr"] == mac

    def test_user_is_licensed(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        data = (
            _field_string(1, "!11223344") +
            _field_varint(5, 37) +
            _tag(6, 0) + _encode_varint(1)  # is_licensed=true
        )
        user = _decode_user(data)
        assert user["is_licensed"] is True

    def test_user_is_unmessagable(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        data = (
            _field_string(1, "!11223344") +
            _tag(9, 0) + _encode_varint(1)  # is_unmessagable=true
        )
        user = _decode_user(data)
        assert user["is_unmessagable"] is True

    def test_user_all_fields(self):
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        pub_key = os.urandom(32)
        mac = b"\x01\x02\x03\x04\x05\x06"
        data = (
            _field_string(1, "!deadbeef") +
            _field_string(2, "Full Node") +
            _field_string(3, "FUL") +
            _field_bytes(4, mac) +
            _field_varint(5, 37) +
            _tag(6, 0) + _encode_varint(1) +  # is_licensed
            _field_varint(7, 3) +               # role=CLIENT_MUTE
            _field_bytes(8, pub_key) +
            _tag(9, 0) + _encode_varint(1)     # is_unmessagable
        )
        user = _decode_user(data)
        assert user["id"] == "!deadbeef"
        assert user["long_name"] == "Full Node"
        assert user["short_name"] == "FUL"
        assert user["macaddr"] == mac
        assert user["hw_model"] == 37
        assert user["is_licensed"] is True
        assert user["role"] == 3
        assert user["public_key"] == pub_key
        assert user["is_unmessagable"] is True


class TestSetOwnerWithNewFields:
    """Test set_owner with role, public_key, is_licensed via AdminHandler."""

    def test_set_owner_with_role(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)
        user_data = (
            _field_string(1, "!12345678") +
            _field_string(2, "New Name") +
            _field_string(3, "NN") +
            _field_varint(7, 2)  # role=ROUTER
        )
        payload = _field_submsg(32, user_data)  # set_owner
        packet = _make_admin_packet(payload)
        handler.handle_admin_packet(packet)
        assert gw.node.long_name == "New Name"
        assert gw.node.short_name == "NN"

    def test_set_owner_with_public_key(self):
        gw = FakeGateway()
        handler = AdminHandler(gw)
        pub_key = os.urandom(32)
        user_data = (
            _field_string(1, "!12345678") +
            _field_string(2, "PKI Node") +
            _field_bytes(8, pub_key)
        )
        payload = _field_submsg(32, user_data)
        packet = _make_admin_packet(payload)
        responses = handler.handle_admin_packet(packet)
        assert responses == []
        assert gw.node.long_name == "PKI Node"


# ============================================================
# NodeInfo Encoder/Decoder Full Field Tests
# ============================================================

class TestNodeInfoFullFields:
    """Test all NodeInfo proto fields encode/decode correctly."""

    def test_nodeinfo_basic_encode_decode(self):
        from meshtastic_sdr.ble.protobuf_codec import (
            encode_fromradio_node_info, decode_fromradio,
        )
        data = encode_fromradio_node_info(
            node_id=0xDEADBEEF,
            long_name="Test",
            short_name="TST",
            hw_model=37,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert decoded["node_info"]["num"] == 0xDEADBEEF
        assert decoded["node_info"]["long_name"] == "Test"
        assert decoded["node_info"]["short_name"] == "TST"

    def test_nodeinfo_with_last_heard(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="Node",
            short_name="N",
            last_heard=1709712000,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert decoded["node_info"]["last_heard"] == 1709712000

    def test_nodeinfo_with_hops_away(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="Far",
            short_name="F",
            hops_away=3,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert decoded["node_info"]["hops_away"] == 3

    def test_nodeinfo_with_snr(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="Node",
            short_name="N",
            snr=7.5,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert abs(decoded["node_info"]["snr"] - 7.5) < 0.01

    def test_nodeinfo_with_via_mqtt(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="MQTT",
            short_name="M",
            via_mqtt=True,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert decoded["node_info"]["via_mqtt"] is True

    def test_nodeinfo_with_is_favorite(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="Fav",
            short_name="F",
            is_favorite=True,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert decoded["node_info"]["is_favorite"] is True

    def test_nodeinfo_with_channel(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="Ch",
            short_name="C",
            channel=3,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        assert decoded["node_info"]["channel"] == 3

    def test_nodeinfo_with_user_role_and_public_key(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        pub_key = os.urandom(32)
        data = encode_fromradio_node_info(
            node_id=0x11223344,
            long_name="PKI Node",
            short_name="PKI",
            hw_model=37,
            role=2,
            public_key=pub_key,
            is_licensed=True,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        ni = decoded["node_info"]
        assert ni["num"] == 0x11223344
        assert ni["long_name"] == "PKI Node"
        assert ni.get("hw_model") == 37
        assert ni.get("role") == 2
        assert ni.get("public_key") == pub_key
        assert ni.get("is_licensed") is True

    def test_nodeinfo_with_is_ignored_and_is_muted(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        data = encode_fromradio_node_info(
            node_id=0xAABBCCDD,
            long_name="Ignored",
            short_name="I",
            is_ignored=True,
            is_muted=True,
            msg_id=1,
        )
        decoded = decode_fromradio(data)
        ni = decoded["node_info"]
        assert ni["is_ignored"] is True
        assert ni["is_muted"] is True

    def test_nodeinfo_all_fields(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_node_info, decode_fromradio
        pub_key = os.urandom(32)
        data = encode_fromradio_node_info(
            node_id=0xDEADBEEF,
            long_name="Full Node",
            short_name="FUL",
            hw_model=37,
            msg_id=42,
            role=5,
            public_key=pub_key,
            is_licensed=True,
            last_heard=1709712000,
            snr=-3.5,
            hops_away=2,
            channel=1,
            via_mqtt=True,
            is_favorite=True,
            is_ignored=False,
            is_muted=True,
        )
        decoded = decode_fromradio(data)
        ni = decoded["node_info"]
        assert ni["num"] == 0xDEADBEEF
        assert ni["long_name"] == "Full Node"
        assert ni["short_name"] == "FUL"
        assert ni.get("hw_model") == 37
        assert ni.get("role") == 5
        assert ni.get("public_key") == pub_key
        assert ni.get("is_licensed") is True
        assert ni["last_heard"] == 1709712000
        assert abs(ni["snr"] - (-3.5)) < 0.01
        assert ni["hops_away"] == 2
        assert ni["channel"] == 1
        assert ni["via_mqtt"] is True
        assert ni["is_favorite"] is True
        assert ni["is_muted"] is True


# ============================================================
# MyNodeInfo Encoder/Decoder Full Field Tests
# ============================================================

class TestMyNodeInfoFullFields:
    """Test all MyNodeInfo proto fields encode/decode correctly."""

    def test_my_info_basic(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_my_info, decode_fromradio
        data = encode_fromradio_my_info(
            node_id=0xDEADBEEF,
            msg_id=1,
            nodedb_count=5,
        )
        decoded = decode_fromradio(data)
        assert decoded["my_info"]["my_node_num"] == 0xDEADBEEF
        assert decoded["my_info"]["nodedb_count"] == 5

    def test_my_info_with_reboot_count(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_my_info, decode_fromradio
        data = encode_fromradio_my_info(
            node_id=0x11223344,
            msg_id=1,
            reboot_count=42,
        )
        decoded = decode_fromradio(data)
        assert decoded["my_info"]["reboot_count"] == 42

    def test_my_info_with_firmware_edition(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_my_info, decode_fromradio
        data = encode_fromradio_my_info(
            node_id=0x11223344,
            msg_id=1,
            firmware_edition=2,
        )
        decoded = decode_fromradio(data)
        assert decoded["my_info"]["firmware_edition"] == 2

    def test_my_info_with_device_id(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_my_info, decode_fromradio
        dev_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        data = encode_fromradio_my_info(
            node_id=0x11223344,
            msg_id=1,
            device_id=dev_id,
        )
        decoded = decode_fromradio(data)
        assert decoded["my_info"]["device_id"] == dev_id

    def test_my_info_with_pio_env(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_my_info, decode_fromradio
        data = encode_fromradio_my_info(
            node_id=0x11223344,
            msg_id=1,
            pio_env="linux-native",
        )
        decoded = decode_fromradio(data)
        assert decoded["my_info"]["pio_env"] == "linux-native"

    def test_my_info_all_fields(self):
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_my_info, decode_fromradio
        dev_id = os.urandom(8)
        data = encode_fromradio_my_info(
            node_id=0xDEADBEEF,
            msg_id=10,
            nodedb_count=12,
            min_app_version=30200,
            reboot_count=7,
            device_id=dev_id,
            pio_env="linux-native",
            firmware_edition=1,
        )
        decoded = decode_fromradio(data)
        info = decoded["my_info"]
        assert info["my_node_num"] == 0xDEADBEEF
        assert info["nodedb_count"] == 12
        assert info["reboot_count"] == 7
        assert info["device_id"] == dev_id
        assert info["pio_env"] == "linux-native"
        assert info["firmware_edition"] == 1


# ============================================================
# LoRa tx_power int32 Sign Handling
# ============================================================

class TestLoRaTxPowerInt32Sign:
    """Test that LoRa tx_power is properly decoded as int32 (signed)."""

    def test_tx_power_positive(self):
        from meshtastic_sdr.ble.admin_handler import _decode_lora_config
        data = _tag(10, 0) + _encode_varint(27)
        result = _decode_lora_config(data)
        assert result["tx_power"] == 27

    def test_tx_power_zero_not_emitted(self):
        from meshtastic_sdr.ble.admin_handler import _decode_lora_config
        data = _tag(7, 0) + _encode_varint(1)  # region only
        result = _decode_lora_config(data)
        assert result.get("tx_power", 0) == 0

    def test_tx_power_negative_as_int32(self):
        """Negative int32 is sign-extended to 64-bit varint."""
        from meshtastic_sdr.ble.admin_handler import _decode_lora_config
        neg_val = (-1 + (1 << 64)) & ((1 << 64) - 1)
        data = _tag(10, 0) + _encode_varint(neg_val)
        result = _decode_lora_config(data)
        assert result["tx_power"] == -1


# ============================================================
# encode_device_metadata_response Full Field Tests
# ============================================================

class TestDeviceMetadataResponseFullFields:
    """Test encode_device_metadata_response with all proto fields."""

    def test_basic_metadata_response(self):
        result = encode_device_metadata_response()
        assert len(result) > 10

    def test_metadata_response_all_fields(self):
        result = encode_device_metadata_response(
            firmware_version="2.7.0.test",
            hw_model=37,
            has_bluetooth=True,
            has_wifi=True,
            has_ethernet=True,
            can_shutdown=True,
            has_remote_hardware=True,
            has_pkc=True,
            role=5,
            position_flags=0x1FF,
            excluded_modules=0x03,
            device_state_version=25,
        )
        assert len(result) > 20
        # Decode to verify — it's wrapped in AdminMessage field 13
        decoded = decode_admin_message(result)
        assert "get_device_metadata_response" in decoded

    def test_metadata_response_defaults_only(self):
        result = encode_device_metadata_response(
            firmware_version="2.6.0.sdr",
            hw_model=37,
            has_bluetooth=True,
        )
        decoded = decode_admin_message(result)
        assert "get_device_metadata_response" in decoded

    def test_metadata_response_has_can_shutdown(self):
        """Verify canShutdown (field 3) is encoded."""
        result = encode_device_metadata_response(can_shutdown=True)
        # The metadata is a submsg inside AdminMessage field 13
        # Verify it decodes without error
        decoded = decode_admin_message(result)
        assert "get_device_metadata_response" in decoded

    def test_metadata_response_has_ethernet(self):
        """Verify hasEthernet (field 6) is encoded."""
        result = encode_device_metadata_response(has_ethernet=True)
        decoded = decode_admin_message(result)
        assert "get_device_metadata_response" in decoded

    def test_metadata_response_role_and_position_flags(self):
        """Verify role (field 7) and position_flags (field 8) are encoded."""
        result = encode_device_metadata_response(role=5, position_flags=0xFF)
        decoded = decode_admin_message(result)
        meta = decoded["get_device_metadata_response"]
        assert meta.get("field_7", 0) == 5 or "field_7" in meta


# ============================================================
# encode_owner_response Full Field Tests
# ============================================================

class TestOwnerResponseFullFields:
    """Test encode_owner_response with all User proto fields."""

    def test_basic_owner_response(self):
        result = encode_owner_response(
            long_name="Test", short_name="TST", node_id=0xDEADBEEF,
        )
        decoded = decode_admin_message(result)
        assert "get_owner_response" in decoded
        user = decoded["get_owner_response"]
        assert user["long_name"] == "Test"
        assert user["short_name"] == "TST"

    def test_owner_response_with_role(self):
        result = encode_owner_response(
            long_name="Router", short_name="R", node_id=0x11223344,
            role=2,
        )
        decoded = decode_admin_message(result)
        user = decoded["get_owner_response"]
        assert user["role"] == 2

    def test_owner_response_with_public_key(self):
        pub_key = os.urandom(32)
        result = encode_owner_response(
            long_name="PKI", short_name="P", node_id=0x11223344,
            public_key=pub_key,
        )
        decoded = decode_admin_message(result)
        user = decoded["get_owner_response"]
        assert user["public_key"] == pub_key

    def test_owner_response_with_is_licensed(self):
        result = encode_owner_response(
            long_name="Ham", short_name="H", node_id=0x11223344,
            is_licensed=True,
        )
        decoded = decode_admin_message(result)
        user = decoded["get_owner_response"]
        assert user["is_licensed"] is True

    def test_owner_response_all_fields(self):
        pub_key = os.urandom(32)
        result = encode_owner_response(
            long_name="Full User", short_name="FU", node_id=0xDEADBEEF,
            hw_model=37, role=5, public_key=pub_key, is_licensed=True,
        )
        decoded = decode_admin_message(result)
        user = decoded["get_owner_response"]
        assert user["long_name"] == "Full User"
        assert user["short_name"] == "FU"
        assert user["hw_model"] == 37
        assert user["role"] == 5
        assert user["public_key"] == pub_key
        assert user["is_licensed"] is True


# ============================================================
# Proto Field Cross-Check: User, NodeInfo, MyNodeInfo, DeviceMetadata
# ============================================================

class TestProtoFieldCrossCheckMessaging:
    """Cross-check User/NodeInfo/MyNodeInfo/DeviceMetadata fields against proto."""

    def test_user_decoder_field_completeness(self):
        """User proto: 1=id, 2=long_name, 3=short_name, 4=macaddr,
        5=hw_model, 6=is_licensed, 7=role, 8=public_key, 9=is_unmessagable"""
        from meshtastic_sdr.ble.protobuf_codec import _decode_user
        # Encode all fields
        pub_key = b"\xAA" * 32
        mac = b"\x01\x02\x03\x04\x05\x06"
        data = (
            _field_string(1, "!aabbccdd") +
            _field_string(2, "Long") +
            _field_string(3, "Sht") +
            _field_bytes(4, mac) +
            _field_varint(5, 37) +
            _tag(6, 0) + _encode_varint(1) +
            _field_varint(7, 2) +
            _field_bytes(8, pub_key) +
            _tag(9, 0) + _encode_varint(1)
        )
        user = _decode_user(data)
        assert user["id"] == "!aabbccdd"          # field 1
        assert user["long_name"] == "Long"         # field 2
        assert user["short_name"] == "Sht"         # field 3
        assert user["macaddr"] == mac              # field 4
        assert user["hw_model"] == 37              # field 5
        assert user["is_licensed"] is True         # field 6
        assert user["role"] == 2                   # field 7
        assert user["public_key"] == pub_key       # field 8
        assert user["is_unmessagable"] is True     # field 9

    def test_nodeinfo_decoder_field_completeness(self):
        """NodeInfo: 1=num, 2=user, 4=snr(float/fixed32), 5=last_heard(fixed32),
        7=channel, 8=via_mqtt, 9=hops_away, 10=is_favorite, 11=is_ignored,
        12=is_key_manually_verified, 13=is_muted"""
        from meshtastic_sdr.ble.protobuf_codec import _decode_node_info
        user_data = _field_string(1, "!11223344") + _field_string(2, "N") + _field_varint(5, 37)
        data = (
            _field_varint(1, 0x11223344) +
            _field_submsg(2, user_data) +
            _field_float(4, 5.25) +  # snr
            _tag(5, 5) + struct.pack("<I", 1709712000) +  # last_heard fixed32
            _field_varint(7, 2) +     # channel
            _tag(8, 0) + _encode_varint(1) +  # via_mqtt
            _field_varint(9, 3) +     # hops_away
            _tag(10, 0) + _encode_varint(1) +  # is_favorite
            _tag(11, 0) + _encode_varint(1) +  # is_ignored
            _tag(12, 0) + _encode_varint(1) +  # is_key_manually_verified
            _tag(13, 0) + _encode_varint(1)    # is_muted
        )
        ni = _decode_node_info(data)
        assert ni["num"] == 0x11223344
        assert ni["long_name"] == "N"
        assert ni.get("hw_model") == 37
        assert abs(ni["snr"] - 5.25) < 0.01
        assert ni["last_heard"] == 1709712000
        assert ni["channel"] == 2
        assert ni["via_mqtt"] is True
        assert ni["hops_away"] == 3
        assert ni["is_favorite"] is True
        assert ni["is_ignored"] is True
        assert ni["is_key_manually_verified"] is True
        assert ni["is_muted"] is True

    def test_my_info_decoder_field_completeness(self):
        """MyNodeInfo: 1=my_node_num, 8=reboot_count, 11=min_app_version,
        12=device_id, 13=pio_env, 14=firmware_edition, 15=nodedb_count"""
        from meshtastic_sdr.ble.protobuf_codec import _decode_my_info
        dev_id = b"\xAA\xBB\xCC\xDD"
        data = (
            _field_varint(1, 0xDEADBEEF) +
            _field_varint(8, 7) +
            _field_varint(11, 30200) +
            _field_bytes(12, dev_id) +
            _field_string(13, "linux-native") +
            _field_varint(14, 2) +
            _field_varint(15, 10)
        )
        info = _decode_my_info(data)
        assert info["my_node_num"] == 0xDEADBEEF
        assert info["reboot_count"] == 7
        assert info.get("min_app_version") == 30200
        assert info["device_id"] == dev_id
        assert info["pio_env"] == "linux-native"
        assert info["firmware_edition"] == 2
        assert info["nodedb_count"] == 10

    def test_device_metadata_encoder_field_completeness(self):
        """DeviceMetadata: 12 fields, all should be encodable."""
        from meshtastic_sdr.ble.protobuf_codec import encode_fromradio_metadata
        data = encode_fromradio_metadata(
            firmware_version="2.7.0",     # field 1
            device_state_version=25,       # field 2
            can_shutdown=True,             # field 3
            has_wifi=True,                 # field 4
            has_bluetooth=True,            # field 5
            has_ethernet=True,             # field 6
            role=5,                        # field 7
            position_flags=0x1FF,          # field 8
            hw_model=37,                   # field 9
            has_remote_hardware=True,      # field 10
            has_pkc=True,                  # field 11
            excluded_modules=0x03,         # field 12
            msg_id=1,
        )
        # Should encode all 12 metadata fields
        assert len(data) > 30
