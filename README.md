# meshtastic-sdr

A complete Python-based Meshtastic transceiver using the BladeRF x40 SDR. Turns an SDR into a functioning Meshtastic node that can send/receive messages and participate in the mesh network.

## Architecture

```
CLI / Application Layer            <- send/receive messages, node config
Meshtastic Protocol Layer          <- packet framing, AES-CTR encryption, protobuf
LoRa PHY Layer                     <- CSS modulation/demod, Hamming FEC, interleaving
Radio Backend (abstracted)         <- BladeRF x40 driver OR simulated loopback
```

Pure Python stack: NumPy for DSP, pycryptodome for AES, official bladerf bindings for hardware.

## Quick Start

```bash
pip install -e .

# Show node info
meshtastic-sdr info

# Listen for messages
meshtastic-sdr listen

# Send a message
meshtastic-sdr send "Hello mesh!"

# Scan for traffic
meshtastic-sdr scan

# Simulated mode (no hardware needed)
meshtastic-sdr --simulate info
```

## BLE Support

Two BLE modes allow integration with phones and existing Meshtastic hardware:

### BLE Tether (Central Mode)

Connect to an existing Meshtastic device (T-Beam, Heltec, etc.) via BLE and use it as the radio backend. The device handles LoRa/RF — we shuttle protobuf messages.

```bash
# Scan for nearby devices
meshtastic-sdr ble-tether scan

# Connect and listen for messages
meshtastic-sdr ble-tether listen --address XX:XX:XX:XX:XX:XX

# Send a message through the tethered device
meshtastic-sdr ble-tether send --address XX:XX:XX:XX:XX:XX --message "Hello!"

# Get device info
meshtastic-sdr ble-tether info --address XX:XX:XX:XX:XX:XX
```

### BLE Gateway (Peripheral Mode)

Our SDR acts as a full Meshtastic device. A phone running the Meshtastic app connects to us via BLE, and we transmit/receive over the air via the SDR.

```bash
# Start gateway with simulated radio
meshtastic-sdr --simulate ble-gateway --name "SDR Gateway"

# Start gateway with BladeRF
meshtastic-sdr ble-gateway --name "SDR Gateway"
```

**Note:** Linux requires root or `CAP_NET_ADMIN` for BLE advertising.

## Configuration

meshtastic-sdr uses YAML config files for persistent settings. Config file search order:

1. `--config <path>` (explicit CLI flag)
2. `./meshtastic-sdr.yaml` (project-local)
3. `~/.config/meshtastic-sdr/config.yaml` (XDG standard)
4. Built-in defaults (if no file found)

CLI arguments always override config file values.

### Quick Setup

```bash
# Interactive setup wizard
meshtastic-sdr init

# Or copy the template
cp config/default.yaml meshtastic-sdr.yaml
```

### Default Mode

Running `meshtastic-sdr` with no subcommand starts the configured default mode (default: `ble-gateway`). Override with `--simulate` for testing without hardware:

```bash
meshtastic-sdr                           # starts ble-gateway mode
meshtastic-sdr --simulate listen         # listen with simulated radio
meshtastic-sdr --config my.yaml info     # use explicit config file
```

### Node Identity

Node identity is persisted separately in `~/.local/share/meshtastic-sdr/node_identity.yaml` so your node ID survives across restarts. Set a fixed ID in config with `node.id: "!1a2b3c4d"`.

### XB-200 Transverter

The BladeRF XB-200 transverter board is auto-detected at startup. Configure behavior in the radio section:

```yaml
radio:
  xb200: auto          # auto (try, continue without), true (required), false (skip)
  xb200_filter: auto_1db  # auto_1db, auto_3db, custom, 50m, 144m, 222m
```

## Installation

```bash
pip install -e .
```

### BladeRF x40 Setup

The BladeRF Python bindings ship with libbladeRF (not on PyPI):

```bash
# 1. System libraries
sudo apt-get install -y bladerf libbladerf-dev bladerf-fpga-hostedx40 bladerf-firmware-fx3

# 2. Python bindings
pip install git+https://github.com/Nuand/bladeRF.git#subdirectory=host/libraries/libbladeRF_bindings/python

# 3. USB permissions (run once, then replug or reboot)
sudo tee /etc/udev/rules.d/88-nuand-bladerf.rules <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6066", MODE="0660", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
groups | grep -q plugdev || sudo usermod -aG plugdev $USER
```

### BLE Support (optional)

```bash
# Both modes (tether + gateway)
pip install -e ".[ble]"

# Or individually
pip install -e ".[ble-central]"     # tether to existing device
pip install -e ".[ble-peripheral]"  # act as gateway for phones
```

### Dependencies

- `numpy>=1.24` - Signal processing, FFT, chirp generation
- `protobuf>=4.0` - Meshtastic message serialization
- `pycryptodome>=3.19` - AES-256-CTR encryption/decryption
- `pyyaml>=6.0` - Config file parsing
- `bladerf` (system) - Official Nuand Python bindings for BladeRF hardware
- `bleak>=0.21` (optional) - BLE Central (cross-platform async BLE client)
- `bless>=0.2` (optional) - BLE Peripheral (GATT server)

## Modem Presets

| Preset | SF | BW (kHz) | CR | Use Case |
|---|---|---|---|---|
| SHORT_TURBO | 7 | 500 | 4/5 | Fastest, shortest range |
| SHORT_FAST | 7 | 250 | 4/5 | Fast, short range |
| SHORT_SLOW | 8 | 250 | 4/5 | Moderate speed |
| MEDIUM_FAST | 9 | 250 | 4/5 | Balanced |
| MEDIUM_SLOW | 10 | 250 | 4/5 | Slower, more range |
| LONG_TURBO | 11 | 500 | 4/8 | Turbo long range |
| **LONG_FAST** | **11** | **250** | **4/5** | **Default - best general use** |
| LONG_MODERATE | 11 | 125 | 4/8 | Long range, moderate speed |
| LONG_SLOW | 12 | 125 | 4/8 | Maximum range, slow |
| VERY_LONG_SLOW | 12 | 62.5 | 4/8 | Extreme range |

## Default Configuration

- **Region**: EU_868 (869.4-869.65 MHz)
- **Preset**: LONG_FAST (SF11, 250 kHz BW, CR 4/5)
- **Default mode**: ble-gateway
- **Preamble**: 16 symbols
- **Sync word**: 0x2B (Meshtastic-specific)
- **Encryption**: AES-128-CTR with default PSK
- **XB-200**: Auto-detected at startup

## BladeRF x40 Notes

- TX power: ~+6 dBm (lower than dedicated LoRa modules at +14 to +22 dBm)
- Min RF bandwidth: 1.5 MHz (software filtering handles narrower LoRa bandwidths)
- Sample format: SC16_Q11 (12-bit I/Q as int16)
- Full frequency coverage: 300 MHz - 3.8 GHz (covers all Meshtastic bands)
- XB-200 transverter: Extends range down to 60 kHz (needed for 433 MHz bands)

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Project Structure

```
src/meshtastic_sdr/
  radio/          - Radio backend abstraction (BladeRF, simulated loopback)
  lora/           - LoRa PHY: CSS modulation, FEC encoding, packet framing
  protocol/       - Meshtastic protocol: 16-byte header, AES-CTR, protobuf
  mesh/           - Mesh networking: node identity, flood routing, send/receive API
  transport/      - Packet-level transport abstraction (SDR, BLE)
  ble/            - BLE Central (tether) and Peripheral (gateway) modes
  cli/            - CLI entry point
```

## Supported Regions

All 27 Meshtastic regions are defined in `config/regions.json`: US, EU_433, EU_868, CN, JP, ANZ, KR, TW, RU, IN, NZ_865, TH, UA_433, UA_868, MY_433, MY_919, SG_923, LORA_24, and more.