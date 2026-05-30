# Aiper Pool Cleaner & Water Quality Monitor

[![HACS][hacs-badge]][hacs-url]
[![GitHub Release][release-badge]][release-url]
[![License][license-badge]][license-url]
[![Validate][validate-badge]][validate-url]

![Aiper Pool Cleaner icon](custom_components/aiper/brand/icon.png)

Home Assistant custom integration for Aiper pool cleaners and water quality monitors. Connects to Aiper's cloud REST API and AWS IoT MQTT control plane to expose live device state and controls in Home Assistant.

**Supported device families:**
- **Pool cleaners** — Scuba X1, Surfer S2, Shark, and compatible models
- **Water quality monitors** — HydroComm, HydroComm Pro/Pure, HydroHub, HydroHub Pro, W2 series

## What's New in v1.0.0

### HydroComm / W2 Water Quality Monitor Support
Full MQTT shadow support for the HydroComm/W2 family. All live sensor data is parsed and exposed as Home Assistant entities:

- **Water chemistry** — pH, ORP, EC, TDS, Free Chlorine (mg/L), Water Quality Score
- **Probe management** — per-probe install status, serial number, usage time, and calibration timestamp for up to 3 probes + ultrasonic sensor
- **Power & charging** — battery level, charge type (mains/solar), solar charging state, supply voltage, solar voltage, light level, work current, charge current
- **Station status** — Idle / Active / Charging / Updating / Sleeping / Deep Sleep states
- **Alarms** — full bitmask decoding of probe, sensor, and battery warnings into readable text
- Cleaner-only entities (mode, running, clean path, consumables, history) are automatically hidden for monitor devices

### X1 Charging & Status Fix
Corrected status code handling for the Scuba X1: charging state is now correctly detected and the mode entity no longer flips during charging cycles.

## Features

- Config flow setup from the Home Assistant UI.
- Live MQTT-backed device state with AWS IoT WebSocket transport.
- Model-capability profiles — each device family only exposes the entities it actually supports.
- HACS release ZIPs for normal installs and upgrades.

## Installation

### HACS (recommended)

1. In HACS, open **Integrations**.
2. Open the three-dot menu and choose **Custom repositories**.
3. Add `https://github.com/kmich/ha-aiper` as an **Integration** repository.
4. Install **Aiper Pool Cleaner** and restart Home Assistant.

### Manual

1. Copy `custom_components/aiper` from this repository into
   `config/custom_components/aiper` in Home Assistant.
2. Restart Home Assistant.

For upgrades, replace the whole `config/custom_components/aiper` directory.
Do not merge files into an older copy because releases may remove Python modules.

## Configuration

1. Open **Settings -> Devices & Services**.
2. Select **Add Integration**.
3. Search for **Aiper Pool Cleaner**.
4. Sign in with the Aiper account used by the mobile app.

The integration uses Aiper's cloud services. Credentials, tokens, serial numbers, and MQTT payloads should be treated as sensitive when sharing logs or diagnostics.

## Entities

The entities exposed depend on the device family and the capabilities Aiper reports for it.

### Pool Cleaners (Scuba X1, Surfer S2, Shark)

| Entity | Type | Notes |
|--------|------|-------|
| Status | Sensor | Live cleaner state |
| Battery | Sensor | % |
| Charging | Binary sensor | |
| Solar Charging | Binary sensor | Where supported |
| Running | Binary sensor | |
| Warning | Sensor | Decoded error text |
| Mode | Sensor | Current cleaning mode |
| Cleaning Mode | Select | Change cleaning mode |
| Clean Path | Select | Where supported |
| Running | Switch | Surfer S2 start/stop |
| Roller Brush | Sensor | Consumable % remaining |
| Micromesh Filter | Sensor | Consumable % remaining |
| Caterpillar Tread | Sensor | Consumable % remaining |
| Propeller | Sensor | Consumable % remaining |
| Total Cleanings | Sensor | Lifetime count |
| Total Cleaning Time | Sensor | Lifetime hours |
| Last Cleaning Mode | Sensor | |
| Last Cleaning Start | Sensor | Timestamp |
| Last Cleaning Duration | Sensor | Minutes |
| Firmware Version | Sensor | Diagnostic |
| OTA State | Sensor | Diagnostic |
| Online | Binary sensor | |

### HydroComm / W2 Water Quality Monitors

| Entity | Type | Notes |
|--------|------|-------|
| Status | Sensor | Idle / Active / Charging / Updating / Sleeping / Deep Sleep |
| Battery | Sensor | % |
| Charging | Binary sensor | |
| Solar Charging | Binary sensor | |
| Charge Type | Sensor | Not charging / Charging / Solar charging |
| Warning | Sensor | Decoded alarm text (probe, sensor, and battery alarms) |
| pH | Sensor | With sample timestamp attribute |
| ORP | Sensor | mV, with sample timestamp attribute |
| EC | Sensor | µS/cm |
| TDS | Sensor | ppm |
| Free Chlorine | Sensor | mg/L |
| Water Quality Score | Sensor | 0–100 |
| Water Quality Result | Sensor | Diagnostic |
| Probe 1 / 2 / 3 Status | Sensor | Installed / Not installed; attributes: serial, usage time, calibration time |
| Ultrasonic Sensor Status | Sensor | Diagnostic |
| Calibration Status | Sensor | Idle / In progress |
| Supply Voltage | Sensor | mV, diagnostic |
| Solar Voltage | Sensor | mV, diagnostic |
| Light Level | Sensor | lx, diagnostic |
| Work Current | Sensor | mA, diagnostic |
| Charge Current | Sensor | mA, diagnostic |
| Firmware Version | Sensor | Diagnostic |
| Water Sample Time | Sensor | Diagnostic |
| Online | Binary sensor | |

## Development

Run a local Home Assistant container with the integration bind-mounted:

```bash
docker compose up
```

Then open Home Assistant at <http://localhost:8123>.

The container uses `ha-config/` as its Home Assistant config directory and
mounts this repository's `custom_components/` directory into it.

For local Python checks, install the development environment and run the focused
test suite:

```bash
uv sync --group dev
uv run pytest
```

## Troubleshooting

- If an upgrade leaves import errors mentioning removed Aiper modules, delete
  the existing `config/custom_components/aiper` directory and install the new
  one again.
- If live state or controls are unavailable, check that Home Assistant can
  reach Aiper cloud services and that the cleaner is online in the Aiper app.
- When reporting an issue, include Home Assistant logs and diagnostics after
  removing any secrets or identifying device data.

## Support

Report bugs and request features in the GitHub issue tracker.

## Lovelace examples

This repository includes ready-to-copy dashboard snippets:

- `lovelace/example-dashboard.yaml` (stock Lovelace)
- `lovelace/mushroom-example.yaml` (Mushroom cards)

### Optional device image (header)
Place an image at:

- `config/www/aiper/scuba_x1.png`

Then reference it from Lovelace as:

- `/local/aiper/scuba_x1.png`

(Any image works - it is purely cosmetic.)

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-41BDF5.svg
[hacs-url]: https://github.com/hacs/integration
[release-badge]: https://img.shields.io/github/v/release/kmich/ha-aiper
[release-url]: https://github.com/kmich/ha-aiper/releases
[license-badge]: https://img.shields.io/github/license/kmich/ha-aiper
[license-url]: https://github.com/kmich/ha-aiper/blob/main/LICENSE
[validate-badge]: https://img.shields.io/github/actions/workflow/status/kmich/ha-aiper/validate.yml?label=validate
[validate-url]: https://github.com/kmich/ha-aiper/actions/workflows/validate.yml
