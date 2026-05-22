# Aiper Pool Cleaner

![Aiper Pool Cleaner icon](custom_components/aiper/brand/icon.png)

Home Assistant custom integration for Aiper pool cleaners. It connects to
Aiper's cloud REST API and AWS IoT MQTT control plane to expose live pool
cleaner state and supported controls in Home Assistant.

## Features

- Config flow setup from the Home Assistant UI.
- Live MQTT-backed device state for supported cleaners.
- Device sensors, binary sensors, switches, selects, and diagnostics based on
  model capabilities.
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
Do not merge files into an older copy because releases may remove Python
modules.

## Configuration

1. Open **Settings -> Devices & Services**.
2. Select **Add Integration**.
3. Search for **Aiper Pool Cleaner**.
4. Sign in with the Aiper account used by the mobile app.

The integration uses Aiper's cloud services. Credentials, tokens, serial
numbers, and MQTT payloads should be treated as sensitive when sharing logs or
diagnostics.

## Entities

The available entities depend on the cleaner model and the capabilities Aiper
reports for it. Supported surfaces can include:

- Cleaner state, battery, charging, error, warning, and consumable sensors.
- Online and runtime binary sensors.
- Switch controls such as supported cleaner start/stop paths.
- Select controls for supported cleaning mode and clean-path choices.

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
