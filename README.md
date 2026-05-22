# Aiper Pool Cleaner (Home Assistant)

Custom Home Assistant integration for Aiper pool cleaners.

## Installation

### HACS (recommended)
1. In HACS -> Integrations -> 3-dots -> **Custom repositories**
2. Add this repository URL as **Integration**
3. Install and restart Home Assistant

### Manual
Replace the existing `config/custom_components/aiper` directory with
`custom_components/aiper` from this repository and restart Home Assistant.
Do not merge files into an older copy; upgrades may remove Python modules.

## Configuration
Add the integration via **Settings -> Devices & Services -> Add Integration ->
Aiper Pool Cleaner**.

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

## Notes
- This integration uses Aiper's cloud + AWS IoT (MQTT) control plane.
- Set device "Clean Path" is applied via downChan to ensure it takes effect on
  supported models/regions.

## Support
- Issues: see the repository issue tracker.

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
