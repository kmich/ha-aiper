# Aiper Pool Cleaner (Home Assistant)

Custom Home Assistant integration for Aiper pool cleaners.

## Installation

### HACS (recommended)
1. In HACS → Integrations → 3-dots → **Custom repositories**
2. Add this repository URL as **Integration**
3. Install and restart Home Assistant

### Manual
Copy `custom_components/aiper` into your Home Assistant `config/custom_components/` folder and restart.

## Configuration
Add the integration via **Settings → Devices & Services → Add Integration → Aiper Pool Cleaner**.

## Notes
- This integration uses Aiper's cloud + AWS IoT (MQTT) control plane.
- Set device “Clean Path” is applied via downChan to ensure it takes effect on supported models/regions.

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

(Any image works — it’s purely cosmetic.)
