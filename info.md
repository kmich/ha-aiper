# Aiper Pool Cleaner & Water Quality Monitor

Bring your Aiper pool cleaner and water quality monitor into Home Assistant. This integration automatically detects and connects to your Aiper cloud account to expose real-time telemetry and safe controls.

## Features
- **Pool Cleaners (Scuba X1, Surfer S2, Shark):** Live state, battery, cleaning mode controls, clean path preferences, Surfer S2 start/stop, and filter/brush consumable tracking.
- **Water Quality Monitors (HydroComm, W2 Series):** Live pH, ORP (mV), EC (µS/cm), TDS (ppm), Free Chlorine (mg/L), overall Water Quality Score, and bitmask-decoded alarm warnings.

## Configuration

To add the integration to Home Assistant, click the button below:

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=aiper)

Alternatively, follow these manual steps:
1. Open **Settings -> Devices & Services**.
2. Select **Add Integration**.
3. Search for **Aiper Pool Cleaner**.
4. Sign in with the Aiper account used by your mobile app.

---
> For advanced troubleshooting, security practices, and Lovelace dashboard examples, please view the full documentation on [GitHub](https://github.com/kmich/ha-aiper).


## Recent Changes

### v1.2.3
- Fixed HACS release notes layout bug by combining custom release notes with GitHub format.

### v1.2.2
- Fixed HACS release notes display timing issue by ensuring the GitHub Release is fully built before clients poll the new tag.

### v1.2.1
- Fixed empty release notes in HACS UI by dynamically injecting CHANGELOG.md snippets into GitHub Release tags.

### v1.2.0
- Removed "Experimental" tags from documentation. All supported models (Surfer S2, Shark, etc.) are now marked as "Verified".
