# Aiper Pool Cleaner & Water Quality Monitor

Bring your Aiper pool cleaner and water quality monitor into Home Assistant. This integration automatically detects and connects to your Aiper cloud account to expose real-time telemetry and safe controls.

## Features
- **Pool Cleaners (Scuba S1, Scuba X1, Surfer S2, Shark):** Live state, battery, cleaning mode controls, clean path preferences, Surfer S2 start/stop, and supported consumable tracking.
- **Water Quality Monitors (HydroComm, W2 Series):** Live pH, ORP (mV), EC (µS/cm), TDS (ppm), Free Chlorine (mg/L), overall Water Quality Score, and bitmask-decoded alarm warnings.
- **Cloud connection health:** An "Aiper Cloud" device with Cloud Connected, Connection State, and Last Cloud Update entities so automations can react when the cloud link drops.
- **Guided recovery:** A Repairs prompt for an unrecognized device model or rejected credentials, instead of the integration failing silently.

## Configuration

To add the integration to Home Assistant, click the button below:

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=aiper)

Alternatively, follow these manual steps:
1. Open **Settings -> Devices & Services**.
2. Select **Add Integration**.
3. Search for **Aiper Pool Cleaner**.
4. Sign in with the Aiper account used by your mobile app.

---
> **Dashboard cards:** the companion [**ha-aiper-card**](https://github.com/kmich/ha-aiper-card) adds purpose-built Lovelace cards for the cleaner and the water quality monitor. Install it in HACS as a **Dashboard** custom repository.
>
> For advanced troubleshooting, security practices, and Lovelace dashboard examples, please view the full documentation on [GitHub](https://github.com/kmich/ha-aiper).


## Recent Changes

### v1.4.0
- Added an "Aiper Cloud" device exposing connection health: Cloud Connected, Connection State, and Last Cloud Update.
- Added Repairs issues for unrecognized device models (links the model onboarding guide) and for rejected credentials (triggers re-authentication).
- Added an internal MQTT connection-status tracker so diagnostics report one authoritative connection state, plus a redacted one-command model-onboarding bundle for reporting new hardware.

### v1.3.1
- Fixed config-entry diagnostics reading a stale storage location, so `mqtt_connected` and the signing/reconnect counters always read wrong on a live install.
- Fixed OpenID token renewal for regions whose `getOpenIdToken` response omits `tokenDuration`; a Cognito 4xx now triggers one bounded refresh and retry.

### v1.3.0
- Added hardware-verified `Scuba_S1_2025` clean-path and cleaning-mode support (Auto, Floor, Wall, Scheduled) with a dedicated capability profile.
- Fixed MQTT reconnection after AWS credential expiry: the credential signer now reads a live snapshot and a watchdog forces a full reconnect (including resubscribing) after a grace period.

### v1.2.4
- Fixed Scuba S3 reporting charging as "Returning" and full charge as "Charging", which left the charging sensor inverted. Status codes are now interpreted per model; other models are unchanged.
