# Aiper Pool Cleaner & Water Quality Monitor

[![HACS][hacs-badge]][hacs-url] [![GitHub Release][release-badge]][release-url] [![Validate][validate-badge]][validate-url]

**Bring your Aiper pool cleaner and water quality monitor into Home Assistant.**  
View live status, battery, charging state, cleaning modes, consumables, and water chemistry (pH, ORP, Chlorine) alongside safe controls, directly in your smart home dashboard.

> [!WARNING]
> **Unofficial & Cloud-Based**
> This integration uses Aiper's cloud services (REST and AWS IoT MQTT). It is unofficial and not affiliated with Aiper. Because it relies on reverse-engineered cloud APIs, an update to the Aiper app or firmware could break functionality. Please read the [Security & Privacy Guide](docs/trust/security-privacy.md) before installing.

## Supported Models

| Cleaners | Monitors |
|---|---|
| ✅ **Scuba S1 (2025/2026)** | ✅ **HydroComm** |
| ✅ **Scuba X1** | ✅ **HydroComm Pro / W2 Series** |
| ✅ **Surfer S2** | |
| ✅ **Shark** | |

The current 2026 retail Scuba S1 identifies itself through Aiper's cloud as
`Scuba_S1_2025`; both names refer to the verified model listed above.

*(Don't see your model? We need your help! Check our [Diagnostics Guide](docs/support/diagnostics-and-troubleshooting.md) for how to submit a payload.)*

---

## 🚀 Installation

### HACS (Recommended)

1. In HACS, open **Integrations**.
2. Open the three-dot menu and choose **Custom repositories**.
3. Add `https://github.com/kmich/ha-aiper` as an **Integration** repository.
4. Install **Aiper Pool Cleaner** and restart Home Assistant.

### Configuration

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=aiper)

1. Open **Settings -> Devices & Services**.
2. Select **Add Integration**.
3. Search for **Aiper Pool Cleaner**.
4. Sign in with the Aiper account used by the mobile app.

---

## 📊 Features & Entities

The integration uses "capability profiles" to automatically expose only the features your device supports.

- **Pool Cleaners:** Live state, battery, cleaning mode controls, clean path preferences, Surfer S2 start/stop, and filter/brush consumable tracking.
- **Water Quality Monitors:** Live pH, ORP (mV), EC (µS/cm), TDS (ppm), Free Chlorine (mg/L), overall Water Quality Score, and bitmask-decoded alarm warnings.
- **Cloud Connection Health:** A dedicated "Aiper Cloud" device with `binary_sensor.aiper_cloud_cloud_connected`, a `Connection State` sensor, and a `Last Cloud Update` timestamp — so an automation can alert you when the integration loses its cloud/MQTT link.
- **Device Actions:** Safe buttons to force-refresh cloud metadata or re-sync the MQTT shadow state.
- **Guided Recovery:** Home Assistant **Repairs** entries appear when a device model is not recognized (with a link to the onboarding guide) or when your stored credentials stop working (starts re-authentication).

*(Note: Diagnostic telemetry like raw voltages, currents, and lifetime cleaning hours are hidden by default to keep your dashboard clean. You can enable them manually in the entity registry.)*

---

## 📖 Documentation & Support

If you encounter issues, please read our guides before opening a ticket:

- [Diagnostics & Troubleshooting Guide](docs/support/diagnostics-and-troubleshooting.md) - Learn how to redact your logs safely.
- [Security & Privacy Guide](docs/trust/security-privacy.md) - What data leaves your network and how your credentials are used.
- [Entity Taxonomy](docs/product/entity-taxonomy.md) - Full list of exposed entities.
- [Automation Examples](docs/examples/automations.md) - Copy/paste snippets for alerts and routines.

---

## Lovelace Dashboards

### Custom cards (recommended)

[**ha-aiper-card**](https://github.com/kmich/ha-aiper-card) is a companion set of
Lovelace cards built for this integration:

- **Aiper Cleaner Card** – status, battery, connectivity, warnings, cleaning-mode
  and clean-path chips, start/stop, consumable wear.
- **Aiper Water Quality Card** – water-quality score, pH / ORP / chlorine / TDS /
  EC gauges, temperature and sample age.

Install it via HACS as a **Dashboard** custom repository
(`https://github.com/kmich/ha-aiper-card`). Point a card at your Aiper device and
it wires up the entities itself.

### Plain YAML examples

If you prefer stock cards, copy-paste YAML lives in this repository:
- `lovelace/example-dashboard.yaml` (stock Lovelace)
- `lovelace/mushroom-example.yaml` (Mushroom cards)

To use the device headers, place an image (like `docs/assets/scuba_x1.png`) into `config/www/aiper/` and reference it as `/local/aiper/scuba_x1.png` in your cards.

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-41BDF5.svg
[hacs-url]: https://github.com/hacs/integration
[release-badge]: https://img.shields.io/github/v/release/kmich/ha-aiper
[release-url]: https://github.com/kmich/ha-aiper/releases
[validate-badge]: https://img.shields.io/github/actions/workflow/status/kmich/ha-aiper/validate.yml?label=validate
[validate-url]: https://github.com/kmich/ha-aiper/actions/workflows/validate.yml
