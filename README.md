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
| ✅ **Scuba X1** | ✅ **HydroComm** |
| ✅ **Surfer S2** | ✅ **HydroComm Pro / W2 Series** |
| ✅ **Shark** | |

*(Don't see your model? We need your help! Check our [Diagnostics Guide](docs/support/diagnostics-and-troubleshooting.md) for how to submit a payload.)*

---

## 🚀 Installation

### HACS (Recommended)

1. In HACS, open **Integrations**.
2. Open the three-dot menu and choose **Custom repositories**.
3. Add `https://github.com/kmich/ha-aiper` as an **Integration** repository.
4. Install **Aiper Pool Cleaner** and restart Home Assistant.

### Configuration

1. Open **Settings -> Devices & Services**.
2. Select **Add Integration**.
3. Search for **Aiper Pool Cleaner**.
4. Sign in with the Aiper account used by the mobile app.

---

## 📊 Features & Entities

The integration uses "capability profiles" to automatically expose only the features your device supports.

- **Pool Cleaners:** Live state, battery, cleaning mode controls, clean path preferences, Surfer S2 start/stop, and filter/brush consumable tracking.
- **Water Quality Monitors:** Live pH, ORP (mV), EC (µS/cm), TDS (ppm), Free Chlorine (mg/L), overall Water Quality Score, and bitmask-decoded alarm warnings.
- **Device Actions:** Safe buttons to force-refresh cloud metadata or re-sync the MQTT shadow state.

*(Note: Diagnostic telemetry like raw voltages, currents, and lifetime cleaning hours are hidden by default to keep your dashboard clean. You can enable them manually in the entity registry.)*

---

## 📖 Documentation & Support

If you encounter issues, please read our guides before opening a ticket:

- [Diagnostics & Troubleshooting Guide](docs/support/diagnostics-and-troubleshooting.md) - Learn how to redact your logs safely.
- [Security & Privacy Guide](docs/trust/security-privacy.md) - What data leaves your network and how your credentials are used.
- [Entity Taxonomy](docs/product/entity-taxonomy.md) - Full list of exposed entities.
- [Automation Examples](docs/examples/automations.md) - Copy/paste snippets for alerts and routines.

---

## Lovelace Dashboard Examples

You can find copy-paste YAML for beautiful dashboards in our repository:
- `lovelace/example-dashboard.yaml` (stock Lovelace)
- `lovelace/mushroom-example.yaml` (Mushroom cards)

To use the device headers, place an image (like `docs/assets/scuba_x1.png`) into `config/www/aiper/` and reference it as `/local/aiper/scuba_x1.png` in your cards.

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-41BDF5.svg
[hacs-url]: https://github.com/hacs/integration
[release-badge]: https://img.shields.io/github/v/release/kmich/ha-aiper
[release-url]: https://github.com/kmich/ha-aiper/releases
[validate-badge]: https://img.shields.io/github/actions/workflow/status/kmich/ha-aiper/validate.yml?label=validate
[validate-url]: https://github.com/kmich/ha-aiper/actions/workflows/validate.yml
