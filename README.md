# Aiper Pool Cleaner & Water Quality Monitor

[![HACS][hacs-badge]][hacs-url] [![GitHub Release][release-badge]][release-url] [![CI][ci-badge]][ci-url]

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
| 🧪 **Scuba P1 Pro** | |
| 🧪 **Scuba V3** | |

The current 2026 retail Scuba S1 identifies itself through Aiper's cloud as
`Scuba_S1_2025`; both names refer to the verified model listed above.

🧪 **Scuba P1 Pro** support is onboarded from a community diagnostics bundle
(no `temp` field; Roller Brush and MicroMesh Filter consumables) and has not
been verified on hardware by the maintainer. Reports welcome.

🧪 **Scuba V3** support is onboarded from community reports (issues #38, #49):
`machineStatus` 2/3 map to Charging/Charged as on the S3, and the
water-temperature entity is dropped. The cleaning-mode options are still the
generic Scuba set; the V3's real mode command IDs have not been captured yet.

*(Don't see your model? We need your help! Check our [Diagnostics Guide](docs/support/diagnostics-and-troubleshooting.md) for how to submit a payload.)*

---

## 🚀 Installation

Requires Home Assistant **2024.12** or newer.

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
4. Enter the details of the Aiper account used by the mobile app:
   - **Email / Phone** — the account login. Letter case and surrounding spaces
     are ignored when checking whether the account is already added.
   - **Password** — the Aiper account password.
   - **Region** — the Aiper cloud your account lives in: *Americas*, *Europe*
     or *Asia/Pacific* (the same region the mobile app uses).

Aiper allows one active session per account, so Home Assistant and the
mobile app can briefly log each other out. If setup reports a session
conflict, close the app, wait a few minutes and try again.

### Options

Open the integration's **Configure** menu to change:

| Option | Default | What it does |
|---|---|---|
| **Cloud metadata refresh interval (hours)** | 24 | How often slow-changing data (firmware, consumables, cleaning history) is fetched. 1–168 hours. |
| **MQTT debug logging** | Off | Logs raw MQTT topics and payloads at debug level and refreshes AWS credentials every 5 minutes, for troubleshooting only. |

### Reconfigure and re-authenticate

- To change the **region** or **password**, choose **Reconfigure** from the
  integration's menu in **Settings -> Devices & Services**.
- If Aiper rejects the stored password (at startup or later), Home Assistant
  shows a **re-authentication** prompt. Enter the new password there.

### Removing the integration

1. Open **Settings -> Devices & Services** and select **Aiper Pool Cleaner**.
2. Open the three-dot menu of the account entry and choose **Delete**.
3. Optionally remove the repository from HACS and restart Home Assistant.

Removing the integration does not change anything on your Aiper account or
devices.

---

## 📊 Features & Entities

The integration uses "capability profiles" to automatically expose only the features your device supports.

- **Pool Cleaners:** Live state, battery, estimated cleaning duration (Scuba S1), cleaning mode controls, clean path preferences, Surfer S2 start/stop, and filter/brush consumable tracking.
- **Water Quality Monitors:** Live pH, ORP (mV), EC (µS/cm), TDS (ppm), Free Chlorine (mg/L), overall Water Quality Score, and bitmask-decoded alarm warnings.
- **Cloud Connection Health:** A dedicated "Aiper Cloud" device with `binary_sensor.aiper_cloud_cloud_connected`, a `Connection State` sensor, and a `Last Cloud Update` timestamp — so an automation can alert you when the integration loses its cloud/MQTT link.
- **Device Actions:** Safe buttons to force-refresh cloud metadata or re-sync the MQTT shadow state.
- **Guided Recovery:** Home Assistant **Repairs** entries appear when a device model is not recognized (with a link to the onboarding guide) or when your stored credentials stop working (starts re-authentication, also after setup).

*(Note: Diagnostic telemetry like raw voltages, currents, and lifetime cleaning hours are hidden by default to keep your dashboard clean. You can enable them manually in the entity registry.)*

Entity names are translated into English, German, Spanish, French, Italian,
Dutch, Portuguese, Russian and Simplified Chinese.

### How data updates

- **MQTT push (live):** status, mode, battery, charging, water chemistry and
  other telemetry arrive over AWS IoT MQTT as soon as the device reports them.
- **REST poll (every 5 minutes):** the device list and online state are
  refreshed from Aiper's REST API, and act as a backstop when MQTT is quiet.
  Recent MQTT values win over REST for live fields; a REST value takes over
  once the MQTT value is more than 10 minutes old.
- **Metadata (every 24 hours by default):** firmware versions, consumables and
  cleaning history. Use the **Refresh Metadata** button to fetch it now.
- If REST fails for about 15 minutes while MQTT is also down, device entities
  become unavailable instead of showing stale data as current.

### Known limitations

- **Cloud only.** Nothing works without internet access and Aiper's cloud.
- **One session per account.** Using the mobile app at the same time can
  interrupt Home Assistant (and vice versa) for a few minutes.
- **Controls need the cloud link.** Start/stop is sent over MQTT and is
  unavailable while the MQTT link is down. Mode and clean-path changes prefer
  MQTT and fall back to REST where the model supports it. All controls are
  disabled while the robot reports offline, and sleeping or docked robots may
  ignore commands.
- **Unverified models.** Command formats are verified on hardware for the
  Scuba S1 and Surfer S2. Other models try the variants seen across Aiper
  firmware and remember the one that works.
- **New devices** added to your Aiper account after setup appear after
  reloading the integration.

### Use cases

- Get notified when the cleaner finishes, gets stuck, or its battery is low.
- Start a Surfer skim or set the Scuba cleaning mode from an automation.
- Alert when pH, free chlorine or ORP from a HydroComm monitor leaves a safe
  range.
- Track brush and filter wear and remind yourself to replace them.

See [Automation Examples](docs/examples/automations.md) for ready-made YAML.

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
[ci-badge]: https://img.shields.io/github/actions/workflow/status/kmich/ha-aiper/ci.yml?label=CI
[ci-url]: https://github.com/kmich/ha-aiper/actions/workflows/ci.yml
