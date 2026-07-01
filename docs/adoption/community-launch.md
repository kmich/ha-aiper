# Community Launch Materials

## 1. Home Assistant Forum Post Template

**Title:** [Custom Component] Aiper Pool Cleaners & Water Monitors (Scuba, Surfer, HydroComm)

**Body:**
Hi everyone,

I've been working on an unofficial integration for **Aiper** pool devices, and it's finally ready for broader testing. If you have an Aiper Scuba X1, Surfer S2, or one of the new HydroComm water quality monitors, you can now bring them into Home Assistant!

### Features
* Live battery, charging, and mode status.
* Water chemistry metrics (pH, ORP, EC, TDS, Chlorine) for HydroComm.
* Start/Stop and Cleaning Mode controls.
* Consumables tracking (filter/brush life).

### Important Note
**This is an unofficial, cloud-based integration.** It uses Aiper's REST API and AWS IoT MQTT broker. It is not local.

### Supported Devices
* **Verified:** Scuba X1, HydroComm
* **Verified:** Surfer S2, Shark, W2 Series

### Installation
It's available via HACS as a custom repository.
1. Add `https://github.com/kmich/ha-aiper` as an Integration repository in HACS.
2. Install, restart, and add the "Aiper" integration via the UI.

I’m looking for testers, especially for the Surfer and Shark models. If you encounter issues, please check the [Diagnostics Guide](https://github.com/kmich/ha-aiper/blob/main/docs/support/diagnostics-and-troubleshooting.md) and open an issue!

---

## 2. Reddit Post Template (r/homeassistant)

**Title:** I built an unofficial integration for Aiper Pool Cleaners and Water Monitors

**Body:**
Hey r/homeassistant!
If you have an Aiper robot (Scuba X1, Surfer S2) or a HydroComm water monitor, I’ve put together a HACS custom integration to get your data out of the app and into your dashboards.

*   **What it does:** Pulls live MQTT state (battery, cleaning modes, water chemistry like pH/ORP, consumables). It also supports basic controls like changing cleaning modes or starting/stopping.
*   **The Catch:** It's 100% cloud-based (relies on their AWS IoT setup). Unfortunately, there's no local API. Also, because they only allow one active session, you can't have the official mobile app open at the exact same time as HA is polling it (you'll get a session conflict).

Check out the repo here: [Link]
I'd love feedback from anyone with a Surfer or Shark model, as I need raw payloads to verify the reverse engineering!

---

## 3. Launch Checklist
- [ ] `README.md` is rewritten with the "conversion funnel" structure.
- [ ] Screenshots are uploaded to `docs/assets/`.
- [ ] `v1.1.0` is released on GitHub.
- [ ] Ensure all issue templates (Bug, Model Support) are merged.
- [ ] Post to Home Assistant Community Forum.
- [ ] Post to Reddit.
