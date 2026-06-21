# Competitive and Ecosystem Positioning

## Product Statement
`ha-aiper` is the Home Assistant bridge for Aiper pool devices. It provides visibility, automations, alerts, dashboards, and safe basic controls within your smart home ecosystem.

## Who It Is For
- Smart home enthusiasts who want all their data in one place.
- Users who want to trigger automations based on pool status (e.g., "Turn on patio lights when Scuba X1 finishes cleaning").
- Users who want real-time alerts for water quality issues without opening a proprietary app.

## Who It Is Not For
- Users looking for **local, offline control**. (This integration relies on the Aiper cloud).
- Users who want to configure complex, initial device setup. (You must use the official Aiper app to link your device to WiFi first).
- Users expecting a 100% stable, officially supported API.

## Competitive Comparison

| Feature | Official Aiper App | `ha-aiper` (Home Assistant) |
|---|---|---|
| **Initial WiFi Pairing** | ✅ Yes | ❌ No |
| **Firmware Updates** | ✅ Yes | ❌ No (View only) |
| **Local/Offline Control**| ❌ No (Cloud only) | ❌ No (Cloud only) |
| **Custom Automations** | ❌ No | ✅ Yes (Infinite possibilities) |
| **Data History & Graphs**| ⚠️ Limited | ✅ Yes (via HA Recorder/InfluxDB) |
| **Unified Dashboards** | ❌ No | ✅ Yes |
| **Water Chemistry Alerts**| ✅ Yes (Push notifications) | ✅ Yes (Custom TTS, Telegram, etc.) |

## Positioning Strategy
> "`ha-aiper` is not a replacement for the Aiper app. You still need the official app to set up your device and install firmware updates. However, once connected, `ha-aiper` frees your data, allowing you to build the ultimate automated pool experience."
