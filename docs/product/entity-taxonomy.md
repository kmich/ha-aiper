# Entity Taxonomy

This document classifies every entity exposed by `ha-aiper`. The goal is to provide a clean UX by disabling low-value diagnostic entities by default, focusing the user's dashboard on what matters: "Is my robot running?" and "Is my water safe?"

| Entity | Platform | Family | Default | Category | Purpose | Automation Use |
|---|---|---|---|---|---|---|
| **Online** | Binary Sensor | All | **Enabled** | Diagnostic | Cloud connection state | Yes (Alert if offline) |
| **Status** | Sensor | All | **Enabled** | None | Live cleaner/monitor state | Yes (Trigger on 'Idle') |
| **Battery** | Sensor | All | **Enabled** | None | Battery % | Yes (Low battery alert) |
| **Charging** | Binary Sensor | All | **Enabled** | None | Wall charging state | No |
| **Solar Charging** | Binary Sensor | Supported | **Enabled** | None | Solar charging state | No |
| **Warning** | Sensor | All | **Enabled** | None | Decoded error text | Yes (Alert on warning) |
| **Mode** | Sensor | Cleaners | **Enabled** | None | Current cleaning mode | Yes |
| **Cleaning Mode** | Select | Cleaners | **Enabled** | None | Change cleaning mode | Yes (Set before schedule) |
| **Clean Path** | Select | Scuba | **Enabled** | None | Change pathing algorithm | No |
| **Running** | Switch | Surfer | **Enabled** | None | Start/stop cleaning | Yes |
| **pH / ORP / EC / TDS / Chlorine** | Sensor | Monitors | **Enabled** | None | Core water chemistry | Yes (Alert if out of bounds) |
| **Water Quality Score** | Sensor | Monitors | **Enabled** | None | Global water safety metric | Yes |
| **Consumables (Brush/Filter/etc.)**| Sensor | Cleaners | **Enabled** | None | Wear items % | Yes (Alert if < 10%) |
| **Total Cleanings / Time** | Sensor | Cleaners | Disabled | Diagnostic | Lifetime metrics | No |
| **Last Cleaning Stats** | Sensor | Cleaners | Disabled | Diagnostic | Previous run metrics | No |
| **Firmware Version** | Sensor | All | Disabled | Diagnostic | Version string | No |
| **OTA State** | Sensor | Cleaners | Disabled | Diagnostic | Update progress | No |
| **Probe Status (1/2/3/Ultrasonic)** | Sensor | Monitors | Disabled | Diagnostic | Hardware install state | No |
| **Calibration Status** | Sensor | Monitors | Disabled | Diagnostic | Ongoing calibration check | No |
| **Voltage / Current / Light Level** | Sensor | Monitors | Disabled | Diagnostic | Raw hardware telemetry | No |
| **Water Sample Time** | Sensor | Monitors | Disabled | Diagnostic | Exact sensor read time | No |
| **Refresh Shadow** | Button | All | **Enabled** | None | Manual MQTT sync | No |
| **Refresh Metadata** | Button | All | **Enabled** | None | Manual REST sync | No |
| **Clear Command State** | Button | All | Disabled | Diagnostic | Reset local command tracking | No |
