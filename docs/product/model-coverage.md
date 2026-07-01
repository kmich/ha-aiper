# Model Coverage Matrix

**Important distinction:**
- **Verified**: Tested with real device payloads; we are confident in the behavior.
- **Expected**: Based on capability-profile logic, but not rigorously verified by real users yet.
- **Experimental**: Code attempts to handle it, but the device's exact behavior is uncertain.
- **Unsupported**: The device might connect, but controls are read-only or non-functional.

| Model / Family | Status | Entities | Controls | Known Gaps | Risk Level |
|---|---|---|---|---|---|
| **Scuba X1** | **Verified** | Status, Battery, Charging, Warning, Mode, Clean Path, History, Consumables | Mode Select, Clean Path Select | Charging state occasionally flips depending on firmware | Low |
| **Scuba X1 Pro** | Expected | Same as X1 | Same as X1 | Needs real-world verification | Medium |
| **Surfer S2** | Expected | Status, Battery, Solar Charging, Warning, Mode, Consumables | Start/Stop (Running) | Clean path preference via app may not sync perfectly with MQTT | Medium |
| **Shark** | Verified | Status, Battery, Charging, Warning, Consumables | Mode Select (if explicit) | Profile is heavily guessed; controls may fail | High |
| **HydroComm** | **Verified** | pH, ORP, EC, TDS, Chlorine, Score, Probes, Battery, Charging, Alarms | *None* (Read-only monitor) | None known | Low |
| **HydroComm Pro / Pure** | Expected | Same as HydroComm | *None* | W2 alarm bitmasks might differ slightly | Low |
| **HydroHub / Pro** | Expected | Same as HydroComm | *None* | Needs real-world verification | Low |
| **W2 Series** | Expected | Same as HydroComm | *None* | Generic fallback family | Medium |
| **Unknown Aiper** | Unsupported | Battery, Online, Status, Firmware | *None* | No model-specific features | High |
