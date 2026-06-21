# Test Gap Analysis

| Area | Existing Coverage | Missing Coverage | Risk | Recommended Test | Priority |
|---|---|---|---|---|---|
| **Config Flow** | ✅ Full coverage | None | Low | - | Low |
| **Auth / Session**| ✅ Good coverage | Reauth edge cases | Medium | Simulate 402 Session Conflict during live polling | Medium |
| **Parsers** | ✅ Excellent | Water monitor anomalies | Low | Feed corrupted/missing `W2Alarm` masks to `normalize_device_state` | High |
| **Capabilities** | ✅ Good coverage | Shark edge cases | Medium | Test Shark profile generation with mixed capability lists | Low |
| **Command Safety**| ⚠️ Basic API tests | Controller layer tests | High | Mock `AiperApi.set_cleaning_mode` to fail, ensure `controller.py` handles gracefully | **High** |
| **MQTT Lifecycle**| ⚠️ Reconnection tests | Stale state, Duplicate acks | High | Send out-of-order shadow updates to `coordinator.py` | **High** |
| **Diagnostics** | ✅ Redaction tests | Serial Number leakage | Medium | Ensure deep dict redaction catches `device_id` and `equipment_id` | Medium |
| **Translation** | ✅ Key checks | Parameterized strings | Low | Check translation mapping for dynamic warning codes | Low |

## Summary
The test suite is robust for API parsing and Home Assistant setup. The primary gaps are in the **Controller layer** (testing that UI button presses handle cloud failures gracefully) and **MQTT Lifecycle** (testing what happens when the device reconnects after a long offline period).
