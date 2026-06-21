# Adoption Backlog

This backlog prioritizes engineering and documentation work based on what blocks adoption the most.

| Rank | Task | Impact | Effort | Priority | Notes |
|---|---|---|---|---|---|
| 1 | **README Rewrite** | High | Low | P0 | Needs to look like a product, not a script. Include screenshots. |
| 2 | **Issue Templates** | High | Low | P0 | Essential before launch to capture "Unsupported Model" payloads properly. |
| 3 | **HACS Default Submission** | High | High | P1 | Requires test coverage and HA Quality Scale audit. Will remove install friction. |
| 4 | **Dashboard Examples** | Med | Low | P1 | Provide YAML for Mushroom cards and stock HA cards. |
| 5 | **Session Conflict Fixes** | High | High | P2 | Investigate if we can use a different App ID or token scope to avoid kicking the mobile app out. |
| 6 | **Surfer S2 Validation** | Med | Med | P2 | Need a real S2 payload to move it from Experimental to Verified. |
| 7 | **Shark Validation** | Med | Med | P2 | Need a real Shark payload to move it from Experimental to Verified. |
| 8 | **Controller Tests** | Low | Med | P3 | Add tests for `controller.py` command failures. |
| 9 | **Diagnostic Entity Cleanup** | Med | Low | P3 | Ensure `entity_registry_enabled_default = False` for all low-value telemetry. |
