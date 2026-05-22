# Changelog

This changelog tracks local modernization work intended for a future pull request back to the upstream Aiper Home Assistant integration.

## Unreleased

### Added

- Added repo-level `AGENTS.md` with architecture notes, working rules, and modernization priorities for future agent sessions.
- Added `uv` development tooling with `pyproject.toml` and `uv.lock` for pytest, Ruff, mypy, and Pyright checks.
- Added local Home Assistant development runtime via `docker-compose.yml` and `ha-config/configuration.yaml`.
- Added local Home Assistant brand icons for custom integration and HACS installs.
- Added ws-core-style CI, validation, and tag-triggered release workflows with GitHub-generated release notes.
- Added an Aiper bug report template for versioned, diagnostics-aware issue reports.
- Added pytest coverage for config-flow validation, diagnostics redaction, parser normalization, warning code handling, MQTT push updates, entity publication, command control, and probe helpers.
- Added translation coverage so `strings.json` and the English translation stay synchronized.
- Added a test that keeps discovery-only raw AT commands out of Home Assistant services.
- Added a Surfer S2 propeller maintenance timestamp sensor when the consumables endpoint reports propeller maintenance data.
- Added AWS IoT Device SDK v2 MQTT transport for SigV4 WebSocket notifications.
- Added model-family and capability profiles for Aiper's Scuba X1, Surfer S2, Shark, and unknown devices.
- Added a normalized device-state layer shared by sensors, binary sensors, switches, selects, diagnostics, and tests.
- Added a Surfer S2 Running switch using the verified MQTT AT-command control path.
- Added `metadata_refresh_hours` as the single slow cloud refresh option for device discovery metadata, device info, and consumables.

### Changed

- Documented development commands in `README.md`.
- Expanded the README and HACS display name for installation, configuration, entity, and troubleshooting guidance.
- Expanded `.gitignore` for Python tooling, Home Assistant runtime files, and generated caches.
- Tightened Ruff to the broader `ha_ws_core` lint families and cleaned up the imported code to pass them.
- Normalized parsed Aiper datetime values to UTC-aware datetimes before exposing them to Home Assistant timestamp sensors.
- Cleaned up lint issues surfaced by the new Ruff configuration.
- Gated controls and entities through typed capability profiles so Surfer S2, Scuba, Shark, and unknown devices only expose supported surfaces.
- Replaced the legacy `AWSIoTPythonSDK` dependency with `awsiotsdk`.
- Made MQTT required for live state and command control instead of treating it as optional push support.
- Changed the coordinator to run a slow metadata refresh instead of live REST polling; MQTT-owned state is preserved when cloud metadata is refreshed.
- Updated the integration manifest IoT class to `cloud_push`.
- Switched model-specific entity and select setup to profile capabilities instead of scattered model-name checks.
- Simplified consumables parsing to the probe-backed `/poolRobot/getConsumableList` contract: top-level `data` list, `consumableName`, `id`, and `maintainLastChangeTime`.
- Simplified control availability: controls are unavailable when MQTT is disconnected or the device explicitly reports offline.
- Renamed the Surfer on/off control surface to Running, including the switch unique ID, capability, controller command, and pending-command intent.
- Added short-lived pending intent handling for the Running switch so it does not flip back during device command lag.
- Moved raw-to-entity normalization out of platform modules and into the shared state layer to reduce duplicated fallback logic.
- Trimmed clean-path protocol probing to the currently retained endpoint set and removed redundant one-off wrapper functions.

### Removed

- Removed cleaning-history polling, parsing, sensors, dashboard references, and tests.
- Removed last-cleaning session entities and all-time cleaning count/hour entities.
- Removed REST live-state fallback polling, fast-poll windows, push-primary mode switching, and push reconciliation intervals.
- Removed legacy options for enabling MQTT, REST polling interval, history refresh, consumables refresh, clean-path refresh, and offline command queueing.
- Removed the misleading offline command queue behavior; commands are no longer allowed when a device explicitly reports offline.
- Removed broad consumables fallback wrappers and guessed percent/hour derivations that were not supported by probe evidence.
- Removed MQTT-only entity disable/enable migration code tied to optional MQTT mode.

### Fixed

- Fixed config-flow test scaffolding so tests run through the `uv` managed Python environment.
- Fixed config-flow validation so cloud connection failures are not reported as invalid credentials.
- Fixed config-flow validation so malformed Aiper responses are reported separately from authentication failures.
- Fixed the reauthentication form so its account placeholder is populated with the username being reauthorized.
- Fixed the release preflight so hassfest validates the integration before the local Home Assistant test environment is installed.
- Fixed REST retry exhaustion so repeated transport and retryable server failures stay classified as connection failures.
- Fixed `tools/aiper_probe.py` so `AIPER_REGION` is honored when `--region` is not provided.
- Fixed AWS IoT MQTT connection setup by using the Cognito identity ID as the MQTT client ID required by Aiper's IoT policy.
- Fixed device-info metadata storage to use a normal `payload` key instead of an internal `_payload` key.
