# Changelog

This changelog tracks local modernization work intended for a future pull request back to the upstream Aiper Home Assistant integration.

## Unreleased

### Added

- Added repo-level `AGENTS.md` with architecture notes, working rules, and modernization priorities for future agent sessions.
- Added `uv` development tooling with `pyproject.toml` and `uv.lock`.
- Added local Home Assistant development runtime via `docker-compose.yml` and `ha-config/configuration.yaml`.
- Added initial pytest suite covering config-flow validation helpers, diagnostics redaction, parser normalization, warning code handling, and consumable parsing.
- Added service dispatch tests for the raw AT-command service across multiple loaded config entries.
- Added Australia as a first-class region option backed by the Asia/Pacific Aiper API.
- Added a Surfer S2 propeller maintenance timestamp sensor when the consumables endpoint reports propeller maintenance data.
- Added AWS IoT Device SDK v2 MQTT transport for SigV4 WebSocket notifications.
- Added model-family and capability profiles for Aiper's Scuba X1, Surfer S2, Shark devices.

### Changed

- Documented development commands in `README.md`.
- Expanded `.gitignore` for Python tooling, Home Assistant runtime files, and generated caches.
- Normalized parsed Aiper datetime values to UTC-aware datetimes before exposing them to Home Assistant timestamp sensors.
- Refactored `aiper.send_at_command` to register once at integration setup and dynamically dispatch to the config entry that owns the requested serial number.
- Cleaned up lint issues surfaced by the new Ruff configuration.
- Gated Scuba-only clean-path and fallback mode controls so Surfer S2 does not inherit unproven control entities.
- Replaced the legacy `AWSIoTPythonSDK` dependency with `awsiotsdk`.
- Made MQTT the primary live-state update path when enabled, with REST polling retained as fallback and slow metadata reconciliation.
- Updated the integration manifest IoT class to `cloud_push`.
- Switched model-specific entity and select setup to profile capabilities instead of scattered model-name checks.

### Fixed

- Fixed config-flow test scaffolding so tests run through the `uv` managed Python environment.
- Fixed Surfer S2 cleaning history parsing for long skimming runs that report explicit `cleanTimeMin` values.
- Fixed `tools/aiper_probe.py` so `AIPER_REGION` is honored when `--region` is not provided.
- Fixed AWS IoT MQTT connection setup by using the Cognito identity ID as the MQTT client ID required by Aiper's IoT policy.
