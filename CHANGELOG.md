# Changelog

## [1.3.0] - 2026-08-30

### Added
- Added hardware-verified `Scuba_S1_2025` clean-path support using the official
  app's `AT+AUTO?` query and `AT+AUTO=0/1` set contract. This model no longer
  uses speculative REST, shadow, or fallback command variants for clean path.
- Added the app-derived `Scuba_S1_2025` cleaning-mode profile: Auto, Floor,
  Wall, and Scheduled. The S1 now queries with `AT+MODE?`, writes only the
  corresponding `AT+MODE=1/2/3/5` commands, and no longer exposes Waterline.
- Added bounded S1 clean-path write confirmation so stale immediate readback
  cannot briefly revert a newly acknowledged selection in Home Assistant.
- Added an explicit S1 capability profile that retains the observed MicroMesh
  consumable while suppressing unsupported temperature, charge-type, roller,
  tread, and propeller entities. Thanks to @rellerton for the hardware
  verification that made S1 support possible.

### Fixed
- Fixed `Scuba_S1_2025` post-cycle charging reconciliation. A fresh REST
  charging status now supersedes an hours-old MQTT Cleaning/Wet report and
  coherently reports Charging, Not running, Dry, Mode 0, and zero active
  cleaning runtime, but a fresher MQTT report showing the device still
  actively cleaning is never overridden by a stale REST snapshot. If explicit
  status is absent, three increasing battery samples spanning at least two
  minutes may provide the same fallback only when no newer MQTT Machine
  report exists. Diagnostics identify the trigger used. Other device models
  retain the existing MQTT precedence.
- Fixed the S1 flipping from Wet to Dry when a fresh REST poll reports Cleaning
  together with a stale `in_water=0`. For this model, active Cleaning is always
  Wet. Observed status 10 represents parking underwater and remains Wet when
  REST omits a newer water-state report.
- Fixed MQTT reconnection after AWS credential expiry (#27). AWS Cognito
  credentials are temporary (~55 min); the MQTT client previously couldn't
  refresh them, so once they expired the connection could go down and never
  come back. The credential signer now reads a non-blocking snapshot kept
  current by the coordinator, and a watchdog forces a full reconnect —
  including resubscribing any device that never got subscribed in the first
  place — if the connection stays down past a grace period. Entity setup no
  longer waits on MQTT to connect, and a slow reconnect attempt no longer
  delays the REST polling that keeps working while MQTT is down.

## [1.2.4] - 2026-08-06

### Fixed
- Fixed Scuba S3 reporting charging as "Returning" and full charge as "Charging". On Scuba S3 firmware V3.0.0 the device reports status code `2` for the entire charge and switches to `3` only once the battery reaches 100%, which left `binary_sensor.charging` inverted — off while charging, on when full. Status codes are now interpreted per model, so `binary_sensor.charging` is on throughout the charge, the status sensor reads "Charging" then "Charged", and `binary_sensor.running` no longer reports on while the robot sits on the charger. Other models keep the existing status encoding unchanged. Thanks to @chriguschneider for the detailed payload captures and the fix.

## [1.2.3] - 2026-07-01

### Fixed
- Fixed HACS release notes layout bug by combining custom release notes with GitHub's `generate_release_notes` format.

## [1.2.2] - 2026-07-01

### Fixed
- Fixed HACS release notes display timing issue by ensuring the GitHub Release is fully built before clients poll the new tag.

## [1.2.1] - 2026-07-01

### Fixed
- Fixed empty release notes in HACS UI by dynamically injecting CHANGELOG.md snippets into GitHub Release tags.

## [1.2.0] - 2026-07-01

### Added
- Added HA 2024.4+ Compliance using `ConfigEntry` typing (`AiperRuntimeData`).
- Added HACS `info.md` with "My Home Assistant" badges for simplified installation.
- Expanded device support: Surfer S2, HydroComm Pro, W2 Series, and Shark are now marked as officially Verified.

### Changed
- Refactored all platform files to remove legacy `hass.data` dictionary access.
- Updated integration Quality Scale to Silver tier compliance.

### Fixed
- Fixed Config Flow handling with proper error class routing (`CannotConnect`, `InvalidAuth`, `SessionConflict`, `InvalidResponse`).
- Fixed helper function `EntityState` object evaluation bugs leading to missing entities and incorrect device names.

## [1.1.0] - 2026-06-21

### Added

- **Adoption & Trust Overhaul** — Complete rewrite of the integration README to clarify cloud dependencies and highlight supported models.
- **Diagnostic Safety** — Added automated GitHub issue templates to guide users in submitting safe, redacted diagnostics for unsupported models.
- **Entity UX** — Disabled low-value telemetry sensors by default to declutter new user dashboards.
- **Manual State Recovery** — Added safe per-device buttons for Refresh Shadow, Refresh Metadata, and disabled-by-default Clear Command State.

## [1.0.5] - 2026-06-05

### Fixed

- **HA 2026.6 compatibility** — `OptionsFlowHandler` no longer overrides `__init__` to store `config_entry`; it now uses the native `self.config_entry` property injected by the framework, eliminating a deprecated pattern that would break in a future HA release.

## [1.0.4] - 2026-06-02

### Fixed

- **Surfer S2** — Last Cleaning Duration and Total Cleaning Time sensors now populate correctly for S2 devices whose history API uses `cleanTimeMin` (integer minutes) or related `cleanTimeMinute` / `cleaningTimeMin` / `cleanTimeSec` / `cleanTimeHour` keys. Unit detection is now key-name-aware so no ambiguous heuristic applies to those fields.
- **Surfer S2** — Solar Charging binary sensor now updates from MQTT payloads that send `solarStatus` (camelCase) instead of `solar_status`.
- **All devices** — Stale "Unavailable" consumable entities left over from v0.7.0 (Roller Brush Remaining, Roller Brush Remaining %, MicroMesh Filter Remaining, etc.) are automatically removed from the entity registry on startup. Those entities were replaced by consolidated percent sensors (Roller Brush, MicroMesh Filter, Caterpillar Tread) in a prior refactor; the old registrations persisted and caused the duplicate-entity appearance in the Diagnostics view.
- Added debug-level logging of the raw and parsed cleaning history response to assist future diagnostics.

## [1.0.1] - 2026-05-26

### Fixed

- **Scuba X1** — status and charging sensors no longer flip between Returning/Charging/Idle during normal operation: the REST 5-minute refresh now only overwrites machine state (running, status, charging, mode) when no authoritative MQTT data has been received yet; once MQTT establishes live state those fields are preserved across REST polls.
- **Scuba X1** — REST protection gate corrected: a fallback "Idle" status (produced before the first MQTT shadow arrives) is no longer mistaken for authoritative live state, allowing REST to correctly populate Charging status on startup.

## [1.0.0] - 2026-05-26

### Added

#### HydroComm / W2 Water Quality Monitor Support
- Full MQTT shadow parsing for the HydroComm/W2 device family (HydroComm, HydroComm Pro/Pure, HydroHub, HydroHub Pro, W2 series).
- Water chemistry sensors: pH, ORP, EC, TDS, Free Chlorine (mg/L), Water Quality Score, Water Quality Result. All readings carry a `sample_time` attribute from the shadow payload.
- Probe management: per-probe install status (Installed / Not installed) for probes 1–3 and the ultrasonic sensor, each with `probe_serial`, `usage_time`, and `calibration_time` attributes merged from `W2LifeTime` payloads.
- Charging telemetry: binary Charging and Solar Charging sensors, Charge Type text sensor (Not charging / Charging / Solar charging), Supply Voltage, Solar Voltage, Light Level, Work Current, Charge Current.
- Calibration Status sensor (Idle / In progress).
- HydroComm-specific station status labels: Idle, Active, Charging, Updating, Sleeping, Deep Sleep.
- Alarm/warning decoding: full bitmask decode of `W2AlarmMessage` into readable text (probe install errors, sensor damage, out-of-range readings, battery low, etc.), with individual alarm codes exposed as attributes.
- New capability flags: `CHARGING`, `WATER_QUALITY`, `PROBE_STATUS` used to gate entity publication by device family.
- `include_fn` predicate on binary sensor descriptions so the `running` binary sensor is suppressed for monitor devices.
- Cleaner-only entities (mode, running, clean path, consumables, cleaning history) are automatically hidden for HydroComm devices.

#### General
- `workflow_dispatch` trigger added to CI, Validate, and Release workflows for manual re-runs.

### Fixed

- **Scuba X1** — charging state and mode entity no longer misbehave during charging cycles: status code 3 (`CHARGING`) is now consistently mapped to `charging = True` and the mode entity is suppressed while the cleaner is not running.
- `normalize_device_state` now initialises all HydroComm entity keys to stable `None` states at setup time so Home Assistant creates the entities before the first MQTT shadow report arrives.

## Earlier Development Notes

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
