# Repository Instructions

## Purpose

This repository is a HACS-compatible Home Assistant custom integration for
Aiper pool cleaners. It connects to Aiper's cloud REST API and AWS IoT MQTT
control plane to expose sensors, binary sensors, switches, select controls, and
diagnostics.

## Stack

- Python Home Assistant custom component under `custom_components/aiper`.
- Home Assistant config flow, options flow, `DataUpdateCoordinator`, and
  `CoordinatorEntity` platforms.
- Async cloud client (`api.py` facade over `api_rest.py`, `api_mqtt.py`,
  `api_commands.py`) using Home Assistant's shared aiohttp client.
- AWS IoT MQTT via `awsiotsdk`, using temporary Cognito credentials from
  Aiper's API through the transport in `mqtt.py`.
- HACS distribution with `hacs.json` and a zip release artifact.

## Architecture

- `custom_components/aiper/__init__.py` handles config-entry setup,
  coordinator creation, platform forwarding, background MQTT setup, and the
  one-time `async_migrate_entry` (1.1 -> 1.2: unique-ID normalization and
  legacy entity-registry cleanup).
- The API client is layered; each module builds on the one below:
  - `api_rest.py` (`AiperRestClient`): account session, AES/RSA envelope,
    REST pacing/backoff, device discovery, Cognito credential exchange, and
    the `AiperApiError` exception hierarchy.
  - `api_mqtt.py` (`AiperMqttClient`): AWS IoT transport lifecycle,
    subscriptions, message decoding, AT-command acknowledgement.
  - `api_commands.py` (`AiperCommandClient`): model-aware settings commands
    (mode, running, clean path), including bounded discovery sweeps with
    learned per-model routes for unverified models.
  - `api.py` (`AiperApi`): the facade the integration imports, plus
    `diagnostics()`; re-exports the public names.
- `custom_components/aiper/mqtt.py` wraps the AWS IoT SDK transport.
- `custom_components/aiper/profiles.py` and `state.py` normalize model
  capabilities and device state for platforms and tests.
- `custom_components/aiper/coordinator.py` merges REST metadata and MQTT shadow
  updates into the normalized data shape consumed by entities. MQTT pushes use
  `async_set_push_data()` so they do not reschedule the REST poll.
- `custom_components/aiper/s1_reconciliation.py` holds the hardware-verified
  Scuba S1 lifecycle heuristics and their diagnostics state.
- `custom_components/aiper/entity.py` provides `AiperEntity` /
  `AiperControlEntity` (device info, availability, translated command errors).
  `sensor.py`, `binary_sensor.py`, `button.py`, `switch.py`, and `select.py`
  build on it with translation keys.
- `custom_components/aiper/controller.py` is the typed command surface used by
  control entities.
- `custom_components/aiper/crypto.py` implements the Aiper AES/RSA request
  envelope.
- `custom_components/aiper/diagnostics.py` assembles the public
  `diagnostics()` snapshots and redacts them.

## Current State

The integration is functional but carries reverse-engineering complexity. Tests
run against current Home Assistant (dev lock, Python 3.14) and the declared
minimum (Home Assistant 2024.12 on Python 3.12, see `hacs.json` and the
`test-min-ha` CI job). Keep tests anchored to captured or representative
payload shapes. `quality_scale.yaml` tracks the quality-scale rules; the
manifest claims `bronze`, and test coverage (CI floor in `pyproject.toml`) is
the remaining Silver requirement.

The code intentionally contains compatibility paths for regional API and
firmware variance. Preserve that behavior unless a test or live payload proves
a branch is obsolete.

## Working Rules

- Keep changes small and Home Assistant idiomatic. Prefer `ConfigEntry`,
  `DataUpdateCoordinator`, entity descriptions, translations, repairs/reauth,
  and diagnostics patterns over custom machinery.
- Do not make live Aiper API calls in tests. Mock `AiperApi` and cover
  parser/coordinator/entity behavior with representative payload fixtures.
- Treat credentials, tokens, Cognito identities, MQTT payloads, and serial
  numbers as sensitive. Do not add logs that expose them. INFO and above must
  not contain payloads, the account email, or full serials (use
  `redaction.redact_serial` / `redact_topic`). Diagnostics pseudonymize serials
  and the username via `redact_known_values`; probe bundles keep serials.
- Before touching command/control behavior, read `api_commands.py` (and the
  layers it uses), `coordinator.py`, `controller.py`, `entity.py`, and the
  relevant platform module; command state crosses those layers.
- Entity names and service errors come from `strings.json`. When adding or
  changing a string, update `translations/en.json` identically and add the key
  to every other language file; `tests/test_translations.py` enforces this.
- Build coordinators in tests with `tests/coordinator_factory.py`
  (`make_coordinator`, `BaseFakeApi`), not `__new__`.
- Before changing entity unique IDs or names, check the legacy
  cleanup/migration code in `__init__.py` so existing dashboards are not broken
  accidentally. New registry or config-entry changes belong in
  `async_migrate_entry` behind a `MINOR_VERSION` bump, not in setup.
- After changes, run at least Python compilation and any available tests. Once
  test tooling exists, prefer targeted pytest runs plus Home Assistant
  component tests for config flow and setup/unload.

## Modernization Priorities

1. Raise test coverage past 95% (Silver): payload-driven tests for
   `api_mqtt.py`, `api_rest.py`, `coordinator.py`, and
   `coordinator_parsing.py`, then ratchet `fail_under` up.
2. Pick up devices added to the account after setup without a reload
   (dynamic-devices).
3. Move entity icons into `icons.json` (icon-translations).
4. Tighten typing toward mypy strict mode.
