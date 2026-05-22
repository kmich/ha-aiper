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
- Async cloud client in `api.py` using Home Assistant's shared aiohttp client.
- AWS IoT MQTT via `awsiotsdk`, using temporary Cognito credentials from
  Aiper's API through the transport in `mqtt.py`.
- HACS distribution with `hacs.json` and a zip release artifact.

## Architecture

- `custom_components/aiper/__init__.py` handles config-entry setup,
  coordinator creation, platform forwarding, MQTT subscription setup, and
  legacy entity cleanup.
- `custom_components/aiper/api.py` owns Aiper REST, encryption, AWS credential
  exchange, clean-path REST handling, command acknowledgement, and low-level
  protocol handling.
- `custom_components/aiper/mqtt.py` owns the AWS IoT MQTT transport.
- `custom_components/aiper/profiles.py` and `state.py` normalize model
  capabilities and device state for platforms and tests.
- `custom_components/aiper/coordinator.py` merges REST metadata and MQTT shadow
  updates into the normalized data shape consumed by entities.
- `custom_components/aiper/sensor.py`, `binary_sensor.py`, `switch.py`, and
  `select.py` define entity descriptions and entity behavior.
- `custom_components/aiper/crypto.py` implements the Aiper AES/RSA request
  envelope.
- `custom_components/aiper/diagnostics.py` redacts config/runtime data for
  issue reports.

## Current State

The integration is functional but carries reverse-engineering complexity. Local
pytest, Ruff, and mypy scaffolding is present; keep tests anchored to captured
or representative payload shapes.

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
  numbers as sensitive. Do not add logs that expose them.
- Before touching command/control behavior, read `api.py`, `coordinator.py`,
  `controller.py`, and the relevant platform module; command state crosses
  those layers.
- Before changing entity unique IDs or names, check the legacy
  cleanup/migration code in `__init__.py` so existing dashboards are not broken
  accidentally.
- After changes, run at least Python compilation and any available tests. Once
  test tooling exists, prefer targeted pytest runs plus Home Assistant
  component tests for config flow and setup/unload.

## Modernization Priorities

1. Tighten config-flow error classification so connection failures, invalid
   auth, and unexpected payloads produce distinct user-facing errors.
2. Update manifest metadata toward current Home Assistant expectations,
   including dependency transparency and quality-scale fields where
   appropriate.
3. Reduce duplicate helper functions across entity/coordinator modules once
   tests protect behavior.
