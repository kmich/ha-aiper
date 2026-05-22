# Unknown

## Scope

This file covers devices that do not match the known family markers:

- `surfer`
- `scuba`
- `shark`

Unknown devices are still Aiper devices discovered from the account, but the
integration cannot safely assume model-specific controls.

## Known

Unknown devices receive only the shared baseline capabilities:

- battery
- online
- status
- warning
- wifi
- firmware
- MQTT shadow
- bluetooth diagnostics
- device link diagnostics

Evidence discovered from payloads may add capabilities even when the family is
unknown. Current examples:

- `Machine.temp` can enable water temperature
- `Machine.in_water` can enable in-water state
- `Machine.solar_status` can enable solar charging
- known consumable names can enable maintenance sensors

The model string used for classification is selected from:

- `model`
- `deviceModel`
- `modelName`
- `productName`

## Unknown

- Whether the device is a known family with a missing or unexpected model string.
- Whether controls should exist.
- Whether mode IDs match Scuba labels, Surfer generic labels, or another model
  map entirely.
- Whether clean-path exists.
- Whether the device publishes state through normal shadow report topics, X9
  app-report topics, or model-specific topics not yet known.
- Whether consumables and device-info payloads have familiar shapes.

## At Risk

- Showing controls by default for unknown devices would risk sending incorrect
  commands to real hardware.
- Hiding controls may under-support a device that is actually compatible with a
  known family but lacks a matching model marker.
- Payload-driven capability discovery can be too optimistic if a field appears
  once but is not authoritative.
- Users may report missing controls without enough payload evidence to classify
  the device safely.

## How To Promote An Unknown Device

Use probe output to identify the family and capabilities:

```bash
uv run tools/aiper_probe.py list
uv run tools/aiper_probe.py snapshot --sn <sn>
uv run tools/aiper_probe.py observe --sn <sn> --seconds 120
uv run tools/aiper_probe.py shadow --sn <sn> --seconds 15
uv run tools/aiper_probe.py guided --profile generic --sn <sn>
```

Promote the device out of `unknown` only after there is enough evidence for:

- stable model string markers
- baseline REST payload shapes
- MQTT topic behavior
- state fields for sensors and binary sensors
- command path, if controls are requested
- reported-state confirmation after commands
