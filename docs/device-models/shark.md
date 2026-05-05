# Shark

## Scope

This file covers devices classified as the `shark` family. The family is
detected when a discovered model field such as `model`, `deviceModel`,
`modelName`, or `productName` contains `shark`.

The current project goal includes improving support for an Aiper-managed device
that is more focused on a Shark device, but this family does not yet have the
same live verification depth as Surfer S2.

## Known

Shark devices are currently treated conservatively. The profile exposes only the
shared capabilities:

- battery
- online
- status
- warning
- wifi
- firmware
- MQTT shadow
- bluetooth diagnostics
- device link diagnostics

The integration does not currently expose Shark-specific controls by family
default. Shark is expected to have selectable cleaning modes because it is a
hybrid cleaner, but Home Assistant mode control still needs discovered mode IDs
before it is enabled.

If Shark payloads contain evidence-based fields, generic profile derivation may
still add some capabilities. For example:

- `Machine.temp` can enable water temperature.
- `Machine.in_water` can enable in-water state.
- `Machine.solar_status` can enable solar charging.
- consumable names containing known terms can enable matching maintenance
  sensors.
- explicit supported mode IDs can enable cleaning-mode select with conservative
  generic labels such as `Mode 1` until app labels are verified.

This evidence-driven behavior is intentionally separate from the Shark family
default.

## Unknown

- Whether Shark devices use the same REST consumables contract as Surfer S2.
- Whether Shark devices publish to normal `shadow/report`, X9-style `app/report`,
  or both.
- Whether Shark controls are REST, MQTT down-channel AT commands, shadow desired
  updates, or a combination.
- Whether Shark model strings consistently include `shark`.
- Whether Shark exposes consumables similar to Surfer propeller maintenance or
  Scuba brush/filter/tread maintenance.
- Whether Shark has a clean-path concept at all.
- Which Shark cleaning-mode IDs exist and what app labels they use.
- Whether Shark command acknowledgements use the same `+OK` and `+ERROR`
  up-channel format.

## At Risk

- Exposing controls by analogy to Surfer or Scuba would be risky. The device
  could share the Aiper cloud while using different command names or different
  state semantics.
- Family detection may miss devices if marketing names and cloud model strings
  diverge.
- Shark may be a product line with multiple hardware platforms. A single
  `shark` family could become too broad if probes reveal incompatible behavior.
- If Shark devices use X9-style topics, subscribing only to normal report topics
  would miss state changes. The integration currently subscribes to both normal
  and X9 app-report topics for all devices, which reduces this risk.

## Verification Needed

Start with read-only probes:

```bash
uv run tools/aiper_probe.py list
uv run tools/aiper_probe.py snapshot --sn <sn>
uv run tools/aiper_probe.py observe --sn <sn> --seconds 120
uv run tools/aiper_probe.py shadow --sn <sn> --seconds 15
uv run tools/aiper_probe.py guided --profile generic --sn <sn>
```

Then compare official app actions with MQTT and REST captures:

- online/offline transitions
- start or stop actions, if safe
- mode changes, if the app exposes modes
- maintenance screen loads
- firmware or device-info screen loads

Do not enable Shark controls by default until a command path and reported-state
confirmation are captured.
