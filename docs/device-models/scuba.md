# Scuba

## Scope

This file covers devices classified as the `scuba` family. The family is
detected when a discovered model field such as `model`, `deviceModel`,
`modelName`, or `productName` contains `scuba`.

Most current Scuba-specific behavior in the integration was built around Scuba
X-series observations, especially Scuba X1. It has not been re-verified in the
same live probe pass as Surfer S2.

## Known

Scuba devices use the normal Aiper account, REST, Cognito, AWS IoT, and shadow
flow used by the integration.

The Scuba profile currently enables these capabilities:

- common cloud/shadow diagnostics
- cleaning mode select
- clean-path select
- water temperature, when `Machine.temp` is present
- in-water state, when `Machine.in_water` is present
- roller brush maintenance, when consumables expose roller brush data
- micromesh filter maintenance, when consumables expose micromesh data
- caterpillar tread maintenance, when consumables expose caterpillar data

Scuba is currently the only family with default cleaning-mode select exposure.
Surfer S2 verification showed `Machine.mode` is cleaning context, and Shark has no
cleaning-mode evidence yet.

The Scuba mode map is currently:

- `1`: Smart
- `2`: Floor
- `3`: Wall
- `4`: Waterline
- `5`: Scheduled

Mode control uses MQTT down-channel AT commands:

```text
AT+MODE=<mode_id>
```

The integration no longer uses a REST mode fallback or `AT+WORKMODE=<mode_id>`
fallback.

Clean-path values are normalized across observed payload variants:

- integer `0` or string `"0"`: S-shaped
- integer `1` or string `"1"`: Adaptive
- label variants such as `S-shaped` or `Adaptive`
- sentinel `-1`: default `0`

## Legacy Clean-Path Runtime Path

Scuba still uses the legacy clean-path matrix in `custom_components/aiper/api.py`
because current Scuba hardware has not been re-probed. The matrix tries multiple
endpoint families, encrypted and plain envelopes, and several body shapes.

Query endpoint families still present for non-Surfer devices:

- `/equipmentCleanPathSetting/getCleanPathSetting`
- `/equipmentCleanPathSetting/getCleanPathSettingBySn`
- `/equipmentCleanPathSetting/queryCleanPathSetting`
- `/network/clean_path_setting`
- `/network/cleanPathSetting`
- `/swimming/v2/queryCleanPathSetting`
- `/swimming/v2/getCleanPathSetting`
- `/swimming/v2/getCleanPathSettingBySn`

Update endpoint families still present for non-Surfer devices:

- `/equipmentCleanPathSetting/updateCleanPathSetting`
- `/equipmentCleanPathSetting/updateCleanPathSettingBySn`
- `/network/clean_path_setting`
- `/network/cleanPathSetting`
- `/swimming/v2/updateCleanPathSetting`
- `/swimming/v2/setCleanPathSetting`

Clean-path update body variants still present for non-Surfer devices:

- `{"sn":"<sn>","cleanPath":<value>}`
- `{"sn":"<sn>","cleanPathSetting":<value>}`
- `{"sn":"<sn>","clean_path_setting":<value>}`
- optional `id`, `equipmentId`, or `deviceId`

Clean-path MQTT apply variants still present for non-Surfer devices:

- structured `Machine.cleanPath`
- structured `Machine.cleanPathSetting`
- structured `Machine.clean_path_setting`
- structured `cmd: AUTO`
- `AT+AUTO=<value>`
- `AUTO <value>`
- `AT+CPATH=<value>`
- `AT+CLEANPATH=<value>`
- `AT+SETPATH=<value>`

These are intentionally documented as legacy. They should be collapsed after
Scuba hardware verification identifies the real current contract.

## Unknown

- Whether current Scuba cloud infrastructure now accepts the same single
  clean-path query/update contract verified for Surfer S2.
- Whether all Scuba models use the Scuba X1 mode labels.
- Whether `Scheduled` mode ID `5` is consistent across Scuba models and
  firmware revisions.
- Which clean-path endpoint/body/envelope combinations are actually required
  today.
- Whether shadow desired-state updates affect Scuba behavior or are only useful
  for state convergence.
- Whether X9-style topic behavior applies to any Scuba serial prefixes.

## At Risk

- The non-Surfer clean-path fallback matrix is broad and may hide obsolete or
  cloud-side behavior. It should be treated as technical debt pending Scuba
  verification.
- Some Scuba assumptions are label-level assumptions. Numeric mode IDs may be
  stable while names differ by model or firmware.
- Clean-path control may appear successful if one publish path succeeds even
  when the device ignores that specific variant. Hardware verification should
  check reported state after commands.
- Removing legacy clean-path fallbacks without Scuba evidence could regress
  users whose devices still depend on older backend routes.

## Verification Needed

Run a Scuba contract verification process:

```bash
uv run tools/aiper_probe.py snapshot --sn <sn>
uv run tools/aiper_probe.py consumables --sn <sn>
uv run tools/aiper_probe.py contract-verify --sn <sn> --allow-control
```

The contract verifier still includes legacy clean-path REST and AT variants
because those are the Scuba questions most likely to retire fallback code.
