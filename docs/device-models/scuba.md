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

### Scuba S1 2025 / 2026 retail hardware

The 2026 retail Scuba S1 identifies itself as `Scuba_S1_2025` with serial
prefix `52`. Aiper Android 3.5.0 maps it to the app's X5ProMax device family and
opens the model-specific X6 clean-path screen.

The clean-path contract was verified against a physical device running main
firmware V2.0.1:

- query: `AT+AUTO?`
- S-shaped: `AT+AUTO=0`
- Adaptive: `AT+AUTO=1`
- successful writes return `+OK`

The model capability profile exposes only hardware-backed S1 entities. It
retains the observed MicroMesh consumable and suppresses water temperature,
charge type, roller brush, caterpillar tread, and propeller entities for which
this device provides no usable data.

The query and both writes were captured from the official app. A subsequent
read-only AWS IoT query from the integration returned code `1` after Adaptive
was selected. The REST clean-path endpoint returns `-1`, and the setting is not
present in the device shadow, so neither is used for this model.

This model-specific path deliberately bypasses the legacy Scuba endpoint and
command matrix below. Other Scuba models retain their existing behavior.

The same app build exposes an S1-specific cleaning-mode list and AT contract:

- query: `AT+MODE?`
- `1`: Auto
- `2`: Floor
- `3`: Wall
- `5`: Scheduled
- set: `AT+MODE=<mode_id>`; successful writes return `+OK`

Waterline (`4`) is not supported by this model and is not offered by its app
screen. The integration therefore treats this exact list as authoritative for
`Scuba_S1_2025`, rather than inheriting the generic Scuba mode list. The
cleaning-mode select represents the configured program for the next run; the
separate Mode sensor continues to represent the machine's currently reported
operating mode. Aiper cleaning history calls mode `1` "Smart" generically; the
S1's Last Cleaning Mode sensor normalizes that label to the model's "Auto".

Over AWS IoT, this S1 currently acknowledges `AT+MODE?` with `+OK` but does not
return a numeric value. The select therefore uses the active mode when present,
the last confirmed local selection, or cleaning history after a restart. A set
command is accepted only after the cleaner returns `+OK`.

After a low-battery stop, firmware V2.0.1 can leave its last MQTT report at
Cleaning/Wet even after retrieval and power-off. Once charging begins, the REST
device list supplies a fresh status `2` and live battery updates while no new
machine-state MQTT report arrives. The integration tracks, per field, which
source last set `running` / `status` / `charging` / `mode`, and lets a REST
value take over once the MQTT evidence for that field is older than two polling
intervals; this applies to every model. For the S1 specifically, a fresh REST
charging status supersedes the stale MQTT report immediately (without waiting
out that window) and also implies Dry, Not running, Mode 0, and zero current
cleaning runtime. A recent MQTT report that still shows Cleaning keeps MQTT
authoritative for that poll.

The explicit status remains authoritative. If an S1 REST response omits status,
the integration has a conservative fallback requiring three strictly rising
battery samples over at least two minutes while online, with a total rise of at
least two percentage points and no newer MQTT Machine report. Diagnostics record
whether `mqtt_machine_status`, `rest_machine_status`, or
`battery_rise_fallback` caused reconciliation, along with the fields applied.
A bounded, de-duplicated event timeline preserves source order when a later
REST poll confirms a transition first reported through MQTT.

The inverse transition has similar S1-only rules. A fresh REST device-list poll
can report Cleaning together with a stale `in_water=0`; Cleaning is authoritative
because this model cannot physically clean outside the pool. Observed status 10
means the S1 has parked underwater, so Parked remains Wet when REST omits a newer
water-state report. Explicit water state remains authoritative outside active
Cleaning, and charging always implies Dry.

### Scuba P1 Pro

Identifies as `Scuba_P1_Pro` (X6 Pro hardware family). Support was onboarded
from a community diagnostics bundle (issue #45, integration 1.4.0) and has not
been verified on hardware by the maintainer.

The capture shows an MQTT `Machine` shadow of `cap`, `in_water`, `mode`,
`run_time`, `status`, `warn`, `warn_code` with no `temp` field, and a
consumables list of exactly a Roller Brush and a MicroMesh Filter. The model
profile therefore mirrors the conservative S1 base (no water temperature, charge
type, caterpillar tread, or propeller) but keeps roller-brush maintenance
because the device reports that consumable. The clean-path query succeeded
(`0`), so clean path stays enabled.

No charge or park cycle was captured, so the model uses the default status-code
encoding (no `MODEL_STATUS_SEMANTICS` entry) and the generic Scuba mode map
(`1` Smart, `2` Floor, `3` Wall, `4` Waterline, `5` Scheduled); there is no app
evidence to narrow it. Both are `# TODO: verify on hardware`.

## Legacy Clean-Path Runtime Path

Scuba models other than `Scuba_S1_2025` still use the legacy clean-path matrix
in `custom_components/aiper/api.py` because current hardware has not been
re-probed. The matrix tries multiple endpoint families, encrypted and plain
envelopes, and several body shapes.

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
uv run tools/aiper_probe.py guided --profile scuba-x1-features --sn <sn>
```

The contract verifier still includes legacy clean-path REST and AT variants
because those are the Scuba questions most likely to retire fallback code.
Use the guided Scuba scan around app actions to capture current X1 behavior for:

- cleaning mode and clean-path changes from the app
- cleaning progress, remaining time, completion, and history clues
- basket/filter state beyond long-term consumable wear
- pause, return, charge, surface, park, or pickup state transitions
