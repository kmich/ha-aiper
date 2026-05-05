# Device Model Notes

This directory records device-family evidence used by the integration. These
notes are device-focused: what is known for a model type, what remains unknown,
and what is operationally risky for Home Assistant support.

Runtime family detection currently lives in
`custom_components/aiper/profiles.py` and uses model-name markers:

- `surfer`: model string contains `surfer`
- `scuba`: model string contains `scuba`
- `shark`: model string contains `shark`
- `unknown`: no known marker matched

These files are not runtime configuration. They are engineering notes for
maintainers. Runtime behavior must still be backed by parser tests, coordinator
tests, and, where possible, probe output from `tools/aiper_probe.py`.

## Model Types

- [Surfer](surfer.md)
- [Scuba](scuba.md)
- [Shark](shark.md)
- [Unknown](unknown.md)

## Shared Cloud And MQTT Details

All currently supported model types use Aiper cloud credentials and regional
REST endpoints from `custom_components/aiper/const.py`:

- `eu`: `https://apieurope.aiper.com`
- `us`: `https://apiamerica.aiper.com`
- `asia`: `https://apiasia.aiper.com`
- `au`: aliases to the Asia/Pacific backend

REST calls use the encrypted Aiper request envelope for most device operations.
MQTT uses AWS IoT credentials obtained from Aiper's `getOpenIdToken` and Cognito
exchange flow.

Common MQTT topics:

- up channel: `aiper/things/{sn}/upChan`
- down channel: `aiper/things/{sn}/downChan`
- shadow get request: `$aws/things/{sn}/shadow/get`
- shadow get accepted: `$aws/things/{sn}/shadow/get/accepted`
- shadow update: `$aws/things/{sn}/shadow/update`
- shadow update accepted: `$aws/things/{sn}/shadow/update/accepted`
- shadow update delta: `$aws/things/{sn}/shadow/update/delta`
- shadow update documents: `$aws/things/{sn}/shadow/update/documents`
- shadow report: `aiper/things/{sn}/shadow/report`
- X9-style app report: `aiper/things/{sn}/app/report`

Common integration capabilities:

- battery
- online
- status
- warning
- wifi
- firmware
- MQTT shadow
- bluetooth diagnostics
- device link diagnostics

The shared capabilities are broad assumptions from the integration's current
payload normalizers. Device-family docs below describe where support is verified
or still tentative.

## Mode And Profile Model

The integration keeps running control and cleaning mode separate:

- Running is a boolean Home Assistant intent. The API maps `True` to
  `AT+MODE=1` and `False` to `AT+MODE=0`. The switch state still comes from
  the operational status in `Machine.status`.
- `CleaningMode` is only the known label set for cleaning-mode IDs such as
  Smart, Floor, Wall, Waterline, and Scheduled. It is not proof that every
  device uses those IDs, and it is not the complete set of possible IDs.
- `Machine.mode` is a raw device-reported integer. Its meaning depends on the
  device family. Scuba treats it as a selectable cleaning mode. Surfer treats it
  as read-only cleaning context, such as Off, Manual, or Scheduled.
- `supported_mode_ids` is the normalized list of mode IDs reported by cloud
  metadata or inferred from a known family. Explicit cloud-reported IDs are
  preserved as integers even when they are outside the `CleaningMode` enum.
- `mode_map` maps those integer IDs to Home Assistant labels. Known Scuba IDs
  use friendly names. Unknown explicit IDs use conservative labels like
  `Mode 7`.

Profile capability rules are intentionally conservative:

- Scuba exposes the cleaning-mode select from the known family profile.
- Surfer never exposes the cleaning-mode select from `Machine.mode`; verified
  Surfer evidence shows those IDs describe context, while the only commandable
  surface is Running.
- Shark exposes the cleaning-mode select only when metadata explicitly reports
  supported mode IDs.
- Unknown devices stay read-only until probe or payload evidence proves a safe
  control surface.

This is why the code accepts integer cleaning-mode IDs at the controller/API
boundary, even though `CleaningMode` exists. The enum is for labels and known
defaults; the actual command ID is device-provided evidence.
