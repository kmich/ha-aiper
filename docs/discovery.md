# Aiper Discovery Utility

`tools/aiper_probe.py` is a developer utility for collecting evidence from real
Aiper devices. It reuses `custom_components.aiper.api.AiperApi`; it does not
reimplement login, encryption, MQTT topics, checksums, or AT command handling.

The tool is intended for model support work such as Surfer S2 discovery.

## Approach

The probe is deliberately thin. Protocol behavior belongs in
`custom_components/aiper/api.py`, because that is what the Home Assistant
integration uses in production. If discovery needs a protocol capability that
does not exist yet, add it to `AiperApi` first and call it from the probe.

The probe owns only:

- command-line argument parsing
- choosing a device serial number
- running existing `AiperApi` methods
- writing timestamped output files
- redacting sensitive values
- guided prompts for humans using the official app

Do not add one-off encryption, checksum, topic, REST endpoint, or MQTT publish
logic directly to `tools/aiper_probe.py`.

Discovery flows are not runtime device profiles. They only describe what the
human should do while the tool records evidence. Runtime support should be
implemented later in integration code, backed by fixtures from probe output.

## Safety

Default commands are read-only:

- list devices
- capture REST snapshots
- subscribe to MQTT
- request device shadow state
- record observed payloads

Commands that can affect a real device require `--allow-control`.

Serial numbers are intentionally not redacted because they are needed to
correlate REST payloads, MQTT topics, and support reports. Passwords, tokens,
AWS credentials, Cognito/OpenID data, and authorization-like fields are redacted.

## Setup

Install the development environment first:

```bash
uv sync --group dev
```

The probe file is executable, so prefer:

```bash
uv run tools/aiper_probe.py ...
```

The longer form also works:

```bash
uv run python tools/aiper_probe.py ...
```

## Credentials

Use environment variables to avoid putting credentials in shell history:

```bash
export AIPER_USERNAME='person@example.com'
export AIPER_PASSWORD='...'
export AIPER_REGION='eu'
```

You can also pass `--username`, `--password`, and `--region` directly. If no
password is provided, the tool prompts for one.

## Commands

List devices:

```bash
uv run tools/aiper_probe.py list
```

Capture read-only REST state:

```bash
uv run tools/aiper_probe.py snapshot --sn T1B50900024
```

Observe MQTT events:

```bash
uv run tools/aiper_probe.py observe --sn T1B50900024 --seconds 120
```

Request shadow state and observe replies:

```bash
uv run tools/aiper_probe.py shadow --sn T1B50900024 --seconds 15
```

Send one AT command:

```bash
uv run tools/aiper_probe.py at --sn T1B50900024 --command 'AT+INFO' --allow-control
```

Run a guided discovery flow:

```bash
uv run tools/aiper_probe.py guided --profile surfer-s2 --sn T1B50900024
```

Available flows live in `tools/discovery_flows/`.

Run the contract verifier when checking current REST bodies and legacy control
fallbacks:

```bash
uv run tools/aiper_probe.py contract-verify --sn T1B50900024 --allow-control
```

### Command Behavior

`list` logs in and prints the discovered devices as redacted JSON. Use it first
to confirm the account, region, and serial numbers.

`snapshot` captures read-only REST state for one device:

- `get_device_status`
- `get_device_info`
- `get_consumables`
- `query_clean_path_setting`

Each REST call is recorded independently. If one endpoint fails, the snapshot
still records the other endpoint results and stores the error for the failed
call.

`observe` connects to MQTT, subscribes through `AiperApi.subscribe_device`, sends
a shadow request, then records callback payloads for the requested duration.

`shadow` is a short `observe` run intended to capture shadow responses after a
shadow request.

`at` sends exactly one AT command through `AiperApi.send_machine_at`. It requires
`--allow-control` because AT commands can affect a real device.

`contract-verify` runs targeted REST and MQTT command probes. It is intended for
specific protocol questions such as consumables body shape, clean-path endpoint
behavior, and legacy AT fallback behavior. It requires
`--allow-control` because it sends commands to the device.

`guided` loads a YAML flow from `tools/discovery_flows/`, prompts the user for
each step, and captures REST/shadow/MQTT evidence around the official app action
the user performs.

## Output

The tool writes timestamped directories under `probe-output/`, which is ignored
by git. Typical files include:

- `manifest.json`
- `devices.json`
- `rest-snapshot.json`
- `mqtt.ndjson`
- `summary.md`
- guided flow step captures under `steps/`

Review output before sharing it. The redactor is conservative, but discovery
captures are real cloud/device payloads.

### Output Details

`manifest.json` records the probe command, timestamp, region, selected serial
number, and discovered device list.

`rest-snapshot.json` contains one top-level object per REST call. Each call has:

- `ok`
- `started`
- `data` when successful
- `error` when the call raised

`mqtt.ndjson` contains one JSON object per MQTT callback. The most useful fields
are:

- `ts`
- `sn`
- `topic`
- `payload`

For guided runs, each step also gets a directory under `steps/<step-id>/` with
`rest-before.json`, `rest-after.json`, and `step.json` when enabled by the flow.

### Flow Files

Discovery flows are YAML files in `tools/discovery_flows/`. They are declarative
and intentionally simple:

```yaml
name: Example Device
description: What this flow is trying to capture.
steps:
  - id: baseline_idle
    prompt: Make sure the device is online and idle.
    capture:
      rest: true
      shadow: true
      observe_seconds: 30
```

Supported step fields:

- `id`: stable step identifier used in output paths
- `prompt`: text shown to the person running the tool
- `capture.rest`: whether to capture REST before and after the observe window
- `capture.shadow`: whether to request shadow state during the step
- `capture.observe_seconds`: MQTT observe window for the step

Keep flows focused on repeatable observations. They should ask the user to
perform actions in the official Aiper app; they should not encode protocol
guesses.

## Discovery Workflow

1. Run `snapshot` for the device.
2. Run targeted probes for known protocol questions:
   `consumables`, `at-format`, or `contract-verify`.
3. Run `guided --profile generic` or a more specific app-action flow
   when the missing evidence depends on official app workflows.
4. During guided steps, use the official Aiper app to perform the requested
   action while the probe captures REST/shadow/MQTT evidence.
5. Add sanitized output as fixtures under `tests/fixtures/<model_family>/`.
6. Implement parser/capability changes from fixture evidence.

Do not guess movement/control commands from a different device family. Capture
official app behavior first, then encode support in the integration.

## Turning Probe Output Into Support

After collecting device data:

1. Review the output and remove anything irrelevant or unexpectedly sensitive.
2. Keep serial numbers if they help correlate topic names and payloads.
3. Add representative payloads as fixtures under `tests/fixtures/<model_family>/`.
4. Add parser tests before changing entity behavior.
5. Add or update model-family/capability logic in the integration.
6. Gate family-specific controls away from other families unless probe evidence
   proves they apply.
7. Add command support only after official app traces show the correct command
   shape and reported-state response.

Useful questions to answer from the evidence:

- Which payload field identifies the model family reliably?
- Which topics does it publish to?
- Which component carries online, battery, status, warnings, and run time?
- Does it report modes as numeric IDs, strings, or another structure?
- Are start/stop/mode changes sent through REST, downChan, shadow desired state,
  or multiple paths?
- Which fields change after official app actions?

## Known Limitations

- The probe talks to the real Aiper cloud and real devices.
- MQTT observation only captures messages delivered while the tool is running.
- The tool does not know whether a captured value is authoritative; that is part
  of the analysis step.
- Redaction is key-name based. Review output before publishing it.
- Guided flows are not tests. They are evidence collection scripts.
