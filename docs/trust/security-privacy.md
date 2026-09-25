# Security, Privacy, and Trust

If you are giving this integration your Aiper credentials, you deserve to know exactly how they are used.

## 1. This is Unofficial
This integration is **not** affiliated with, endorsed by, or supported by Aiper. It relies on reverse-engineered APIs. Aiper may change their cloud architecture at any time, which could break this integration.

## 2. Cloud Dependency
This integration **is not local**. It communicates directly with Aiper's cloud servers (REST API) and Amazon Web Services (AWS IoT MQTT).
- **No Local Fallback**: If your internet goes down, or Aiper's servers go down, you cannot control your robot from Home Assistant.

## 3. What Happens to Your Credentials?
- Your **Email** and **Password** are sent securely over HTTPS to Aiper's authentication servers to generate an access token.
- Home Assistant stores your credentials locally on your hardware. **They are never sent to the integration author or any third party.**
- We exchange your Aiper token for temporary **AWS Cognito credentials** to connect to the AWS IoT MQTT broker where your device sends its live telemetry.

## 4. What Data is Fetched?
The integration fetches:
- Device list, Serial Numbers, and Device metadata.
- Live telemetry (Battery, Status, Water Chemistry, Modes).
- Cleaning History (Total hours and cleanings).

## 5. What is Logged?
The integration never writes your email or full device serial numbers to the log, at any log level. Serials are shortened to a form like `SN1...890`, including inside MQTT topics and logged command payloads.
If you enable Debug Logging, debug lines include response metadata. Raw MQTT payloads are only logged when you turn on the **MQTT debug logging** option, and serials inside them are shortened too.
**Diagnostics automatically remove your password, tokens, Cognito identity, and AWS keys, and partially redact your account email (including in the entry title) and device serial numbers.** The model-onboarding bundle from `tools/aiper_probe.py` shortens serials the same way. However, you should always review your logs before posting them publicly.

Full serial numbers are only kept where they are technically needed: in Home Assistant's own device registry (shown on the device page), in the local Repairs entry for an unrecognized model (to tell you which device it is), in requests to Aiper's cloud, and in the probe's `list` output (you pass a serial back with `--sn`).

## 6. Command Safety
The integration sends commands (like "Start" or "Set Mode") exactly as the official app does for models whose command contract has been verified on hardware (Scuba S1, Surfer S2). For other models the integration tries the command variants observed across Aiper firmware, remembers the one that works, and does not repeat a failed search for six hours. If a command fails, the integration surfaces the error; it does not retry in a loop that could lock your account, and a session conflict with the mobile app stops the attempt immediately.
