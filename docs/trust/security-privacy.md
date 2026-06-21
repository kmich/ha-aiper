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
If you enable Debug Logging, the integration will print raw JSON payloads from the cloud.
**Diagnostics automatically scrub your email, password, tokens, and AWS access keys.** However, you should always review your logs before posting them publicly.

## 6. Command Safety
The integration sends commands (like "Start" or "Set Mode") exactly as the official app does. We do **not** use experimental or unknown command codes. If a command fails, the integration simply surfaces the error; it does not aggressively retry in a loop that could lock your account.
