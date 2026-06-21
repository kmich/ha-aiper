# Diagnostics and Troubleshooting Guide

If you are experiencing issues with `ha-aiper`, follow this guide before opening a GitHub issue. Because this integration relies on unofficial cloud APIs, troubleshooting requires careful log gathering.

## 1. Common Issues

### "Session Conflict" / Error 402 / Kicked out of App
Aiper only allows one active session per account. If you open the official Aiper mobile app, it may invalidate the token used by Home Assistant. The integration will eventually back off and try to recover, but **you cannot actively use the app and Home Assistant at the exact same time.**

### Stale Data / "Online" but not updating
Make sure your pool cleaner has a strong WiFi connection. The integration relies on AWS IoT MQTT. If the robot drops off WiFi, Home Assistant will only show the last known state.

### Commands Failing
Ensure the robot is not docked, charging, or asleep. The Aiper cloud will often silently reject commands sent to a sleeping robot.

## 2. Enabling Debug Logging

To help us figure out what's wrong, you need to enable debug logging.

1. Go to **Settings > Devices & Services**.
2. Find the **Aiper Pool Cleaner** integration.
3. Click the three dots and select **Enable debug logging**.
4. Perform the action that is failing (e.g., try to change the mode, or wait 5 minutes for a data refresh).
5. Click **Disable debug logging**. Home Assistant will automatically download a `.log` file.

## 3. Downloading Diagnostics

For issues with missing entities or unsupported models, we need the raw payload your device sends.

1. Go to **Settings > Devices & Services > Aiper**.
2. Click on your Device (e.g., "Scuba X1").
3. In the Device Info card, click **Download diagnostics**.

## 4. Redacting Secrets (CRITICAL)

**NEVER publicly share your raw logs or diagnostics without checking them!**
While the integration attempts to sanitize data, you must manually ensure the following are not in your text:

- `email`, `password`, or `token`
- AWS `AccessKeyId` or `SecretAccessKey`
- Your exact latitude/longitude.

*(Note: Device Serial Numbers (`sn`) are generally safe to share for debugging, but you may replace them with `SN_REDACTED` if you prefer).*

## 5. What to Include in a Bug Report

When opening an issue, always provide:
- Integration Version (e.g., v1.1.0)
- Home Assistant Version (e.g., 2026.6.0)
- Device Model and Firmware Version
- The downloaded diagnostics file
- A clear description of what you expected vs what happened.
