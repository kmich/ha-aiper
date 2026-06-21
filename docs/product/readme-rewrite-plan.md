# README Rewrite Plan

The current README is a technical manual. It needs to be a **conversion funnel**. Users must immediately understand what the integration does, that it's unofficial, and what models are supported.

## Structure

1. **Hero Header**: High-quality logo and bold claim.
2. **One-Sentence Value Prop**: "Bring your Aiper pool cleaner and water monitor into Home Assistant."
3. **Screenshot / GIF**: (Placeholder for a beautiful Mushroom-card dashboard).
4. **Transparency Disclaimer**: VERY CLEAR blockquote stating this is unofficial and cloud-based.
5. **Compatibility Matrix**: Brief list mapping models to "Verified" or "Experimental".
6. **Installation**: HACS instructions (front and center).
7. **Configuration**: Step-by-step UI config flow.
8. **What You Get (Entities)**: Bulleted list of key features.
9. **Safe Controls**: Explanation of what commands are supported (and why some aren't).
10. **Troubleshooting & Diagnostics**: Link out to the diagnostics guide.
11. **Privacy**: Link out to the security/privacy doc.

## Above-the-Fold Copy Draft

```markdown
# Aiper for Home Assistant

[![HACS][hacs-badge]][hacs-url] [![GitHub Release][release-badge]][release-url]

**Bring your Aiper pool cleaner and water quality monitor into Home Assistant.**
View live status, battery, charging state, cleaning modes, consumables, and water chemistry (pH, ORP, Chlorine) alongside safe controls, directly in your smart home dashboard.

> [!WARNING]
> **Unofficial & Cloud-Based**
> This integration uses Aiper's cloud services (REST and AWS IoT MQTT). It is unofficial and not affiliated with Aiper. Because it relies on reverse-engineered cloud APIs, an update to the Aiper app or firmware could break functionality. Please read the [Security & Privacy Guide](docs/trust/security-privacy.md) before installing.

## Supported Models

| Cleaners | Monitors |
|---|---|
| ✅ **Scuba X1** | ✅ **HydroComm** |
| ⚠️ **Surfer S2** (Experimental) | ⚠️ **HydroComm Pro / W2 Series** (Experimental) |
| ⚠️ **Shark** (Experimental) | |

*(Don't see your model? We need your help! Check our [Model Contribution Guide](#).)*

![Dashboard Example](docs/assets/dashboard-preview.png)
```
