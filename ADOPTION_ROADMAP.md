# Adoption Roadmap

## Phase 1: Trust and Documentation Fixes (Next 48 Hours)
**Goal:** Make the integration safe to look at, read, and debug.
- **Action:** Merge the `ADOPTION_REVIEW.md` and related docs into the repository.
- **Action:** Rewrite the `README.md` to be a conversion funnel rather than a technical manual.
- **Action:** Publish `docs/trust/security-privacy.md` to address unofficial cloud concerns.
- **Action:** Create GitHub Issue Templates for bug reports, model support, and command failures to standardize incoming telemetry.

## Phase 2: Launch Readiness (1 Week)
**Goal:** Productize the integration for a public audience.
- **Action:** Prepare the Lovelace dashboard examples (`example-dashboard.yaml`, `mushroom-example.yaml`) with screenshots and add them to the README.
- **Action:** Add `docs/examples/automations.md` to give users immediate, copy-paste value.
- **Action:** Cut release `v1.1.0` with the new device action buttons and clear release notes.
- **Action:** Verify HA 2026.x compatibility and ensure `hassfest` passes in GitHub Actions.

## Phase 3: Community Validation (2 Weeks)
**Goal:** Soft launch and gather real-world telemetry.
- **Action:** Post the launch announcement to the Home Assistant Community Forum (using the template in `docs/adoption/community-launch.md`).
- **Action:** Post to r/homeassistant on Reddit, emphasizing "Unofficial Aiper Support is here."
- **Action:** Actively monitor GitHub issues, guiding users to use the new diagnostic tools and issue templates.

## Phase 4: Model Coverage Expansion (1 Month)
**Goal:** Transition remaining unsupported models to "Verified".
- **Action:** Collect user-submitted `aiper_probe.py` payloads for Surfer S2 and Shark.
- **Action:** Fix edge cases in HydroComm alarm decoding and Scuba X1 charging states based on user logs.
- **Action:** Update the `docs/product/model-coverage.md` matrix as devices are proven stable.

## Phase 5: HACS Default-Level Credibility (3 Months)
**Goal:** Remove the friction of custom repositories.
- **Action:** Ensure test coverage passes 80% for parsers and entities.
- **Action:** Achieve a "Silver" or "Gold" Home Assistant Quality Scale internally.
- **Action:** Submit a PR to the official `hacs/default` repository to have `ha-aiper` included as a default integration.
