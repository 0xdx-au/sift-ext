# P0 client baseline — 2026-11-15

## Directly observed

- Repository `0xdx-au/sift-ext` is publicly accessible; default branch `main`; initial head `09c66930a88caf89f28a416392b24cd5eb1f5ab4`.
- No branch protection on `main`; repository rulesets endpoint returned `[]`.
- Initial repository had only 10 governance and CI files, no browser manifest, background service worker, popup, DNR rule file, installed-browser tests or signed-feed verification client.
- An unrelated CORS bypass extension in the private `cf-website` repository is not a suitable source for the SIFT browser client.
- No validated original Link Signal 1.4.2 package was available in the inspected repositories, so this branch does **not** claim to be a verified synchronization of that package.

## This branch: conservative Chromium starter

- Adds independently inspectable Manifest V3 source with a single bundled DNR rule restricted to four known analytics/ad-serving domains in third-party subresource contexts.
- Protection can be enabled or paused using actual DNR enabled-ruleset state, not simulated counters.
- Adds opt-in **manual** URL cleanup with exact-key matching, raw query preservation, and sensitive-flow avoidance.
- No host permissions, content-script injection, remote code, remote telemetry, production key, or automatic intelligence updates.
- Local source/manifest tests are provided. Browser installation, network capture, branding verification, accessibility checks and regression testing remain required.

## Ship blockers

1. Reconcile against independently validated prior extension package; do not overwrite current published behaviour blindly.
2. Import a public, independently reviewed protocol implementation; provision only an authorised public Ed25519 pin after offline key custody.
3. Add staged signed release ingestion, validation, DNR installation and recovery.
4. Implement and independently test exclusions and automatic link cleaning if safe, then run real browser installs.
5. Configure actual GitHub rulesets; check workflow statuses and installed browser coverage.
6. Verify third-party list rights, actual ADMINE branding, privacy disclosures and Chrome/Edge/Brave compatibility; Safari separately.

No store-readiness or signed-feed availability is asserted.
