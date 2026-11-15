# ADMINE / SIFT EXT

**LESS NOISE. MORE SIGNAL.**

Public browser-extension client for [ADMINE](https://admine.au) SIFT.

## Repository boundary

| Resource | Status | Purpose |
| --- | --- | --- |
| [0xdx-au/sift](https://github.com/0xdx-au/sift) | **Private** | Feed ingestion, curation, publishing infrastructure |
| **0xdx-au/sift-ext** | **Public by policy** | Browser client, user interface, verification and platform adapters |
| Public signed-feed endpoint | Planned | Compiled signed policy data, not private curation source |

Chrome, Edge and Brave share a Manifest V3 client with browser-specific validation; Safari requires a separate tested adapter. This is browser request filtering, not network-wide protective DNS.

**Current status:** A conservative source-level Manifest V3 starter has been added on an engineering branch. It provides one bundled, restricted third-party network rule, an actual on/off control, and optional manual tracking-link cleanup. A standalone public Ed25519 release verifier and target compiler have tests, but the live feed is **not provisioned**, the installer is **not connected**, and no installed-browser validation or store publication has been performed. This is not a verified copy of the earlier packaged Link Signal extension.

## Commercial rights

This repo is **source-visible, rights reserved**. ADMINE retains its ability to sell and commercially license the client later. The code is not automatically offered under MIT, Apache-2.0 or another broad reuse licence simply because it is public.

See [LICENSE](LICENSE), [COMMERCIAL.md](COMMERCIAL.md), [SECURITY.md](SECURITY.md) and [HARDENING.md](HARDENING.md) for the unconfigured ruleset requirements. Upstream filters and dependencies keep their own licences.

## Trust model

The public extension may contain a *public* Ed25519 verification key. Production **private** signing keys must never appear in either repository, CI or browser builds. Signed feed updates must reject invalid signatures, oversize inputs, expiry, and rollback; a failure must not trigger an unsigned fallback.

The [visibility audit](.github/workflows/public-visibility.yml) checks public accessibility. It detects drift, but GitHub repository administrators can still change visibility; no workflow can guarantee permanence.

## Development and test

Requires Node.js 22+. Run `npm run check` and `npm test`. These validate the manifest, static DNR resource, link cleaning, signature verification and installer/compiler fixtures. CI passing is **not** the same as Chrome, Brave, Edge or Safari installed-extension testing.

To inspect the source-level Chromium starter, review `manifest.json`, `rules/starter.json` and `src/`. The current blocker layer ships as bundled rules; signing and public distribution require approved offline key custody and independently verified `admine.au` feed bytes. No private GitHub credentials are ever required by a browser.

The source is visible for independent review, but use, modification and commercial distribution permissions remain subject to [LICENSE](LICENSE). Browser store installation packages and published screenshots are not yet provided.

See [docs/BASELINE.md](docs/BASELINE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), and the tracked [completion issues](https://github.com/0xdx-au/sift-ext/issues) for limits and next gates.
