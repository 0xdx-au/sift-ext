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

**Current status:** Repository policy and scaffolding are being established. A publicly visible repo is not proof of a published store extension, live signed feed, or installed-browser validation. Do not advertise those as complete until verified.

## Commercial rights

This repo is **source-visible, rights reserved**. ADMINE retains its ability to sell and commercially license the client later. The code is not automatically offered under MIT, Apache-2.0 or another broad reuse licence simply because it is public.

See [LICENSE](LICENSE), [COMMERCIAL.md](COMMERCIAL.md) and [SECURITY.md](SECURITY.md). Upstream filters and dependencies keep their own licences.

## Trust model

The public extension may contain a *public* Ed25519 verification key. Production **private** signing keys must never appear in either repository, CI or browser builds. Signed feed updates must reject invalid signatures, oversize inputs, expiry, and rollback; a failure must not trigger an unsigned fallback.

The [visibility audit](.github/workflows/public-visibility.yml) checks public accessibility. It detects drift, but GitHub repository administrators can still change visibility; no workflow can guarantee permanence.
