# SIFT EXT repository hardening

## Verified project split

- `0xdx-au/sift-ext` is the **public** client repository.
- `0xdx-au/sift` is the **private** publishing and curation repository.
- The approved anonymous feed location is planned at `https://admine.au/feeds/sift/current.json` with `current.sig.json`. These are not live.
- Publishing a repo publicly does not grant commercial rights; see [LICENSE](LICENSE).

## Required GitHub settings (manual, not yet enforced)

GitHub's connected API cannot change these repository settings. Configure and independently verify:

1. **Ruleset for `main`:** require pull requests before merge; require passing `Repository hygiene / review`, `GitHub landing page QA / docs`, `Security assurance / Source security gate`, and `Public visibility policy / audit`; block force pushes and branch deletion. Set reviewer requirements supported by your account and plan. Protect `.github/workflows`, `LICENSE` and `COMMERCIAL.md` through code-owner review.
2. **Actions:** allow only trusted actions and pin any third-party actions to immutable commit SHAs; default workflow token to read-only; disable permissive write and untrusted fork workflows.
3. **Security:** enable secret scanning and push protection where available; review Dependabot and code-scanning settings as supported; enable 2FA/passkeys for maintainers.
4. **Publication:** check store privacy declarations, signed release provenance, pinned verification key, licence/attribution notices, and installed-browser network tests before releasing.
5. **Visibility:** leave this repository public and monitor the daily `Public visibility policy` workflow. A GitHub administrator can still change visibility; a workflow cannot prevent that change. Enable notifications for failed Actions runs.

## Public-source boundary

No upstream private curations, per-user browsing data, production private signing keys, PATs, privileged GitHub Apps, or Cloudflare API secrets may be committed here.

A public GitHub repo is not a trustworthy signing authority. SIFT clients must accept only signatures from a pinned public key and reject invalid, oversized, expired and rolled-back releases.

## Commercial future

Current posture: source-visible, ADMINE rights reserved. This preserves the ability to sell separately licensed builds later. It does **not** give third parties an automatic right to commercialise the implementation. Third-party feed licences must be reviewed independently.

## Known release gaps

The default branch currently contains the public README and governance documents. The Manifest V3 client is under draft engineering review; it is not independently reconciled to a previously packaged Link Signal release. The signed public feed has not been deployed or provisioned with a production key. Do not describe this as a store-ready release.
