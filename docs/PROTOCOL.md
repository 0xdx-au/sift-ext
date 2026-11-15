# SIFT public verification protocol — v1

The extension may consume signed release data only after an authorised public verification key is pinned. The signing *private* key belongs outside GitHub and CI.

- The signed payload is the exact UTF-8 bytes of a JSON object with `format: admine.sift.release.v1`, `keyId`, positive monotonic `sequence`, UTC ISO `issuedAt` and `expiresAt`, and a portable `policy`.
- Detached proof contains `format: admine.sift.signature.v1`, `keyId`, Ed25519 `signature` as canonical base64, SHA-256 `sha256` in lowercase hex, and exact payload byte `length`.
- Verify bytes and authenticity before interpreting policy. Reject unknown keys, bad hashes/signatures, expiry, invalid structures and unsupported matching semantics.
- Existing state anchors both sequence and SHA-256: same-sequence substitution is rejected unless the digest matches; lower sequences are always rejected.
- Budgets: 8 MB signed payload, 2,048-character proof, 31-day maximum validity, bounded lists and rule groups.

The public verifier, bounded downloader, policy compiler and staged installation coordinator now have unit tests. The coordinator journals an attempted policy replacement and tracks the last accepted policy. This is a **testable internal mechanism**, not a completed authenticated recovery workflow: retained compiled rules must be reauthenticated against the pinned signing key before privileged startup restoration is enabled. Automatic startup restoration is deliberately disconnected.

**This does not enable live remote feed updates.** No production public key is pinned, there is no approved signing identity or public CDN release, and the update coordinator is deliberately not scheduled or callable through the popup. The current client uses only packaged starter rules. Real-browser QA for signed-update installation, quota failures and restart recovery must still pass before automatic updates are enabled.

The local sequence/hash anchor protects ordinary update flows, not reinstalls, profile restoration, storage deletion or an attacker who can alter privileged extension storage. Independent key lifecycle and recovery reviews remain mandatory.
