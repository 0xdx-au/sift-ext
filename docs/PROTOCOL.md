# SIFT public verification protocol — v1

The extension may consume signed release data only after an authorised public verification key is pinned. The signing *private* key belongs outside GitHub and CI.

- The signed payload is the exact UTF-8 bytes of a JSON object with `format: admine.sift.release.v1`, `keyId`, positive monotonic `sequence`, UTC ISO `issuedAt` and `expiresAt`, and a portable `policy`.
- Detached proof contains `format: admine.sift.signature.v1`, `keyId`, Ed25519 `signature` as canonical base64, SHA-256 `sha256` in lowercase hex, and exact payload byte `length`.
- Verify bytes and authenticity before interpreting policy. Reject unknown keys, bad hashes/signatures, expiry, invalid structures and unsupported matching semantics.
- Existing state anchors both sequence and SHA-256: same-sequence substitution is rejected unless the digest matches; lower sequences are always rejected.
- Budgets: 8 MB signed payload, 2,048-character proof, 31-day maximum validity, bounded lists and rule groups.

`src/intelligence/verify.mjs` is an independent public verifier with test-only disposable signing fixtures. It is not yet wired to remote acquisition, DNR installation, persistent rollback state or a production signing pin. The current client therefore uses packaged rules only; live signed feed protection remains **not provisioned**.
