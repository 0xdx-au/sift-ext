# SIFT public verification and recovery protocol — v1

The client consumes only authenticated policy releases. Production signing **private** keys remain outside GitHub, the browser, CI and CDN. The browser package can pin only an approved Ed25519 **public** key.

## Signed releases

- The publisher signs exact UTF-8 JSON payload bytes containing `format: admine.sift.release.v1`, `keyId`, monotonic positive `sequence`, ISO UTC `issuedAt`/`expiresAt`, and the bounded portable policy.
- The detached proof supplies `format: admine.sift.signature.v1`, the `keyId`, canonical base64 Ed25519 signature, SHA-256 hash and exact payload byte length.
- The client checks the signed bytes before compilation. It rejects unexpected key IDs, invalid signature/hash, malformed schema, expiry, rollback and same-sequence substitution.
- Transport maximum: 8,000,000 bytes for signed payload, 2,048 characters for proof, and a maximum 31-day validity. Durable local retention is more conservative at **6,000,000 bytes** to preserve storage quota headroom.

## Durable accepted state and crash recovery

The v2 journal keeps the last accepted **exact signed payload**, detached proof, signed metadata and pending-install marker. Cached compiled rules are not trust evidence.

1. Reverify acquired signed bytes and their proof, including last accepted sequence/hash.
2. Compile only supported Chromium contextual network rules and reject candidates truncated by the approved DNR quota.
3. Persist the installation journal with `pending=true` while retaining the prior signed bytes.
4. Install via DNR and read back installed rules.
5. Persist the newly accepted signed payload and proof, clearing `pending`.
6. On failure, reverify the prior signed release and restore its compiled rules. If recovery cannot be confirmed, quarantine SIFT-owned dynamic rules.

Startup reconciliation independently checks cached signatures, key ID, metadata and expiry against the **package-pinned** public key. Tampered, expired or unprovisioned cache is quarantined. Bundled starter protection remains separate. Stored data does not acquire signing authority by existing in extension storage.

The extension restricts local/session storage to trusted extension contexts. Startup discards prior session pause snapshots, so an unauthenticated session snapshot cannot revive dynamic rules after a browser/worker restart.

## Verified versus production

Source tests cover signature verification, tampering, replay, expiry, malformed journals, installation failure, pause and interrupted recovery. Installed Chromium tests exercise DNR blocking and signed-release installation using a disposable test signer, never a production key.

**Production is disabled:** `src/intelligence/trust.mjs` exports `SIGNING_PIN = null`. There is no approved public key, no live signed release and no automated network fetch. The packaged starter rules are the only protection enabled by default. No production private key belongs in the public repository or CI.

## Known release gates

- Local profile/storage deletion and restore can reset sequence anchors. Pinning and expiry remain effective for the signed bytes, but robust anti-rollback across profile restoration requires additional threat modelling.
- Enforcement of expiry during a continuously running browser, key rotation/revocation, store upgrades, quota boundary cases and crash test coverage remain open.
- Chrome, Edge, Brave and Safari require separate installed-version QA. Chromium CI is not equivalent to those certifications.
- Mutable `current.json` and `current.sig.json` are not an atomic CDN pointer. Mismatched cached pairs must fail closed. Independent promotion, a signed version index and external byte verification remain release gates.
