# Security and disclosure

SIFT EXT is the **public** browser client. The SIFT feed compiler, curation
pipeline and publication operations belong in the **private** SIFT repository.

Do not commit any production private signing key, GitHub token, API secret,
private feed credential, individual browsing URL, or telemetry dataset here.

The extension must pin only public verification keys and must reject
bad signatures, malformed or oversized signed policy, expiry and rollback.
No unsigned fallback or unreported block widening is permitted.

Before shipping: verify least-privilege browser permissions, on-device
request interception, site exclusions, failure-mode handling, privacy
disclosures, and cross-browser capability differences.

Report vulnerabilities privately through https://admine.au/; do not include
exploit details or browsing data in public issues.

This document is a policy, not a claim of completed production validation.
