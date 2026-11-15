## Summary
Explain the change and its impact.

## Threat model and QA
- [ ] Tests pass for the exact head commit, including negative and recovery cases where relevant.
- [ ] No private signing key, credential, browsing-history dataset or private curation material.
- [ ] Manifest permissions/Incognito behaviour, origins, and storage exposure reviewed.
- [ ] No unauthorised network, remote code or runtime trust-pin changes.
- [ ] Workflows remain SHA-pinned, read-only and safe for external pull requests.
- [ ] Licence, attribution, security disclosure and privacy wording remain accurate.
- [ ] ADMINE visuals retain the approved Contour-A mark and both themes.
- [ ] Production rollout and rollback gates explicitly documented.

This PR is not authorisation to deploy a production signed feed or browser-store package.
