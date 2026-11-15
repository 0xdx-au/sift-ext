# Required GitHub protection — verified gap

As of 15 November 2026, GitHub reports main is UNPROTECTED and the ruleset list is EMPTY. This is a release blocker. A green CI job or CODEOWNERS file is not a protection rule. The current connected integration cannot alter these settings (the branch-protection endpoint returned HTTP 403).

## Owner configuration

Open https://github.com/0xdx-au/sift-ext/settings/rules and create a BRANCH ruleset:

- Name: SIFT EXT / protected main
- Enforcement: Active (not Evaluate)
- Target: default branch / main
- Bypass list: none for ordinary accounts, CI and Apps
- Block force pushes and deletion
- Require a pull request before merging
- Require status checks and an up-to-date branch
- Require a review from another authorised maintainer if one exists; authors cannot approve their own pull requests. Do not use a fake self-review requirement that deadlocks a single-maintainer repository.
- Dismiss stale approvals after new pushes and prevent bypass where the UI supports these rules.

Select the check names that actually run on pull requests:

- Repository hygiene / review
- GitHub landing page QA / docs
- Public visibility policy / audit
- Security assurance / Source security gate

When engineering PR #1 is merged into main, also require:

- Client source checks / test
- Chromium installed-extension QA / installed-browser

Do NOT require the scheduled-only Security assurance / Default-branch protection monitor for PRs: it cannot appear on an ordinary pull request and would deadlock merging.

## Human and automation controls

Require code-owner review when another eligible reviewer exists, especially for .github/workflows/, .github/CODEOWNERS, LICENSE, COMMERCIAL.md, SECURITY.md and the public trust pin. Set default Actions token to read-only, require passkeys/MFA, enable secret scanning/push protection, Dependabot and code scanning where available. A disabled production feed has no justification for CI signing secrets.

## Evidence and negative testing

After saving the ruleset, visit the public branch API:

https://api.github.com/repos/0xdx-au/sift-ext/branches/main

Confirm protected is true and https://api.github.com/repos/0xdx-au/sift-ext/rulesets is nonempty, with the applicable ruleset active. Verify a direct push, force push and deletion are rejected for a non-bypass account; and verify a failed status check prevents a test PR merge. Verify that approvals are invalidated when a PR changes after review.

The scheduled Security assurance workflow checks the GitHub-reported protected state and deliberately fails until this is enforced. It is monitoring, NOT protection.

A separate release audit must validate the extension source, supply chain and signing workflow before any store or CDN release. Public visibility does not grant open-source or commercial licensing rights; see LICENSE.
