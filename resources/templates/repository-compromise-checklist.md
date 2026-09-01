# Repository Compromise Checklist

## Preserve before remediation

- [ ] Export repository, organization, identity, package, registry, cloud, and provider audit logs
- [ ] Preserve suspicious Git objects, refs, commits, diffs, tags, releases, signatures, reviews, and settings
- [ ] Preserve workflow definitions, runs, artifacts, cache metadata, runner state, environments, deployments, and OIDC records
- [ ] Record actors, identities, token types, IP addresses, timestamps, correlation IDs, scope, collection method, hashes, and storage

## Scope and contain

- [ ] Review maintainers, collaborators, teams, sessions, PATs, SSH/deploy keys, apps, OAuth grants, secrets, signing keys, and cloud/registry credentials
- [ ] Review workflow permissions/triggers, reusable workflows, actions, runners, hooks, bots, webhooks, apps, scheduled jobs, branch protections, and rulesets
- [ ] Review dependencies, lockfiles, submodules, packages, artifacts, releases, caches, images, provenance, and downstream consumers
- [ ] Revoke exposed authority and stop active delivery paths with documented impact, approval, validation, and rollback

## Trusted recovery

- [ ] Establish the last trusted source point using independent evidence
- [ ] Run code, secret, dependency, and incident-specific scans
- [ ] Rebuild from trusted source and dependencies in a clean environment without suspect caches
- [ ] Validate hashes, signatures, provenance, SBOMs, tests, permissions, approvals, and business behavior
- [ ] Approve residual risk, monitoring window, rollback triggers, and accountable owners
