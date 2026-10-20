# Repository security hardening

This document records the security controls that protect this static site and the
remaining deployment-layer settings that are not represented in the repository.

## Automated checks

`site-quality.yml` checks site structure and local links. `security-audit.yml`
performs a separate fail-closed audit of every HTML and JavaScript file. It checks
the approved Content Security Policy (CSP), executable markup, unsafe DOM sinks,
external active content, insecure resources, embedded content, browser network or
storage use, and URL-derived input.

Both workflows have read-only repository permission and use an immutable commit
SHA for `actions/checkout`.

## Content Security Policy

Every production HTML page contains this restrictive meta policy:

```text
default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; upgrade-insecure-requests
```

The production site was checked on 6 October 2026. GitHub Pages returned HTTPS and
HSTS, but did not return an HTTP `Content-Security-Policy` response header. The meta
policy remains useful, but an equivalent HTTP response header is the preferred
deployment-layer control because it is applied before the document is parsed and
supports the full CSP feature set. GitHub Pages does not provide per-repository
custom response headers. If the site is later placed behind a configurable CDN or
host, configure the exact policy above as the `Content-Security-Policy` response
header; do not remove or weaken the meta policy until the header deployment has
been verified.

## Native GitHub secret protection

GitHub native secret scanning and push protection were enabled for this public
repository on 6 October 2026. They are preferred to a third-party workflow with
additional supply-chain and permission exposure. To verify or restore them:

1. Open **Settings → Security → Advanced Security**.
2. Enable **Secret scanning**.
3. Enable **Push protection** under secret scanning.
4. Consider validity checks and non-provider patterns when they are available for
   the repository and acceptable for the expected alert volume. Both optional
   features were unavailable or left disabled at the time of this review.

The `.gitignore` blocks common local environment, credential, certificate,
private-key, and Terraform state files. Ignore rules are defense in depth, not a
secret-management mechanism. Revoke a committed credential before removing it
from current files or history.

## Main-branch ruleset

The active `Protect main` ruleset should target the default branch with no routine
bypass actors and retain these settings:

- require changes through a pull request;
- require `structural-audit` and `security-audit` status checks;
- require the branch to be current before merge;
- require all review conversations to be resolved;
- block force pushes and branch deletion.

For this solo-maintained repository, zero mandatory approving reviews is
intentional: pull requests, required automated checks, and resolved conversations
remain enforceable without preventing the only maintainer from merging. Enable a
CODEOWNER approval only after another real, trusted reviewer is available. Signed
commits are recommended only after confirming that the maintainer's web, CLI,
Dependabot, and emergency workflows all produce verifiable signatures. Keep
bypass permissions empty or limited to a narrowly controlled emergency role.

Repository administrators can update this under **Settings → Rules → Rulesets →
Protect main**. The `security-audit` check was added to the active ruleset after
its first successful run on 6 October 2026.

## GitHub Actions policy

The repository workflows pin actions to full commit SHAs. On 20 October 2026,
the repository Actions policy was changed to selected GitHub-owned actions only,
with full-length SHA pinning enforced administratively. Verified-creator wildcard
access is disabled. Workflow tokens remain read-only by default and cannot
approve pull requests. Required structural/security checks and the existing
solo-maintainer ruleset remain active.

The root website additionally requires its build and CodeQL result checks.
Publication approval archives in the private operations repository are protected
by pull requests and a required integrity-validation workflow. Its validation
checks the exact approved draft digest and deployed-source verification evidence.

## External link monitoring

External references use HTTPS-only, credential-free, public-address checks and
bounded redirects, retries, and HEAD-to-GET fallback. Confirmed HTTP 404/410 and
persistent server errors are reported as broken. Authentication/bot protection,
rate limiting, and exhausted network/TLS failures are reported as inconclusive,
not as verified links. Private or synthetic DNS targets are never fetched; a VPN
or proxy can make a public reference inconclusive. The structural/security audits
remain separate and fail closed for their respective repository baselines.
