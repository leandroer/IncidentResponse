# Deployment source-of-truth record

Verified on September 1, 2026 before modernization changes were made.

## Observed relationship

| Published path | Authoritative repository and branch | Observed commit | Deployment method |
|---|---|---|---|
| `https://lrinfosec.com/` | `leandroer/leandroer.github.io`, `main` | `92328b49e87252b28cd6794554cf1dab290ebdd9` | Next.js static export built by `.github/workflows/pages.yml` and deployed with GitHub Pages Actions |
| `https://lrinfosec.com/IncidentResponse/` | `leandroer/IncidentResponse`, `main` | `5381dda08528dfe27a5a34b15e7a18a038ab26d7` | GitHub Pages project site from the repository content |

## Evidence

- GitHub's public repository metadata reported `main` as the default and only published branch for `leandroer/IncidentResponse`; the repository also had the dynamic `pages-build-deployment` workflow.
- The production `/IncidentResponse/` response had a `Last-Modified` timestamp matching the July 17 framework deployment, and its SHA-256 was identical to `IncidentResponse/index.html` at `5381dda`.
- The root response was a Next.js export containing the newer AI Security IR and repository-compromise routes. Those source routes exist in `leandroer/leandroer.github.io` under `app/`.
- The successful root-site Pages workflow run for `92328b4` built `out/` from `leandroer/leandroer.github.io/main` on August 29, 2026.
- DNS resolved the apex to GitHub Pages addresses and `www.lrinfosec.com` to `leandroer.github.io`.

## Operating decision

The repositories retain separate authority boundaries:

- This repository owns the standalone Incident Response framework and `/IncidentResponse/` project site.
- `leandroer/leandroer.github.io` owns the root LR InfoSec website, articles, and top-level navigation.

Do not copy generated Next.js HTML into this repository. Reconcile operational guidance at the source level, preserve the framework's static architecture and restrictive CSP, and review root-site changes separately in the root-site repository.
