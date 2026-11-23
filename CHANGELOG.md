# Changelog

All notable changes to VulnDesk are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-24

First public release.

### Added

- **Multi-tenancy** — organisations/workspaces with tenant-scoped data access
  enforced in the data layer; cross-tenant reads and writes return 404.
- **Authentication** — registration and login with scrypt-hashed passwords,
  opaque session tokens (only SHA-256 hashes stored), cookie and bearer
  token support, logout with server-side invalidation.
- **RBAC** — owner / admin / analyst / viewer roles with a named-permission
  matrix checked on every route; the workspace owner role cannot be granted,
  re-roled or removed.
- **Programmes** — per-workspace bounty programmes with platform and scope.
- **Findings lifecycle** — `new → triaged → accepted → duplicate /
  informative → fixed` with a validated transition map, assignment to
  workspace members, and filters by status, severity, programme and assignee.
- **CVSS 3.1 scoring engine** — full FIRST base-score equations, verified
  against published vectors (10.0 / 9.8 / 7.5 / 6.1 / 0.0 anchors); severity
  is always derived from the vector, never client-claimed.
- **Dedupe engine** — SHA-256 fingerprints over
  (normalised target, class, parameter); exact matches are flagged as
  possible duplicates on submission, same-class/same-host findings are
  surfaced as "similar". Comparisons never cross a tenant boundary.
- **Reports** — every finding renders as a professional report (metadata,
  description, reproduction, impact, remediation, dedupe provenance) in the
  browser and as a downloadable Markdown export.
- **Dashboard & stats API** — counts by severity and status, per-programme
  totals/open counts, recent findings and recent activity.
- **Audit log** — every mutating action recorded per workspace.
- **Dual store backends** behind one repository contract: SQLite
  (`node:sqlite`, Node ≥ 22) and a portable JSON-file store (Node ≥ 18),
  both covered by the same conformance test suite.
- **Seed script** — demo workspace with 3 users, 2 programmes and 12
  findings including a duplicate pair.
- **Docker** image and docker-compose setup; GitHub Actions CI on
  Node 18 / 20 / 22.
- Test suite: 61 tests covering auth, RBAC denials, cross-tenant isolation,
  dedupe flagging, lifecycle transitions, report rendering, CVSS anchors,
  dashboard/stats and store conformance.
