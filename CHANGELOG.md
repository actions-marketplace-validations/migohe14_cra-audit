# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

Releases are automated: pushing a `vX.Y.Z` tag publishes the package to npm
(with provenance) and creates the GitHub Release from the matching section
below, so add the section before running `npm version`.

## [2.0.0] — OSV.dev, CISA KEV & malicious package detection

### Highlights

**Known, actively exploited and malicious dependencies — in one check**

- **OSV.dev** is now the default vulnerability source: every dependency is checked at the exact version pinned in the lockfile (npm, Yarn, pnpm), with severity, CVE aliases and the version that fixes it. `npm` is no longer required.
- **Malicious packages**: compromised releases from the OpenSSF malicious-packages feed (`MAL-*`, e.g. the Shai-Hulud worm versions) always fail the audit and cannot be allowlisted.
- **CISA KEV**: vulnerabilities with evidence of active exploitation fail the audit by default and print the **CRA Art. 14 reporting clock** (24 h / 72 h / 14 days). Use `--no-fail-on-kev` to report them as a warning.
- `--production` now follows the dependency graph, so it works for Yarn and pnpm projects too.
- The allowlist accepts GHSA and CVE identifiers.

### New options

- `--vuln-source osv|npm` / policy `vulnerabilitySource` (default `osv`)
- `--no-fail-on-kev` / policy `failOnKev` (default `true`)

### ⚠️ Breaking changes

- **CLI / CI usage is unchanged** (`npx cra-audit`), but the audit is stricter: malicious packages and actively exploited (KEV) vulnerabilities now fail it.
- **Programmatic API**: `runAudit()` and `scanVulnerabilities()` are now async — add `await`.
- Requires network access to `api.osv.dev` and `cisa.gov`. If OSV.dev is unreachable, the audit falls back to `npm audit` and says so.

## [1.1.0] — TR-03183-2 v2.1 SBOM

### Highlights

**CycloneDX 1.6 SBOM conforming to BSI TR-03183-2 v2.1.0**

- Full dependency graph from npm (v1–v3), Yarn classic/Berry and pnpm (v5–v9) lockfiles, with completeness declared in `compositions`
- SBOM creator (`--creator` flag or `sbomCreator` policy, defaulting to package.json) and component creators read from installed packages
- `bsi:component:filename` / `executable` / `archive` / `structured` properties, SHA-512 on the distribution reference, declared/concluded licenses, source code URI
- `sbom check` validates every TR-03183-2 v2.1 required field

### Fixes

- Licenses of Yarn/pnpm projects now reach the SBOM
- Yarn Berry workspace entries are no longer listed as third-party components
- pnpm v5 lockfile keys with peer suffixes are parsed correctly
- Malformed integrity digests no longer produce schema-invalid hashes

### ⚠️ Stricter validation

- CycloneDX < 1.6 and SPDX < 3.0.1 are flagged (use the default CycloneDX output)
- Yarn Berry projects fail the SHA-512 check (the lockfile doesn't store the npm tarball hash)
- Run it after installing dependencies: component creators and licenses are read from `node_modules`

## [1.0.0]

- Yarn (classic and Berry) and pnpm lockfile support
- CRA audit for npm projects: SBOM (CycloneDX/SPDX), `npm audit` vulnerabilities, licenses and an interactive HTML maintenance report
