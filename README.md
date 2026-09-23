# cra-audit

[![npm](https://img.shields.io/npm/v/cra-audit)](https://www.npmjs.com/package/cra-audit) [![CI](https://github.com/migohe14/cra-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/migohe14/cra-audit/actions/workflows/ci.yml) [![license](https://img.shields.io/npm/l/cra-audit)](LICENSE)

> Compliance audit for the **Cyber Resilience Act** (Regulation EU 2024/2847) and the **BSI TR-03183** technical guideline, for npm projects.

`cra-audit` audits the installed dependencies of an npm project and checks the key requirements that the CRA imposes on "products with digital elements". It runs directly with `npx`, **without installation**, and has **no production dependencies** to minimize its own supply-chain surface.
It reads the project lockfile natively, so it works with **npm** (`package-lock.json` / `npm-shrinkwrap.json`), **Yarn** (classic v1 and Berry v2+ `yarn.lock`) and **pnpm** (`pnpm-lock.yaml`) — auditing the exact versions each package manager pinned.
```bash
# Run ALL the law's checks (Vulnerabilities + Licenses + SBOM)
npx cra-audit

# Interactive visual report (HTML) with maintenance data
npx cra-audit --visualize

# Just the SBOM part
npx cra-audit --sbom
npx cra-audit sbom check
```

---

## What it checks and why (mapping to the regulation)

Under the hood, the package runs the checks derived from the CRA legal obligations and the TR-03183 technical guideline:

### 1. Automatic SBOM validation

Generates and validates a **Software Bill of Materials (SBOM)** in a machine-readable format —**CycloneDX 1.6** (default) or **SPDX 2.3**— from the `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` or `pnpm-lock.yaml`, following the field mapping of **BSI TR-03183-2 v2.1.0**:

| TR-03183-2 data field | Where it comes from | CycloneDX 1.6 field |
| --- | --- | --- |
| Creator of the SBOM (email or URL) | `--creator`, `sbomCreator` policy, or the project's `author` / `homepage` / `repository` | `metadata.manufacturer` |
| Timestamp | generation time (UTC) | `metadata.timestamp` |
| Component creator (email or URL) | installed `package.json`: `author`, `maintainers`, `homepage`, `repository` | `components[].manufacturer` |
| Name, version, purl | lockfile | `name`, `version`, `purl` |
| Filename | tarball name (`left-pad-1.3.0.tgz`) | property `bsi:component:filename` |
| SHA-512 of the deployable component | lockfile `integrity` | `externalReferences[distribution].hashes` |
| Executable / archive / structured | npm tarball: `non-executable`, `archive`, `structured` | properties `bsi:component:*` |
| Dependencies + completeness | lockfile dependency graph (npm v1–v3, Yarn classic/Berry, pnpm v5–v9) | `dependencies`, `compositions[].aggregate` |
| Distribution / original licences | lockfile or installed `package.json` | `licenses[]` with `acknowledgement` `concluded` / `declared` |
| Source code URI | `repository` | `externalReferences[source-distribution]` |

`sbom check` verifies every one of those fields for every component. Licenses (for Yarn/pnpm) and component creators are read from `node_modules`, so **run it after installing dependencies** (e.g. after `npm ci` in CI).

Known limits: Yarn Berry lockfiles only store Yarn's own cache checksum, not the npm tarball SHA-512, so Berry projects fail the hash check. TR-03183-2 v2.1 requires **SPDX ≥ 3.0.1**; the SPDX output is still 2.3, so use CycloneDX for a conforming SBOM.

> CRA Annex I · TR-03183 Part 2 — *"Transparency through SBOM"*.

### 2. Known, actively exploited and malicious dependencies

Checks every **direct and transitive** dependency, at the exact version pinned in the lockfile, against:

| Source | What it finds | Effect on the audit |
| --- | --- | --- |
| [OSV.dev](https://osv.dev) — GitHub Advisory Database | Known vulnerabilities, with severity, CVE aliases and the version that fixes them | Fails at or above `--fail-on` (default `high`) |
| OSV.dev — [OpenSSF malicious packages](https://github.com/ossf/malicious-packages) | Compromised releases (`MAL-*`), e.g. the Shai-Hulud worm versions | **Always fails**; cannot be allowlisted |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities with evidence of **active exploitation** | Fails by default (`--no-fail-on-kev` to only warn) and prints the CRA Art. 14 reporting clock |

```text
  HIGH     [KEV] vite@6.2.3  (fix: vite@6.4.3)
    GHSA-4r4m-qw57-chr8 / CVE-2025-31125 Vite has a `server.fs.deny` bypassed … [KEV since 2026-01-22]

⚠ CRA Art. 14 — actively exploited vulnerability in a dependency
    • Early warning ........ within 24 hours of becoming aware
    • Notification ......... within 72 hours
    • Final report ......... within 14 days after a corrective measure is available
```

Only package names and versions are sent to `api.osv.dev`; the KEV catalogue is downloaded from cisa.gov (or CISA's GitHub mirror). If KEV cannot be reached the report says so instead of silently passing, and if OSV.dev is unreachable the audit falls back to `npm audit`. `--vuln-source npm` uses `npm audit` directly.

> CRA Annex I Part I (2)(a) — *placed on the market without known exploitable vulnerabilities*. Art. 14 — *actively exploited vulnerabilities must be reported within 24 hours*.

### 3. Third-party component check

Identifies every third-party open-source library present in the dependency tree and cross-references it against known security advisories, flagging vulnerable components and whether a fix is available.

> CRA — special attention to third-party developed components.

### 4. License and hash management

Verifies that **all** dependencies have their license documented and compliant with the policy (allowlist / denylist), and that they carry unique identifiers (`purl`) and integrity hashes (SHA-512/384/256) as recommended by TR-03183.

> TR-03183-2 §5.2 — license governance and hash integrity.

### 5. Visualization (`--visualize`)

Generates an **interactive, self-contained HTML report** (no external CDNs, works offline) that gathers, per package: SBOM, installed vs. latest published version, license, vulnerabilities and **maintenance signals** to assess how well each project is maintained:

- Last npm publish and number of maintainers.
- Associated repository.
- (Optional, with `--github`) **last commit** date, number of **contributors** and **stars**.
- **Deprecated** / **archived** indicators.
- A **maintenance score** (0-100) with a label *well-maintained / moderate / at-risk*.

The report includes summary cards, search, filters (vulnerable, outdated, license issues, at risk) and column sorting.

---

## Usage

```bash
# Full audit (default)
npx cra-audit
npx cra-audit audit

# Visual report
npx cra-audit --visualize            # shortcut
npx cra-audit visualize              # long form
npx cra-audit visualize --github     # adds last commit, contributors and stars
npx cra-audit visualize --offline    # no network (skips maintenance metadata)
npx cra-audit visualize --no-open -o report.html

# SBOM
npx cra-audit --sbom                          # = sbom check
npx cra-audit sbom check
npx cra-audit sbom generate -o sbom.cdx.json          # CycloneDX (default)
npx cra-audit sbom generate --format spdx -o sbom.spdx.json
npx cra-audit sbom check -i sbom.cdx.json             # validate an existing SBOM

# Individual checks
npx cra-audit vulnerabilities        # alias: vuln
npx cra-audit licenses
```

### Global installation (optional)

```bash
npm install -g cra-audit
cra-audit --help
```

---

## Commands

| Command | Description |
| --- | --- |
| `cra-audit` / `cra-audit audit` | Full CRA compliance audit (vulnerabilities + SBOM + licenses). **Default.** |
| `cra-audit visualize` (aliases `view`, `report`) | Interactive HTML report with SBOM, licenses, versions and maintenance. |
| `cra-audit sbom generate` | Generate an SBOM (CycloneDX/SPDX). |
| `cra-audit sbom check` | Validate the SBOM against the TR-03183-2 v2.1 data fields. |
| `cra-audit vulnerabilities` (alias `vuln`) | Vulnerability analysis only. |
| `cra-audit licenses` | License analysis only. |
| `cra-audit help` | Show help. |

## Options

| Option | Description |
| --- | --- |
| `--visualize`, `-V` | Shortcut to generate and open the interactive HTML report. |
| `--github` | Enrich the visual report with GitHub data (last commit, contributors, stars). |
| `--offline` | Do not query the network when visualizing (skips maintenance metadata). |
| `--no-open` | Do not open the HTML report in the browser automatically. |
| `--sbom` | Shortcut equivalent to `sbom check`. |
| `--format <fmt>` | SBOM format: `cyclonedx` (default) or `spdx`. |
| `--creator <contact>` | Email or URL of the SBOM creator (TR-03183-2 §5.2.1). Defaults to the project's `package.json` `author` / `homepage` / `repository`. |
| `--fail-on <sev>` | Minimum severity that fails the audit: `info`, `low`, `moderate`, `high`, `critical`. |
| `--vuln-source <src>` | `osv` (default: OSV.dev + CISA KEV) or `npm` (`npm audit`). |
| `--no-fail-on-kev` | Report actively exploited (CISA KEV) vulnerabilities as a warning instead of failing. |
| `--production`, `--prod` | Audit production dependencies only. |
| `--no-sbom` | Do not require an SBOM in the full audit. |
| `--json` | Machine-readable JSON output. |
| `--output`, `-o <path>` | Write the result / SBOM / HTML to a file. |
| `--input`, `-i <path>` | Existing SBOM to validate (for `sbom check`). |
| `--config`, `-c <path>` | Path to the security policy. |
| `--cwd <path>` | Project directory to audit. |
| `--no-color` | Disable colors. |
| `--version`, `-v` · `--help`, `-h` | Version / help. |

### GitHub data and rate limits

With `--github`, the tool queries the public GitHub API to fetch the last commit, contributors and stars. Unauthenticated, GitHub limits to **60 requests/hour**. For large projects, set a read-only token:

```bash
# PowerShell
$env:GITHUB_TOKEN = "ghp_xxx"; npx cra-audit visualize --github
# bash
GITHUB_TOKEN=ghp_xxx npx cra-audit visualize --github
```

The token is only used to add the `Authorization` header on calls to `api.github.com`; it is not stored or sent anywhere else.

---

## The visual report in detail

`cra-audit visualize` writes `cra-audit-report.html` (or the `-o` path) and opens it in the browser. The report is a **single HTML file** with all data embedded and the filtering/sorting logic in its own vanilla JavaScript (no third-party scripts), so it is safe to share and works offline.

| Column | Meaning |
| --- | --- |
| Package | Component name (flags `deprecated` / `archived`). |
| Version | Installed version + `up to date` / `→ latest` indicator. |
| Latest | Latest version published on npm. |
| License | Detected license (red badge if missing or denied). |
| Vulnerability | Highest known severity (`clean` if none). |
| Last activity | Last commit date (with `--github`) or last publish date. |
| Maint. | Number of npm maintainers. |
| Contrib. | Number of GitHub contributors (with `--github`). |
| Maintenance | Score 0-100 based on recency, maintainers, contributors and status. |

Summary cards: total components, vulnerable, license issues, outdated and at risk.

---

## Security policy

Create a `.cra-audit.json` file at the project root to customize the rules (there is an example in `.cra-audit.example.json`):

```json
{
  "failOn": "high",
  "failOnKev": true,
  "vulnerabilitySource": "osv",
  "requireSbom": true,
  "sbomFormat": "cyclonedx",
  "sbomCreator": "security@example.com",
  "productionOnly": false,
  "vulnerabilities": {
    "allowlist": []
  },
  "licenses": {
    "allow": [],
    "deny": ["GPL-3.0", "AGPL-3.0"],
    "failOnMissing": true
  }
}
```

- `failOn`: minimum severity that blocks the audit.
- `failOnKev`: fail when a dependency has an actively exploited vulnerability (CISA KEV). Default `true`.
- `vulnerabilitySource`: `osv` (OSV.dev + CISA KEV) or `npm` (`npm audit`).
- `requireSbom`: require the SBOM to meet the TR-03183-2 required data fields.
- `sbomFormat`: `cyclonedx` or `spdx`.
- `sbomCreator`: email or URL of the entity that creates the SBOM (usually the manufacturer).
- `productionOnly`: audit production dependencies only.
- `vulnerabilities.allowlist`: package names or advisory ids (GHSA, CVE) accepted with documented justification, e.g. when the vulnerable code is not reachable in your product. Malicious packages (`MAL-*`) cannot be allowlisted.
- `licenses.allow` / `licenses.deny`: allowed / denied lists (SPDX id).
- `licenses.failOnMissing`: treat undocumented licenses as a failure.

Command-line options take precedence over the policy file.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit passed (or report generated successfully). |
| `1` | Audit failed or execution error. |

Suitable for CI/CD: a non-`0` code blocks the pipeline.

```yaml
# Example in GitHub Actions
- name: CRA compliance audit
  run: npx cra-audit --fail-on high --production --json -o cra-report.json
```

---

## Programmatic API

```js
const {
  runAudit, loadPolicy, generateSbom, validateSbom,
  scanVulnerabilities, checkLicenses, parseLockfile,
  enrichComponents, buildHtml,
} = require('cra-audit');

const { policy, source } = loadPolicy(process.cwd());
const report = await runAudit(process.cwd(), policy, source);
console.log(report.gate.passed ? 'OK' : 'FAILED');

// Maintenance data + custom HTML report
const { components } = parseLockfile(process.cwd());
const signals = await enrichComponents(components, { network: true, github: true });
```

---

## Requirements

- Node.js >= 18 (uses native `fetch` and `node --test`).
- Network access to `api.osv.dev` and `cisa.gov` (or `raw.githubusercontent.com` for the KEV mirror). `npm` on the `PATH` is only needed for `--vuln-source npm` or the offline fallback.
- A lockfile present: `package-lock.json` / `npm-shrinkwrap.json` (npm), `yarn.lock` (Yarn classic or Berry) or `pnpm-lock.yaml` (pnpm). Run `npm install` / `yarn` / `pnpm install` if missing.

## See also

- [hulud-party-scanner](https://www.npmjs.com/package/hulud-party-scanner) — incident response for a machine that may have installed a compromised package: lifecycle-hook analysis, malicious code patterns and Shai-Hulud artifacts in the home directory.

## Legal notice

`cra-audit` is a technical support tool. It helps verify controls associated with the CRA and TR-03183, but it **does not constitute legal advice** nor does it guarantee regulatory compliance on its own.

## License

MIT
