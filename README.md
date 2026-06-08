# cra-audit

> Compliance audit for the **Cyber Resilience Act** (Regulation EU 2024/2847) and the **BSI TR-03183** technical guideline, for npm projects.

`cra-audit` audits the installed dependencies of an npm project and checks the key requirements that the CRA imposes on "products with digital elements". It runs directly with `npx`, **without installation**, and has **no production dependencies** to minimize its own supply-chain surface.

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

Generates and validates a **Software Bill of Materials (SBOM)** in a machine-readable format —**CycloneDX 1.5** or **SPDX 2.3**— from the `package-lock.json` / `npm-shrinkwrap.json`. It verifies the **minimum elements** required by TR-03183 §6 for every component: name, version, unique identifier (`purl`), cryptographic integrity hash and license.

> CRA Annex I · TR-03183 Part 2 — *"Transparency through SBOM"*.

### 2. "Zero known vulnerabilities" audit

Scans **direct and transitive** dependencies (from the lockfile) with `npm audit` and blocks the audit if there are exploitable vulnerabilities above the configured threshold.

> CRA Art. 13 — *products must be placed on the market without known exploitable vulnerabilities*.

### 3. Third-party component check

Identifies every third-party open-source library present in the dependency tree and cross-references it against known security advisories, flagging vulnerable components and whether a fix is available.

> CRA — special attention to third-party developed components.

### 4. License and hash management

Verifies that **all** dependencies have their license documented and compliant with the policy (allowlist / denylist), and that they carry unique identifiers (`purl`) and integrity hashes (SHA-512/384/256) as recommended by TR-03183.

> TR-03183 §6 — license governance and hash integrity.

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
| `cra-audit sbom check` | Validate the SBOM against the TR-03183 minimum elements. |
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
| `--fail-on <sev>` | Minimum severity that fails the audit: `info`, `low`, `moderate`, `high`, `critical`. |
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
  "requireSbom": true,
  "sbomFormat": "cyclonedx",
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
- `requireSbom`: require the SBOM to meet the TR-03183 minimum elements.
- `sbomFormat`: `cyclonedx` or `spdx`.
- `productionOnly`: audit production dependencies only.
- `vulnerabilities.allowlist`: advisory/CVE identifiers accepted with documented justification.
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
const report = runAudit(process.cwd(), policy, source);
console.log(report.gate.passed ? 'OK' : 'FAILED');

// Maintenance data + custom HTML report
const { components } = parseLockfile(process.cwd());
const signals = await enrichComponents(components, { network: true, github: true });
```

---

## Requirements

- Node.js >= 18 (uses native `fetch` and `node --test`).
- `npm` available on the `PATH` (for `npm audit`).
- A `package-lock.json` or `npm-shrinkwrap.json` present (run `npm install` if missing).

## Legal notice

`cra-audit` is a technical support tool. It helps verify controls associated with the CRA and TR-03183, but it **does not constitute legal advice** nor does it guarantee regulatory compliance on its own.

## License

MIT
