'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runJson } = require('../utils/exec');
const { exists, readJson } = require('../utils/fs');
const { parseLockfile, toNpmLockfile, componentKey, buildPurl } = require('./lockfile-parser');
const {
  queryOsv, osvSeverity, cvssScore, isMalicious, fixedVersion, compareSemver,
} = require('./osv');
const { loadKev } = require('./kev');

const SEVERITY_ORDER = ['info', 'low', 'moderate', 'high', 'critical'];

/**
 * Scans direct and transitive dependencies for known vulnerabilities. The CRA
 * requires products to ship "without known exploitable vulnerabilities"
 * (Annex I) and, since 11 September 2026, the reporting of actively exploited
 * ones (Art. 14), so this is the core gate of the audit.
 *
 * Sources:
 *  - `osv` (default): every exact `name@version` from the lockfile is checked
 *    against OSV.dev (GitHub advisories + OpenSSF malicious packages), and the
 *    CVEs found are cross-checked with the CISA KEV catalogue.
 *  - `npm`: `npm audit`. Also the fallback when OSV.dev is unreachable.
 *
 * An existing SBOM of any ecosystem can be scanned instead of the lockfile by
 * passing the result of readSbom() as `parsed`; its components are looked up
 * in OSV.dev by Package URL.
 *
 * @param {string} projectRoot
 * @param {{ production?: boolean, source?: 'osv'|'npm', kev?: boolean, parsed?: object }} [options]
 * @returns {Promise<object>}
 */
async function scanVulnerabilities(projectRoot, { production = false, source = 'osv', kev = true, parsed: given } = {}) {
  const fromSbom = Boolean(given && given.manager === 'sbom');
  if (source === 'npm') {
    if (fromSbom) {
      return { ok: false, error: '`npm audit` cannot scan an input SBOM; use the default OSV source.', counts: emptyCounts(), vulnerabilities: [] };
    }
    return npmAuditSection(projectRoot, { production });
  }

  const parsed = given || parseLockfile(projectRoot);
  if (!parsed.ok) {
    return { ok: false, error: parsed.error, counts: emptyCounts(), vulnerabilities: [] };
  }

  let components = parsed.components;
  if (production) {
    components = fromSbom
      ? components.filter((c) => !c.optional)
      : productionComponents(parsed, readJson(path.join(projectRoot, 'package.json')) || {});
  }
  const scannable = components.filter((c) => c.name && c.version);

  const [osv, catalogue] = await Promise.all([
    queryOsv(scannable),
    kev ? loadKev() : Promise.resolve(null),
  ]);

  if (!osv.ok) {
    if (fromSbom) return { ok: false, error: osv.error, counts: emptyCounts(), vulnerabilities: [] };
    const fallback = npmAuditSection(projectRoot, { production });
    fallback.warnings = [`${osv.error}; fell back to \`npm audit\` (no malicious-package or KEV check).`];
    return fallback;
  }

  const direct = new Set(parsed.root.dependsOn);
  const vulnerabilities = [];
  for (const c of scannable) {
    const key = c.key || componentKey(c.name, c.version);
    const records = osv.byComponent.get(key);
    if (!records || !records.length) continue;
    vulnerabilities.push(toFinding(c, records, direct.has(key), catalogue));
  }

  const counts = emptyCounts();
  for (const v of vulnerabilities) {
    counts[v.severity] = (counts[v.severity] || 0) + 1;
    if (v.malicious) counts.malicious++;
    if (v.kev) counts.kev++;
  }
  counts.total = vulnerabilities.length;

  return {
    ok: true,
    source: 'osv',
    scanned: scannable.length,
    input: fromSbom ? { file: parsed.sourceFile, format: parsed.format, unidentified: parsed.unidentified } : null,
    ecosystems: [...new Set(scannable.map((c) => c.ecosystem || 'npm'))].sort(),
    kev: catalogue
      ? (catalogue.ok
        ? { checked: true, catalogVersion: catalogue.catalogVersion, entries: catalogue.count }
        : { checked: false, error: catalogue.error })
      : { checked: false, error: 'KEV check disabled' },
    counts,
    vulnerabilities: sortBySeverity(vulnerabilities),
  };
}

/** One finding per vulnerable component, aggregating its OSV records. */
function toFinding(component, records, isDirect, catalogue) {
  const sources = records.map((record) => {
    const aliases = record.aliases || [];
    const cves = [record.id, ...aliases].filter((id) => /^CVE-/i.test(id));
    const kevEntry = catalogue && catalogue.ok
      ? cves.map((cve) => catalogue.byCve.get(cve.toUpperCase())).find(Boolean) || null
      : null;
    return {
      id: record.id,
      aliases,
      title: record.summary || (isMalicious(record) ? 'Malicious package' : record.id),
      url: `https://osv.dev/vulnerability/${record.id}`,
      severity: osvSeverity(record),
      cvss: cvssScore(record),
      cwe: (record.database_specific && record.database_specific.cwe_ids) || [],
      malicious: isMalicious(record),
      fixed: fixedVersion(record, component.osvName || component.name, component.version),
      kev: kevEntry,
    };
  });

  const severity = sources.map((s) => s.severity)
    .reduce((max, s) => (severityRank(s) > severityRank(max) ? s : max), 'unknown');
  const fixes = sources.map((s) => s.fixed);
  // Only claim a fix when every advisory has one; suggest the highest of them.
  const fix = fixes.every(Boolean)
    ? fixes.reduce((a, b) => (compareSemver(a, b) >= 0 ? a : b))
    : null;

  return {
    name: component.name,
    version: component.version,
    purl: component.purl || buildPurl(component.name, component.version),
    ecosystem: component.ecosystem || 'npm',
    severity,
    direct: isDirect,
    range: null,
    malicious: sources.some((s) => s.malicious),
    kev: sources.some((s) => s.kev),
    fixAvailable: fix
      ? { name: component.name, version: fix, breaking: major(fix) !== major(component.version) }
      : false,
    // Malicious and actively exploited advisories first, then by severity.
    sources: sources.sort((a, b) => Number(b.malicious) - Number(a.malicious) ||
      Number(Boolean(b.kev)) - Number(Boolean(a.kev)) ||
      severityRank(b.severity) - severityRank(a.severity)),
  };
}

/**
 * Components reachable from the production dependencies declared in
 * package.json (`dependencies` + `optionalDependencies`), following the graph.
 */
function productionComponents(parsed, rootPkg) {
  const prodNames = new Set([
    ...Object.keys(rootPkg.dependencies || {}),
    ...Object.keys(rootPkg.optionalDependencies || {}),
  ]);
  const byKey = new Map(parsed.components.map((c) => [componentKey(c.name, c.version), c]));
  const queue = parsed.root.dependsOn.filter((key) => prodNames.has(byKey.has(key) ? byKey.get(key).name : null));
  const seen = new Set(queue);
  while (queue.length) {
    const comp = byKey.get(queue.shift());
    if (!comp) continue;
    for (const dep of comp.dependsOn) {
      if (!seen.has(dep)) { seen.add(dep); queue.push(dep); }
    }
  }
  return parsed.components.filter((c) => seen.has(componentKey(c.name, c.version)));
}

function severityRank(severity) {
  return SEVERITY_ORDER.indexOf(severity);
}

function major(version) {
  return parseInt(String(version).replace(/^v/i, '').split('.')[0], 10);
}

/** `npm audit` source, used on request or as the OSV fallback. */
function npmAuditSection(projectRoot, { production }) {
  const result = npmAudit(projectRoot, { production });
  return {
    ...result,
    source: 'npm-audit',
    kev: { checked: false, error: 'npm audit reports no CVE identifiers' },
  };
}

function npmAudit(projectRoot, { production = false } = {}) {
  if (hasNpmLockfile(projectRoot)) {
    return runNpmAudit(projectRoot, { production });
  }

  const parsed = parseLockfile(projectRoot);
  if (parsed.ok && parsed.components.length > 0) {
    return auditSynthesized(parsed, { production });
  }

  // No usable lockfile: run npm audit in place so the user gets npm's own error.
  return runNpmAudit(projectRoot, { production });
}

function hasNpmLockfile(projectRoot) {
  return exists(path.join(projectRoot, 'package-lock.json')) ||
    exists(path.join(projectRoot, 'npm-shrinkwrap.json'));
}

/** Runs `npm audit --json` in the given directory. */
function runNpmAudit(cwd, { production = false, packageLockOnly = false } = {}) {
  const args = ['audit', '--json'];
  if (production) args.push('--omit=dev');
  if (packageLockOnly) args.push('--package-lock-only');

  const result = runJson('npm', args, { cwd });

  if (!result.data) {
    return {
      ok: false,
      error:
        'Could not run `npm audit`. Make sure npm is installed and a ' +
        'lockfile is present. ' +
        (result.stderr ? `Detail: ${result.stderr.trim()}` : ''),
      counts: emptyCounts(),
      vulnerabilities: [],
    };
  }

  // npm v7+ returns the modern audit report shape.
  if (result.data.vulnerabilities || result.data.metadata) {
    return parseModernReport(result.data);
  }
  // npm v6 (legacy) shape.
  if (result.data.advisories) {
    return parseLegacyReport(result.data);
  }

  return {
    ok: true,
    counts: emptyCounts(),
    vulnerabilities: [],
  };
}

/**
 * Audits a Yarn/pnpm project by materializing a synthetic npm lockfile in a
 * temporary directory and running `npm audit --package-lock-only` there.
 */
function auditSynthesized(parsed, { production = false } = {}) {
  const { packageJson, packageLock } = toNpmLockfile(parsed);
  let tmpDir;
  try {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(packageJson, null, 2));
    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), JSON.stringify(packageLock, null, 2));
    return runNpmAudit(tmpDir, { production, packageLockOnly: true });
  } catch (err) {
    return {
      ok: false,
      error: `Could not analyze vulnerabilities from lockfile ${parsed.lockfileName || ''}: ${err.message}`.trim(),
      counts: emptyCounts(),
      vulnerabilities: [],
    };
  } finally {
    if (tmpDir) {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }
}

function parseModernReport(data) {
  const counts = emptyCounts();
  const vulnerabilities = [];

  const meta = data.metadata && data.metadata.vulnerabilities;
  if (meta) {
    for (const sev of SEVERITY_ORDER) {
      if (typeof meta[sev] === 'number') counts[sev] = meta[sev];
    }
    counts.total = meta.total || sumCounts(counts);
  }

  for (const [name, info] of Object.entries(data.vulnerabilities || {})) {
    const via = Array.isArray(info.via) ? info.via : [];
    const advisories = via.filter((v) => typeof v === 'object');
    const sources = advisories.length
      ? advisories.map((adv) => ({
          title: adv.title || 'Known vulnerability',
          url: adv.url || null,
          cwe: adv.cwe || [],
          cvss: adv.cvss ? adv.cvss.score : null,
          source: adv.source || null,
          range: adv.range || null,
        }))
      : [{ title: `Dependency vulnerable through ${via.join(', ')}`, url: null, cwe: [], cvss: null }];

    vulnerabilities.push({
      name,
      severity: info.severity || 'unknown',
      direct: Boolean(info.isDirect),
      range: info.range || null,
      fixAvailable: normalizeFix(info.fixAvailable),
      sources,
    });
  }

  if (!meta) {
    for (const v of vulnerabilities) {
      if (counts[v.severity] !== undefined) counts[v.severity]++;
    }
    counts.total = sumCounts(counts);
  }

  return { ok: true, counts, vulnerabilities: sortBySeverity(vulnerabilities) };
}

function parseLegacyReport(data) {
  const counts = emptyCounts();
  const vulnerabilities = [];

  for (const adv of Object.values(data.advisories)) {
    const severity = adv.severity || 'unknown';
    if (counts[severity] !== undefined) counts[severity]++;
    vulnerabilities.push({
      name: adv.module_name,
      severity,
      direct: false,
      range: adv.vulnerable_versions || null,
      fixAvailable: Boolean(adv.patched_versions && adv.patched_versions !== '<0.0.0'),
      sources: [{
        title: adv.title,
        url: adv.url || null,
        cwe: adv.cwe ? [adv.cwe] : [],
        cvss: adv.cvss_score || null,
      }],
    });
  }
  counts.total = sumCounts(counts);
  return { ok: true, counts, vulnerabilities: sortBySeverity(vulnerabilities) };
}

function normalizeFix(fixAvailable) {
  if (fixAvailable === true) return true;
  if (fixAvailable === false || fixAvailable === undefined) return false;
  if (typeof fixAvailable === 'object') {
    return {
      name: fixAvailable.name,
      version: fixAvailable.version,
      breaking: Boolean(fixAvailable.isSemVerMajor),
    };
  }
  return false;
}

function emptyCounts() {
  return { info: 0, low: 0, moderate: 0, high: 0, critical: 0, unknown: 0, malicious: 0, kev: 0, total: 0 };
}

function sumCounts(counts) {
  return SEVERITY_ORDER.reduce((acc, sev) => acc + (counts[sev] || 0), 0);
}

function sortBySeverity(list) {
  return list.sort(
    (a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) ||
      a.name.localeCompare(b.name)
  );
}

module.exports = { scanVulnerabilities, SEVERITY_ORDER };
