'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runJson } = require('../utils/exec');
const { exists } = require('../utils/fs');
const { parseLockfile, toNpmLockfile } = require('./lockfile-parser');

const SEVERITY_ORDER = ['info', 'low', 'moderate', 'high', 'critical'];

/**
 * Scans direct and transitive dependencies for known vulnerabilities using
 * `npm audit --json`. The CRA requires products to ship "without known
 * exploitable vulnerabilities", so this is the core gate of the audit.
 *
 * npm projects are audited in place. Yarn/pnpm projects (which have no npm
 * lockfile) are audited against a synthetic `package-lock.json` generated from
 * their lockfile, preserving the exact installed versions.
 *
 * @param {string} projectRoot
 * @param {{ production?: boolean }} [options]
 */
function scanVulnerabilities(projectRoot, { production = false } = {}) {
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
  return { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
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
