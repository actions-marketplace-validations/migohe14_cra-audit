'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { writeJson } = require('../utils/fs');
const { logger } = require('../utils/logger');
const { parseLockfile } = require('../core/lockfile-parser');
const { normalizeAllowlist, assessmentFor, STATUSES } = require('../core/vex');

const TOOL_VERSION = require('../../package.json').version;
const INFO_URI = 'https://github.com/migohe14/cra-audit';

/** GitHub code scanning ranks alerts by this 0-10 score. */
const SECURITY_SEVERITY = { critical: 9.5, high: 8.0, moderate: 5.5, low: 2.0, info: 0.5, unknown: 5.0 };

/**
 * Converts an audit report to SARIF 2.1.0, the format GitHub code scanning
 * ingests (`github/codeql-action/upload-sarif`). Each advisory on each
 * vulnerable component becomes one result, located on the component's entry
 * in the lockfile; license problems become results too.
 *
 * Advisories assessed as not_affected in the policy are kept as suppressed
 * `note` results carrying the justification, so the decision stays visible.
 *
 * @param {import('../core/auditor').AuditResult} report
 * @param {string} projectRoot
 * @param {object} [policy]
 */
function buildSarif(report, projectRoot, policy = {}) {
  const rules = new Map();
  const results = [];
  const vulns = report.sections.vulnerabilities;
  // An input SBOM is searched for purls; manifest findings carry their own location.
  const inputFile = vulns && vulns.input && vulns.input.format !== 'manifest' ? vulns.input.file : null;
  const lock = lockfileLocator(projectRoot, inputFile);
  const assessments = normalizeAllowlist(policy);

  if (vulns && vulns.ok) {
    for (const finding of vulns.vulnerabilities) {
      for (const source of finding.sources) {
        const ruleId = source.id || (source.url ? source.url.split('/').pop() : `${finding.name}-vulnerability`);
        if (!rules.has(ruleId)) rules.set(ruleId, vulnerabilityRule(ruleId, finding, source));
        const assessment = finding.malicious ? null : assessmentFor(finding, source, assessments);
        const accepted = Boolean(assessment && STATUSES[assessment.status].accepts);
        const result = {
          ruleId,
          level: accepted ? 'note'
            : finding.malicious || source.kev || ['critical', 'high'].includes(source.severity || finding.severity) ? 'error'
              : (source.severity || finding.severity) === 'moderate' ? 'warning' : 'note',
          message: { text: vulnerabilityMessage(finding, source) },
          locations: [finding.location ? lock.at(finding.location) : lock.locate(finding.name, finding.version, finding.purl)],
          partialFingerprints: { 'craAudit/v1': `${ruleId}:${finding.name}@${finding.version || ''}` },
        };
        if (accepted) {
          result.suppressions = [{
            kind: 'external',
            status: 'accepted',
            justification: [assessment.status, assessment.justification, assessment.detail].filter(Boolean).join(' — '),
          }];
        }
        results.push(result);
      }
    }
  }

  const licenses = report.sections.licenses;
  if (licenses && licenses.ok) {
    const s = licenses.summary;
    const groups = [
      ['cra-audit/license-denied', s.denied, 'error', (c) => `${c.name}@${c.version} is licensed under ${c.license}, which the policy denies.`],
      ['cra-audit/license-not-allowed', s.notAllowed, 'warning', (c) => `${c.name}@${c.version} is licensed under ${c.license}, which is not in the policy allowlist.`],
      ['cra-audit/license-missing', s.missing, 'warning', (c) => `${c.name}@${c.version} has no documented license (TR-03183-2 §5.2.2).`],
    ];
    for (const [ruleId, list, level, text] of groups) {
      // Manifests (requirements.txt, go.mod…) never declare licenses: that gap is
      // reported once by the audit, not as one alert per dependency.
      const relevant = ruleId === 'cra-audit/license-missing' ? list.filter((c) => !c.location) : list;
      if (!relevant.length) continue;
      rules.set(ruleId, licenseRule(ruleId));
      for (const c of relevant) {
        results.push({
          ruleId,
          level,
          message: { text: text(c) },
          locations: [c.location ? lock.at(c.location) : lock.locate(c.name, c.version, c.purl)],
          partialFingerprints: { 'craAudit/v1': `${ruleId}:${c.name}@${c.version}` },
        });
      }
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'cra-audit',
          version: TOOL_VERSION,
          semanticVersion: TOOL_VERSION,
          informationUri: INFO_URI,
          rules: [...rules.values()],
        },
      },
      originalUriBaseIds: { '%SRCROOT%': { uri: toFileUri(lock.repoRoot) } },
      results,
    }],
  };
}

function vulnerabilityRule(ruleId, finding, source) {
  const severity = source.severity || finding.severity;
  const score = finding.malicious ? 10 : source.cvss || SECURITY_SEVERITY[severity] || 5;
  const tags = ['security', 'vulnerability', 'supply-chain', 'cra'];
  if (finding.malicious) tags.push('malicious');
  if (source.kev) tags.push('actively-exploited');
  const cves = (source.aliases || []).filter((a) => /^CVE-/i.test(a));
  const title = finding.malicious ? `Malicious package: ${finding.name}` : source.title || ruleId;

  return {
    id: ruleId,
    name: ruleId.replace(/[^A-Za-z0-9]/g, ''),
    shortDescription: { text: title },
    fullDescription: { text: [title, cves.length ? `(${cves.join(', ')})` : ''].join(' ').trim() },
    helpUri: source.url || INFO_URI,
    help: {
      text: finding.malicious
        ? 'This release was published by an attacker. Remove it, reinstall from a clean lockfile, and rotate every credential available to machines that installed it.'
        : 'Update the dependency to a fixed version, or record in .cra-audit.json why it is not exploitable in your product (the assessment goes to the VEX document).',
    },
    properties: {
      tags,
      precision: 'very-high',
      'security-severity': String(Math.min(10, Number(score)).toFixed(1)),
    },
  };
}

function vulnerabilityMessage(finding, source) {
  const pkg = `${finding.name}${finding.version ? `@${finding.version}` : ''}`;
  if (finding.malicious) {
    return `[MALICIOUS] ${pkg} is a known compromised release (${source.id}). Remove it and rotate exposed credentials.`;
  }
  const parts = [];
  if (source.kev) parts.push(`[ACTIVELY EXPLOITED — CISA KEV since ${source.kev.dateAdded}; CRA Art. 14 reporting may apply]`);
  parts.push(`${pkg}: ${source.title || source.id}`);
  const cves = (source.aliases || []).filter((a) => /^CVE-/i.test(a));
  if (cves.length) parts.push(`(${cves.join(', ')})`);
  const fixed = source.fixed || (finding.fixAvailable && finding.fixAvailable.version);
  parts.push(fixed ? `Fixed in ${fixed}.` : 'No fixed version available.');
  if (!finding.direct) parts.push('Transitive dependency.');
  return parts.join(' ');
}

function licenseRule(ruleId) {
  const texts = {
    'cra-audit/license-denied': 'Dependency license denied by the policy',
    'cra-audit/license-not-allowed': 'Dependency license outside the policy allowlist',
    'cra-audit/license-missing': 'Dependency without a documented license',
  };
  return {
    id: ruleId,
    name: ruleId.replace(/[^A-Za-z0-9]/g, ''),
    shortDescription: { text: texts[ruleId] },
    helpUri: INFO_URI,
    properties: { tags: ['license', 'compliance', 'cra'], precision: 'high' },
  };
}

/**
 * Finds the line of `name@version` in the project lockfile (or of the purl in
 * an input SBOM) so each alert points at the exact entry. Falls back to line 1.
 */
function lockfileLocator(projectRoot, inputFile = null) {
  const repoRoot = findRepoRoot(projectRoot);
  let file;
  if (inputFile) {
    file = path.resolve(inputFile);
  } else {
    const parsed = parseLockfile(projectRoot);
    file = parsed.lockfileName ? path.join(projectRoot, parsed.lockfileName) : path.join(projectRoot, 'package.json');
  }
  let lines = [];
  try {
    lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  } catch {
    // Unreadable lockfile: every result points at line 1.
  }
  const uri = path.relative(repoRoot, file).split(path.sep).join('/');

  const locate = (name, version, purl) => {
    const line = inputFile ? findPurlLine(lines, purl) : findEntryLine(lines, name, version);
    return {
      physicalLocation: {
        artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
        region: { startLine: line },
      },
    };
  };
  // A known file + line (components read from manifests).
  const at = ({ file: rel, line }) => ({
    physicalLocation: {
      artifactLocation: { uri: path.relative(repoRoot, path.resolve(projectRoot, rel)).split(path.sep).join('/'), uriBaseId: '%SRCROOT%' },
      region: { startLine: line || 1 },
    },
  });
  return { repoRoot, locate, at };
}

function findEntryLine(lines, name, version) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  // npm: "node_modules/name": { | yarn: name@range: / "name@npm:range": | pnpm: name@version: / /name/version:
  const header = new RegExp(`(node_modules/${escaped}"\\s*:|^\\s*["']?/?${escaped}(@|/)[^\\s]*:?\\s*$|^\\s*["']?/?${escaped}@)`);
  for (let i = 0; i < lines.length; i++) {
    if (!header.test(lines[i])) continue;
    if (!version) return i + 1;
    // The entry's version is on the key itself (pnpm) or within the next lines.
    if (lines[i].includes(version)) return i + 1;
    for (let j = i + 1; j < Math.min(lines.length, i + 8); j++) {
      if (lines[j].includes(`"version": "${version}"`) || lines[j].includes(`version "${version}"`) ||
        new RegExp(`^\\s*version:\\s*["']?${version.replace(/\./g, '\\.')}["']?\\s*$`).test(lines[j])) {
        return i + 1;
      }
    }
  }
  return 1;
}

/** Line of an SBOM that holds the purl (qualifiers may follow it). */
function findPurlLine(lines, purl) {
  if (!purl) return 1;
  const escaped = purl.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const exact = new RegExp(`${escaped}(?![\\w.+-])`);
  const index = lines.findIndex((line) => exact.test(line));
  return index === -1 ? 1 : index + 1;
}

/** Nearest folder with a .git entry: SARIF paths must be repository-relative. */
function findRepoRoot(start) {
  let dir = path.resolve(start);
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return path.resolve(start);
    dir = parent;
  }
}

function toFileUri(dir) {
  const normalized = dir.split(path.sep).join('/');
  return `file://${normalized.startsWith('/') ? '' : '/'}${normalized}/`;
}

/**
 * Writes the SARIF report to disk. `quiet` keeps stdout clean when it
 * carries the JSON report.
 */
function reportSarif(report, projectRoot, outputPath, { quiet = false, policy } = {}) {
  const outPath = path.isAbsolute(outputPath) ? outputPath : path.join(process.cwd(), outputPath);
  writeJson(outPath, buildSarif(report, projectRoot, policy));
  if (!quiet) logger.success(`SARIF report written to: ${outPath}`);
}

module.exports = { buildSarif, reportSarif, findEntryLine };
