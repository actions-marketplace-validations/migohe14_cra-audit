'use strict';

const { scanVulnerabilities, SEVERITY_ORDER } = require('./vuln-scanner');
const { generateSbom } = require('./sbom-generator');
const { validateSbom } = require('./sbom-validator');
const { checkLicenses } = require('./license-checker');

/**
 * @typedef {object} AuditResult
 * @property {object} project
 * @property {string|null} policySource
 * @property {object} sections
 * @property {{ passed: boolean, reasons: Array<{label:string, passed:boolean}> }} gate
 */

/**
 * Runs the full CRA audit: vulnerabilities + SBOM + licenses, then evaluates
 * the result against the configured security policy.
 *
 * @param {string} projectRoot
 * @param {object} policy
 * @param {string|null} policySource
 * @param {{ only?: 'vulnerabilities'|'sbom'|'licenses' }} [options]
 * @returns {Promise<AuditResult>}
 */
async function runAudit(projectRoot, policy, policySource, options = {}) {
  const { only } = options;
  const sections = {};
  const reasons = [];

  // --- 1. Vulnerabilities -------------------------------------------------
  if (!only || only === 'vulnerabilities') {
    const vulns = await scanVulnerabilities(projectRoot, {
      production: policy.productionOnly,
      source: policy.vulnerabilitySource,
    });
    sections.vulnerabilities = vulns;

    if (!vulns.ok) {
      reasons.push({ label: `Vulnerabilities could not be analyzed: ${vulns.error}`, passed: false });
    } else {
      for (const warning of vulns.warnings || []) {
        reasons.push({ label: warning, passed: true, warning: true });
      }
      reasons.push(...exploitationReasons(vulns, policy));
      const blocking = countBlocking(vulns, policy);
      reasons.push({
        label: blocking === 0
          ? `No vulnerabilities of severity >= ${policy.failOn}`
          : `${blocking} vulnerability(ies) of severity >= ${policy.failOn}`,
        passed: blocking === 0,
      });
    }
  }

  // --- 2. SBOM ------------------------------------------------------------
  if (!only || only === 'sbom') {
    const sbom = generateSbom(projectRoot, { format: policy.sbomFormat, creator: policy.sbomCreator });
    if (sbom.ok) {
      sbom.validation = validateSbom(sbom.document);
    }
    sections.sbom = sbom;

    if (policy.requireSbom) {
      if (!sbom.ok) {
        reasons.push({ label: `The SBOM could not be generated: ${sbom.error}`, passed: false });
      } else {
        reasons.push({
          label: sbom.validation.valid
            ? 'SBOM valid against the TR-03183-2 required data fields'
            : 'SBOM incomplete with respect to TR-03183',
          passed: sbom.validation.valid,
        });
      }
    }
  }

  // --- 3. Licenses --------------------------------------------------------
  if (!only || only === 'licenses') {
    const licenses = checkLicenses(projectRoot, policy.licenses);
    sections.licenses = licenses;

    if (!licenses.ok) {
      reasons.push({ label: `Licenses could not be analyzed: ${licenses.error}`, passed: false });
    } else {
      const s = licenses.summary;
      const missingFails = policy.licenses.failOnMissing && s.missing.length > 0;
      const licensesPassed = s.denied.length === 0 && s.notAllowed.length === 0 && !missingFails;
      reasons.push({
        label: licensesPassed
          ? 'Licenses documented and compliant with the policy'
          : 'License issues detected (denied, not allowed or undocumented)',
        passed: licensesPassed,
      });
    }
  }

  return {
    project: getProject(projectRoot, sections),
    policySource,
    generatedAt: new Date().toISOString(),
    sections,
    gate: { passed: reasons.every((r) => r.passed), reasons },
  };
}

/**
 * Gate reasons for the OSV source: malicious packages always block (they are
 * compromised releases, not bugs, so the allowlist cannot accept them), and
 * actively exploited vulnerabilities (CISA KEV) block unless `failOnKev` is off.
 */
function exploitationReasons(vulns, policy) {
  if (vulns.source !== 'osv') return [];
  const reasons = [];

  const malicious = vulns.vulnerabilities.filter((v) => v.malicious);
  reasons.push({
    label: malicious.length === 0
      ? 'No malicious packages (OpenSSF malicious-packages via OSV.dev)'
      : `${malicious.length} malicious package(s): ${malicious.map((v) => `${v.name}@${v.version}`).join(', ')}`,
    passed: malicious.length === 0,
  });

  if (!vulns.kev || !vulns.kev.checked) {
    reasons.push({
      label: `Actively exploited vulnerabilities not checked: ${(vulns.kev && vulns.kev.error) || 'CISA KEV unavailable'}`,
      passed: true,
      warning: true,
    });
    return reasons;
  }

  const exploited = vulns.vulnerabilities.filter((v) => v.kev && !isAllowlisted(v, policy));
  reasons.push({
    label: exploited.length === 0
      ? 'No actively exploited vulnerabilities (CISA KEV)'
      : `${exploited.length} component(s) with actively exploited vulnerabilities (CISA KEV) — CRA Art. 14 reporting may apply`,
    passed: exploited.length === 0 || policy.failOnKev === false,
    warning: exploited.length > 0 && policy.failOnKev === false,
  });
  return reasons;
}

function countBlocking(vulns, policy) {
  const threshold = SEVERITY_ORDER.indexOf(policy.failOn);
  if (threshold === -1) return 0;

  let count = 0;
  for (const vuln of vulns.vulnerabilities) {
    if (SEVERITY_ORDER.indexOf(vuln.severity) < threshold) continue;
    if (!vuln.malicious && isAllowlisted(vuln, policy)) continue;
    count++;
  }
  return count;
}

/**
 * A finding is accepted when the policy allowlist names the package, or every
 * advisory on it by id/alias (GHSA, CVE) or advisory URL.
 */
function isAllowlisted(vuln, policy) {
  const allowlist = (policy.vulnerabilities && policy.vulnerabilities.allowlist) || [];
  if (!allowlist.length) return false;
  if (allowlist.includes(vuln.name)) return true;
  return vuln.sources.every((src) => allowlist.some((id) =>
    [src.id, ...(src.aliases || [])].includes(id) || (src.url && src.url.includes(id))));
}

function getProject(projectRoot, sections) {
  // Derive project identity from any section that parsed the lockfile/root.
  if (sections.sbom && sections.sbom.ok && sections.sbom.document) {
    const comp = sections.sbom.document.metadata && sections.sbom.document.metadata.component;
    if (comp) return { name: comp.name, version: comp.version };
  }
  const path = require('node:path');
  const { readJson } = require('../utils/fs');
  const pkg = readJson(path.join(projectRoot, 'package.json')) || {};
  return { name: pkg.name || path.basename(projectRoot), version: pkg.version || '0.0.0' };
}

module.exports = { runAudit };
