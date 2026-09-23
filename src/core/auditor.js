'use strict';

const { scanVulnerabilities, SEVERITY_ORDER } = require('./vuln-scanner');
const { generateSbom } = require('./sbom-generator');
const { validateSbom } = require('./sbom-validator');
const { checkLicenses } = require('./license-checker');
const { acceptance } = require('./vex');
const { readSbom } = require('./sbom-reader');

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
 * With `input` (path to a CycloneDX/SPDX JSON SBOM) the audit runs on that
 * SBOM instead of the npm lockfile, so it covers any ecosystem.
 *
 * @param {{ only?: 'vulnerabilities'|'sbom'|'licenses', input?: string }} [options]
 * @returns {Promise<AuditResult>}
 */
async function runAudit(projectRoot, policy, policySource, options = {}) {
  const { only, input } = options;
  const sections = {};
  const reasons = [];
  const parsed = input ? readSbom(input) : null;

  // --- 1. Vulnerabilities -------------------------------------------------
  if (!only || only === 'vulnerabilities') {
    const vulns = await scanVulnerabilities(projectRoot, {
      production: policy.productionOnly,
      source: policy.vulnerabilitySource,
      parsed,
    });
    sections.vulnerabilities = vulns;

    if (!vulns.ok) {
      reasons.push({ label: `Vulnerabilities could not be analyzed: ${vulns.error}`, passed: false });
    } else {
      for (const warning of vulns.warnings || []) {
        reasons.push({ label: warning, passed: true, warning: true });
      }
      reasons.push(...exploitationReasons(vulns, policy));
      reasons.push(...justificationReasons(vulns, policy));
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
  if ((!only || only === 'sbom') && parsed) {
    // An input SBOM comes from third-party tooling that rarely carries the
    // manufacturer fields TR-03183 requires: report gaps without blocking.
    const sbom = parsed.ok
      ? { ok: true, input: parsed.sourceFile, format: parsed.format, componentCount: parsed.components.length, validation: validateSbom(parsed.document) }
      : { ok: false, input: parsed.sourceFile, error: parsed.error };
    sections.sbom = sbom;
    if (!sbom.ok) {
      reasons.push({ label: `The input SBOM could not be read: ${sbom.error}`, passed: false });
    } else if (policy.requireSbom) {
      reasons.push({
        label: sbom.validation.valid
          ? 'Input SBOM valid against the TR-03183-2 required data fields'
          : `Input SBOM misses ${sbom.validation.failedChecks.length} TR-03183-2 requirement(s) (see \`cra-audit sbom check -i\`)`,
        passed: true,
        warning: !sbom.validation.valid,
      });
    }
  } else if (!only || only === 'sbom') {
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
    const licenses = checkLicenses(projectRoot, policy.licenses, { parsed });
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
    project: parsed && parsed.ok
      ? { name: parsed.root.name, version: parsed.root.version, sbom: parsed.sourceFile }
      : getProject(projectRoot, sections),
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
 * A finding is accepted when every advisory on it is assessed as not_affected
 * (or false_positive) in the policy allowlist. See ./vex.js.
 */
function isAllowlisted(vuln, policy) {
  return acceptance(vuln, policy).accepted;
}

/**
 * Accepted vulnerabilities must be documented (CRA Annex I Part II): warn
 * when an allowlist entry carries no justification or detail for the VEX.
 */
function justificationReasons(vulns, policy) {
  const unjustified = vulns.vulnerabilities.reduce((n, v) => n + acceptance(v, policy).unjustified, 0);
  if (!unjustified) return [];
  return [{
    label: `${unjustified} accepted vulnerability(ies) without a justification — add "justification"/"detail" to the allowlist entry for the VEX`,
    passed: true,
    warning: true,
  }];
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
