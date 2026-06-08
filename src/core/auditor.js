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
 * @returns {AuditResult}
 */
function runAudit(projectRoot, policy, policySource, options = {}) {
  const { only } = options;
  const sections = {};
  const reasons = [];

  // --- 1. Vulnerabilities -------------------------------------------------
  if (!only || only === 'vulnerabilities') {
    const vulns = scanVulnerabilities(projectRoot, { production: policy.productionOnly });
    sections.vulnerabilities = vulns;

    if (!vulns.ok) {
      reasons.push({ label: `No se pudieron analizar vulnerabilidades: ${vulns.error}`, passed: false });
    } else {
      const blocking = countBlocking(vulns, policy);
      reasons.push({
        label: blocking === 0
          ? `Sin vulnerabilidades de severidad >= ${policy.failOn}`
          : `${blocking} vulnerabilidad(es) de severidad >= ${policy.failOn}`,
        passed: blocking === 0,
      });
    }
  }

  // --- 2. SBOM ------------------------------------------------------------
  if (!only || only === 'sbom') {
    const sbom = generateSbom(projectRoot, { format: policy.sbomFormat });
    if (sbom.ok) {
      sbom.validation = validateSbom(sbom.document);
    }
    sections.sbom = sbom;

    if (policy.requireSbom) {
      if (!sbom.ok) {
        reasons.push({ label: `No se pudo generar el SBOM: ${sbom.error}`, passed: false });
      } else {
        reasons.push({
          label: sbom.validation.valid
            ? 'SBOM válido según los elementos mínimos de TR-03183'
            : 'SBOM incompleto respecto a TR-03183',
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
      reasons.push({ label: `No se pudieron analizar licencias: ${licenses.error}`, passed: false });
    } else {
      const s = licenses.summary;
      const missingFails = policy.licenses.failOnMissing && s.missing.length > 0;
      const licensesPassed = s.denied.length === 0 && s.notAllowed.length === 0 && !missingFails;
      reasons.push({
        label: licensesPassed
          ? 'Licencias documentadas y conformes con la política'
          : 'Problemas de licencias detectados (prohibidas, no permitidas o sin documentar)',
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

function countBlocking(vulns, policy) {
  const threshold = SEVERITY_ORDER.indexOf(policy.failOn);
  if (threshold === -1) return 0;
  const allowlist = new Set((policy.vulnerabilities && policy.vulnerabilities.allowlist) || []);

  let count = 0;
  for (const vuln of vulns.vulnerabilities) {
    if (SEVERITY_ORDER.indexOf(vuln.severity) < threshold) continue;
    const isAllowlisted = vuln.sources.some(
      (src) => src.url && [...allowlist].some((id) => src.url.includes(id))
    ) || allowlist.has(vuln.name);
    if (!isAllowlisted) count++;
  }
  return count;
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
