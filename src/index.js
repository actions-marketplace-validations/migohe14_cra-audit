'use strict';

/**
 * Programmatic API for cra-audit.
 *
 * Example:
 *   const { runAudit, loadPolicy } = require('cra-audit');
 *   const { policy, source } = loadPolicy(process.cwd());
 *   const report = await runAudit(process.cwd(), policy, source);
 */

const { runAudit } = require('./core/auditor');
const { loadPolicy, DEFAULT_POLICY } = require('./core/policy');
const { generateSbom } = require('./core/sbom-generator');
const { validateSbom } = require('./core/sbom-validator');
const { scanVulnerabilities } = require('./core/vuln-scanner');
const { checkLicenses } = require('./core/license-checker');
const { parseLockfile } = require('./core/lockfile-parser');
const { enrichComponents } = require('./core/enrich');
const { buildHtml } = require('./reporters/html');
const { buildSarif } = require('./reporters/sarif');
const { buildVex } = require('./core/vex');
const { checkReadiness } = require('./core/readiness');

module.exports = {
  runAudit,
  loadPolicy,
  DEFAULT_POLICY,
  generateSbom,
  validateSbom,
  scanVulnerabilities,
  checkLicenses,
  parseLockfile,
  enrichComponents,
  buildHtml,
  buildSarif,
  buildVex,
  checkReadiness,
};
