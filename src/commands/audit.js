'use strict';

const { findProjectRoot } = require('../utils/fs');
const { logger } = require('../utils/logger');
const { loadPolicy } = require('../core/policy');
const { runAudit } = require('../core/auditor');
const { reportConsole } = require('../reporters/console');
const { reportJson } = require('../reporters/json');

/**
 * `cra-audit [audit]` — runs the full compliance audit (vulnerabilities + SBOM
 * + licenses) or a single section via `only`.
 *
 * @param {object} flags Parsed CLI flags.
 * @param {'vulnerabilities'|'sbom'|'licenses'} [only]
 * @returns {number} Process exit code.
 */
function auditCommand(flags, only) {
  const projectRoot = resolveRoot(flags);
  if (!projectRoot) return 1;

  let policyResult;
  try {
    policyResult = loadPolicy(projectRoot, flags.config);
  } catch (err) {
    logger.error(err.message);
    return 1;
  }

  const policy = applyFlagOverrides(policyResult.policy, flags);
  const report = runAudit(projectRoot, policy, policyResult.source, { only });

  if (flags.json) {
    reportJson(report, { outputPath: flags.output });
  } else {
    reportConsole(report);
  }

  return report.gate.passed ? 0 : 1;
}

function resolveRoot(flags) {
  const start = flags.cwd || process.cwd();
  const root = findProjectRoot(start);
  if (!root) {
    logger.error('No se encontró ningún package.json. Ejecuta el comando dentro de un proyecto npm.');
    return null;
  }
  return root;
}

/** CLI flags take precedence over the file-based policy. */
function applyFlagOverrides(policy, flags) {
  const merged = { ...policy };
  if (flags.failOn) merged.failOn = flags.failOn;
  if (flags.production) merged.productionOnly = true;
  if (flags.format) merged.sbomFormat = flags.format;
  if (flags.noSbom) merged.requireSbom = false;
  return merged;
}

module.exports = { auditCommand };
