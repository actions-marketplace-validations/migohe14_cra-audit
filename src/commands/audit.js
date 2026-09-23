'use strict';

const path = require('node:path');
const { findAnyProjectRoot } = require('../core/project-source');
const { logger } = require('../utils/logger');
const { loadPolicy } = require('../core/policy');
const { runAudit } = require('../core/auditor');
const { reportConsole } = require('../reporters/console');
const { reportJson } = require('../reporters/json');
const { reportSarif } = require('../reporters/sarif');

/**
 * `cra-audit [audit]` — runs the full compliance audit (vulnerabilities + SBOM
 * + licenses) or a single section via `only`.
 *
 * @param {object} flags Parsed CLI flags.
 * @param {'vulnerabilities'|'sbom'|'licenses'} [only]
 * @returns {Promise<number>} Process exit code.
 */
async function auditCommand(flags, only) {
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
  const report = await runAudit(projectRoot, policy, policyResult.source, { only, input: inputPath(flags) });

  if (flags.json) {
    reportJson(report, { outputPath: flags.output });
  } else {
    reportConsole(report);
  }
  if (typeof flags.sarif === 'string') {
    reportSarif(report, projectRoot, flags.sarif, { quiet: flags.json && !flags.output, policy });
  }

  return report.gate.passed ? 0 : 1;
}

/**
 * Project root: with `-i <sbom>` the working directory; otherwise the nearest
 * folder with a package.json or a supported manifest (requirements.txt,
 * poetry.lock, uv.lock, Pipfile.lock, go.mod, pom.xml, gradle.lockfile).
 */
function resolveRoot(flags) {
  const start = flags.cwd || process.cwd();
  if (inputPath(flags)) return path.resolve(start);
  const root = findAnyProjectRoot(start);
  if (!root) {
    logger.error(NO_PROJECT);
    return null;
  }
  return root;
}

const NO_PROJECT = 'No project found: expected a package.json (npm/Yarn/pnpm), requirements.txt, ' +
  'poetry.lock, uv.lock, Pipfile.lock, go.mod, pom.xml or gradle.lockfile — or pass an SBOM with -i.';

/** `-i/--input <sbom>` resolved against the working directory. */
function inputPath(flags) {
  if (typeof flags.input !== 'string') return null;
  return path.resolve(flags.cwd || process.cwd(), flags.input);
}

/** CLI flags take precedence over the file-based policy. */
function applyFlagOverrides(policy, flags) {
  const merged = { ...policy };
  if (flags.failOn) merged.failOn = flags.failOn;
  if (flags.production) merged.productionOnly = true;
  if (flags.format) merged.sbomFormat = flags.format;
  if (flags.noSbom) merged.requireSbom = false;
  if (flags.vulnSource) merged.vulnerabilitySource = flags.vulnSource;
  if (flags.failOnKev) merged.failOnKev = true;
  if (flags.noFailOnKev) merged.failOnKev = false;
  if (typeof flags.country === 'string') merged.country = flags.country.toUpperCase();
  return merged;
}

module.exports = { auditCommand, inputPath, resolveRoot };
