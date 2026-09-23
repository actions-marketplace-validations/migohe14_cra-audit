'use strict';

const { findProjectRoot } = require('../utils/fs');
const { logger, color } = require('../utils/logger');
const { checkReadiness, writeTemplates } = require('../core/readiness');

/**
 * `cra-audit readiness [--init]` — checks the organisational CRA duties that
 * live in the repository (disclosure policy, vulnerability contact, support
 * period, security.txt, SBOM). `--init` writes SECURITY.md and security.txt
 * templates first; existing files are never overwritten.
 *
 * @returns {number} exit code: 1 when a required check fails.
 */
function readinessCommand(flags) {
  const projectRoot = findProjectRoot(flags.cwd || process.cwd());
  if (!projectRoot) {
    logger.error('No package.json found. Run the command inside an npm project.');
    return 1;
  }

  if (flags.init) {
    for (const { file, created } of writeTemplates(projectRoot)) {
      if (created) logger.success(`Created ${file} — fill in the TODO placeholders.`);
      else logger.info(`${file} already exists; left untouched.`);
    }
  }

  const result = checkReadiness(projectRoot);

  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return result.passed ? 0 : 1;
  }

  logger.heading('CRA readiness · vulnerability handling and user information');
  for (const check of result.checks) {
    const mark = check.passed ? color.green('✔') : check.level === 'required' ? color.red('✖') : color.yellow('!');
    const level = check.level === 'required' ? '' : color.gray(' (recommended)');
    logger.log(`  ${mark} ${check.label}${level} ${color.gray(`— ${check.reference}`)}`);
    if (!check.passed || flags.verbose) logger.detail(`    ${check.detail}`);
  }
  logger.log('');

  const failed = result.checks.filter((c) => c.level === 'required' && !c.passed).length;
  const warned = result.checks.filter((c) => c.level === 'recommended' && !c.passed).length;
  if (result.passed) {
    logger.success(color.bold(`READY — all required checks pass${warned ? ` (${warned} recommendation(s))` : ''}.`));
  } else {
    logger.error(color.bold(`NOT READY — ${failed} required check(s) failed.`));
    if (!flags.init && !result.files.securityMd) {
      logger.detail(`Run ${color.cyan('cra-audit readiness --init')} to create SECURITY.md and security.txt templates.`);
    }
  }
  logger.detail('This checks what the repository documents; it is not legal advice.');
  return result.passed ? 0 : 1;
}

module.exports = { readinessCommand };
