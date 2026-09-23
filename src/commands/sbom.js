'use strict';

const path = require('node:path');
const { readJson, writeJson, exists } = require('../utils/fs');
const { logger, color } = require('../utils/logger');
const { generateSbom } = require('../core/sbom-generator');
const { validateSbom } = require('../core/sbom-validator');
const { loadPolicy } = require('../core/policy');
const { hasManifests } = require('../core/manifest-reader');
const { findAnyProjectRoot } = require('../core/project-source');

/**
 * `cra-audit sbom <generate|check>` and the `--sbom` shortcut.
 *
 * - generate: builds a CycloneDX/SPDX SBOM and prints it or writes it to disk.
 * - check:    generates (or reads) an SBOM and validates the data fields
 *             required by BSI TR-03183-2 v2.1.0 §5.2.
 */
function sbomCommand(subcommand, flags) {
  const start = flags.cwd || process.cwd();
  // The nearest project decides: a Python/Go/Java folder inside an npm repo is not npm.
  const nearest = findAnyProjectRoot(start);
  const npmProject = nearest && exists(path.join(nearest, 'package.json'));
  const projectRoot = npmProject ? nearest : (flags.input ? path.resolve(start) : null);
  if (!projectRoot) {
    const other = nearest && hasManifests(nearest);
    logger.error(other
      ? 'cra-audit generates TR-03183 SBOMs for npm/Yarn/pnpm projects. For this ecosystem, generate the SBOM with ' +
        'your build tooling (Syft, cdxgen, cyclonedx-maven-plugin, cyclonedx-py…) and check it with `cra-audit sbom check -i <file>`; ' +
        '`cra-audit` audits this project directly.'
      : 'No package.json found. Run the command inside an npm project, or pass an SBOM with `sbom check -i <file>`.');
    return 1;
  }

  const action = subcommand || 'generate';
  const format = flags.format || 'cyclonedx';

  if (action === 'check') {
    return sbomCheck(projectRoot, format, flags);
  }
  if (action === 'generate') {
    return sbomGenerate(projectRoot, format, flags);
  }

  logger.error(`Unknown SBOM subcommand: "${action}". Use "generate" or "check".`);
  return 1;
}

function sbomGenerate(projectRoot, format, flags) {
  const result = generateSbom(projectRoot, { format, creator: sbomCreator(projectRoot, flags) });
  if (!result.ok) {
    logger.error(result.error);
    return 1;
  }

  if (flags.output) {
    const outPath = path.isAbsolute(flags.output) ? flags.output : path.join(projectRoot, flags.output);
    writeJson(outPath, result.document);
    logger.success(`SBOM (${result.format}) with ${result.componentCount} components written to: ${outPath}`);
  } else {
    process.stdout.write(JSON.stringify(result.document, null, 2) + '\n');
  }
  return 0;
}

function sbomCheck(projectRoot, format, flags) {
  let document;

  // If an SBOM file is provided, validate it directly; otherwise generate one.
  if (flags.input) {
    const inPath = path.isAbsolute(flags.input) ? flags.input : path.join(projectRoot, flags.input);
    if (!exists(inPath)) {
      logger.error(`The specified SBOM was not found: ${flags.input}`);
      return 1;
    }
    document = readJson(inPath);
  } else {
    const result = generateSbom(projectRoot, { format, creator: sbomCreator(projectRoot, flags) });
    if (!result.ok) {
      logger.error(result.error);
      return 1;
    }
    document = result.document;
  }

  const validation = validateSbom(document);
  if (!validation.ok) {
    logger.error(validation.error);
    return 1;
  }

  if (flags.json) {
    process.stdout.write(JSON.stringify(validation, null, 2) + '\n');
    return validation.valid ? 0 : 1;
  }

  logger.heading('SBOM validation · BSI TR-03183-2 v2.1.0 (required data fields)');
  logger.detail(`Detected format: ${validation.format} · Components: ${validation.stats.total}`);
  for (const check of validation.checks) {
    const mark = check.passed ? color.green('✔') : color.red('✖');
    logger.log(`  ${mark} ${check.label}`);
  }
  logger.log('');
  if (validation.valid) {
    logger.success(color.bold('SBOM VALID — meets the TR-03183-2 data fields required by the CRA.'));
    return 0;
  }
  logger.error(color.bold(`SBOM INVALID — ${validation.failedChecks.length} requirement(s) not met.`));
  return 1;
}

/** SBOM creator from --creator, else from the project policy (`sbomCreator`). */
function sbomCreator(projectRoot, flags) {
  if (typeof flags.creator === 'string') return flags.creator;
  try {
    return loadPolicy(projectRoot, flags.config).policy.sbomCreator;
  } catch {
    return undefined; // A broken policy file must not block SBOM generation.
  }
}

module.exports = { sbomCommand };
