'use strict';

const path = require('node:path');
const { findProjectRoot, readJson, writeJson, exists } = require('../utils/fs');
const { logger, color } = require('../utils/logger');
const { generateSbom } = require('../core/sbom-generator');
const { validateSbom } = require('../core/sbom-validator');

/**
 * `cra-audit sbom <generate|check>` and the `--sbom` shortcut.
 *
 * - generate: builds a CycloneDX/SPDX SBOM and prints it or writes it to disk.
 * - check:    generates (or reads) an SBOM and validates the minimum elements
 *             required by BSI TR-03183 §6.
 */
function sbomCommand(subcommand, flags) {
  const projectRoot = findProjectRoot(flags.cwd || process.cwd());
  if (!projectRoot) {
    logger.error('No se encontró ningún package.json. Ejecuta el comando dentro de un proyecto npm.');
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

  logger.error(`Subcomando de SBOM desconocido: "${action}". Usa "generate" o "check".`);
  return 1;
}

function sbomGenerate(projectRoot, format, flags) {
  const result = generateSbom(projectRoot, { format });
  if (!result.ok) {
    logger.error(result.error);
    return 1;
  }

  if (flags.output) {
    const outPath = path.isAbsolute(flags.output) ? flags.output : path.join(projectRoot, flags.output);
    writeJson(outPath, result.document);
    logger.success(`SBOM (${result.format}) con ${result.componentCount} componentes escrito en: ${outPath}`);
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
      logger.error(`No se encontró el SBOM indicado: ${flags.input}`);
      return 1;
    }
    document = readJson(inPath);
  } else {
    const result = generateSbom(projectRoot, { format });
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

  logger.heading('Validación de SBOM · BSI TR-03183 §6 (elementos mínimos)');
  logger.detail(`Formato detectado: ${validation.format} · Componentes: ${validation.stats.total}`);
  for (const check of validation.checks) {
    const mark = check.passed ? color.green('✔') : color.red('✖');
    logger.log(`  ${mark} ${check.label}`);
  }
  logger.log('');
  if (validation.valid) {
    logger.success(color.bold('SBOM VÁLIDO — cumple los elementos mínimos exigidos por el CRA.'));
    return 0;
  }
  logger.error(color.bold(`SBOM INVÁLIDO — ${validation.failedChecks.length} requisito(s) sin cumplir.`));
  return 1;
}

module.exports = { sbomCommand };
