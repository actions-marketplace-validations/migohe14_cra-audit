'use strict';

const path = require('node:path');
const { findProjectRoot, readJson, writeJson } = require('../utils/fs');
const { logger } = require('../utils/logger');
const { loadPolicy } = require('../core/policy');
const { scanVulnerabilities } = require('../core/vuln-scanner');
const { buildVex } = require('../core/vex');
const { creatorFromManifest } = require('../core/installed-metadata');
const { readSbom } = require('../core/sbom-reader');
const { inputPath } = require('./audit');

/**
 * `cra-audit vex` — writes a VEX document (CycloneDX 1.6 or OpenVEX 0.2.0)
 * stating the exploitability of every known vulnerability in the dependency
 * tree, from the assessments recorded in the policy allowlist.
 *
 * @returns {Promise<number>} exit code
 */
async function vexCommand(flags) {
  const input = inputPath(flags);
  const start = flags.cwd || process.cwd();
  const projectRoot = input ? path.resolve(start) : findProjectRoot(start);
  if (!projectRoot) {
    logger.error('No package.json found. Run the command inside an npm project.');
    return 1;
  }

  let policy;
  try {
    policy = loadPolicy(projectRoot, flags.config).policy;
  } catch (err) {
    logger.error(err.message);
    return 1;
  }

  const format = flags.format === 'openvex' ? 'openvex' : 'cyclonedx';
  if (flags.format && !['openvex', 'cyclonedx', 'cdx'].includes(flags.format)) {
    logger.error(`Unsupported VEX format: "${flags.format}". Use "cyclonedx" or "openvex".`);
    return 1;
  }

  const parsed = input ? readSbom(input) : null;
  if (parsed && !parsed.ok) {
    logger.error(parsed.error);
    return 1;
  }
  const vulns = await scanVulnerabilities(projectRoot, {
    production: flags.production || policy.productionOnly,
    source: flags.vulnSource || policy.vulnerabilitySource,
    parsed,
  });
  if (!vulns.ok) {
    logger.error(vulns.error);
    return 1;
  }
  // Without -o the document goes to stdout: keep warnings on stderr.
  for (const warning of vulns.warnings || []) {
    if (flags.output) logger.warn(warning);
    else process.stderr.write(`${warning}\n`);
  }

  const pkg = readJson(path.join(projectRoot, 'package.json')) || {};
  const creator = creatorFromManifest(pkg);
  const author = policy.sbomCreator || (creator && (creator.email || creator.url)) || null;
  const product = parsed
    ? { name: parsed.root.name, version: parsed.root.version, purl: parsed.root.purl }
    : { name: pkg.name || path.basename(projectRoot), version: pkg.version || '0.0.0' };
  const document = buildVex(product, vulns, policy, { format, author });

  const count = format === 'openvex' ? document.statements.length : document.vulnerabilities.length;
  if (flags.output) {
    const outPath = path.isAbsolute(flags.output) ? flags.output : path.join(projectRoot, flags.output);
    writeJson(outPath, document);
    logger.success(`VEX (${format}) with ${count} statement(s) written to: ${outPath}`);
  } else {
    process.stdout.write(JSON.stringify(document, null, 2) + '\n');
  }
  return 0;
}

module.exports = { vexCommand };
