'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const { findProjectRoot } = require('../utils/fs');
const { logger, color } = require('../utils/logger');
const { parseLockfile } = require('../core/lockfile-parser');
const { scanVulnerabilities, SEVERITY_ORDER } = require('../core/vuln-scanner');
const { checkLicenses } = require('../core/license-checker');
const { enrichComponents } = require('../core/enrich');
const { loadPolicy } = require('../core/policy');
const { buildHtml } = require('../reporters/html');

/**
 * `cra-audit visualize` / `--visualize`
 *
 * Builds a single, self-contained HTML report that visualises the SBOM,
 * licenses, versions, known vulnerabilities and maintenance signals
 * (last publish/commit, maintainers, contributors, stars) per dependency.
 *
 * @param {object} flags
 * @returns {Promise<number>} exit code
 */
async function visualizeCommand(flags) {
  const projectRoot = findProjectRoot(flags.cwd || process.cwd());
  if (!projectRoot) {
    logger.error('No package.json found. Run the command inside an npm project.');
    return 1;
  }

  const parsed = parseLockfile(projectRoot);
  if (!parsed.ok) {
    logger.error(parsed.error);
    return 1;
  }

  let policy = {};
  try {
    policy = loadPolicy(projectRoot, flags.config).policy;
  } catch {
    policy = {};
  }

  logger.info(`Analyzing ${parsed.components.length} components from ${parsed.root.name}@${parsed.root.version}…`);

  // Vulnerabilities + licenses run locally (no network).
  const vulns = scanVulnerabilities(projectRoot, { production: policy.productionOnly });
  const licenses = checkLicenses(projectRoot, policy.licenses || {});

  // Maintenance enrichment over the network (opt-out with --offline).
  const network = !flags.offline;
  const github = Boolean(flags.github);
  if (network) {
    logger.info(
      `Fetching maintenance metadata (npm${github ? ' + GitHub' : ''})…` +
      (github && !process.env.GITHUB_TOKEN ? color.gray(' (no GITHUB_TOKEN: limited to 60 req/h)') : '')
    );
  } else {
    logger.info('Offline mode: maintenance metadata skipped.');
  }

  const enrichment = await enrichComponents(parsed.components, {
    network,
    github,
    onProgress: (done, total) => {
      logger.progress('npm metadata', done, total);
    },
  });

  const model = buildModel(parsed, vulns, licenses, enrichment);
  const html = buildHtml(model);

  const outPath = resolveOutputPath(projectRoot, flags.output);
  fs.writeFileSync(outPath, html, 'utf8');
  logger.success(`Visual report written to: ${outPath}`);

  if (!flags.noOpen) {
    openInBrowser(outPath);
    logger.detail('Opening in the browser…');
  } else {
    logger.detail(`Open it in your browser: file://${outPath.replace(/\\/g, '/')}`);
  }

  return 0;
}

/** Merges all data sources into the view model consumed by the HTML reporter. */
function buildModel(parsed, vulns, licenses, enrichment) {
  const vulnByName = new Map();
  if (vulns.ok) {
    for (const v of vulns.vulnerabilities) vulnByName.set(v.name, v);
  }
  const licByKey = new Map();
  if (licenses.ok) {
    for (const l of licenses.components) licByKey.set(`${l.name}@${l.version}`, l);
  }

  const components = parsed.components.map((c) => {
    const key = `${c.name}@${c.version}`;
    const vuln = vulnByName.get(c.name) || null;
    const lic = licByKey.get(key) || null;
    const enr = enrichment.get(key) || {};

    const license = (lic && lic.license) || c.license || enr.license || null;
    const licenseStatus = (lic && lic.license)
      ? lic.status
      : (license ? 'ok' : 'missing');

    return {
      name: c.name,
      version: c.version,
      license,
      licenseStatus,
      severity: vuln ? vuln.severity : 'none',
      fixAvailable: vuln ? Boolean(vuln.fixAvailable) : false,
      latest: enr.latest || null,
      outdated: Boolean(enr.outdated),
      lastPublish: enr.lastPublish || null,
      lastCommit: enr.lastCommit || null,
      maintainers: enr.maintainers == null ? null : enr.maintainers,
      contributors: enr.contributors == null ? null : enr.contributors,
      stars: enr.stars == null ? null : enr.stars,
      deprecated: Boolean(enr.deprecated),
      archived: Boolean(enr.archived),
      repoUrl: enr.repoUrl || null,
      maintenanceScore: enr.maintenanceScore == null ? null : enr.maintenanceScore,
      maintenanceLabel: enr.maintenanceLabel || 'unknown',
      hasHash: Boolean(c.hashValue),
      purl: c.purl || null,
    };
  });

  const summary = {
    total: components.length,
    vulnerable: components.filter((c) => c.severity !== 'none').length,
    critical: components.filter((c) => c.severity === 'critical').length,
    high: components.filter((c) => c.severity === 'high').length,
    licenseIssues: components.filter((c) => !c.license || c.licenseStatus === 'denied' || c.licenseStatus === 'not-allowed').length,
    outdated: components.filter((c) => c.outdated).length,
    atRisk: components.filter((c) => c.maintenanceLabel === 'at-risk').length,
  };

  return {
    project: parsed.root,
    generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    summary,
    components: components.sort(byRisk),
  };
}

function byRisk(a, b) {
  const r = (SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity));
  if (r !== 0) return r;
  return a.name.localeCompare(b.name);
}

function resolveOutputPath(projectRoot, output) {
  if (output) {
    return path.isAbsolute(output) ? output : path.join(projectRoot, output);
  }
  return path.join(projectRoot, 'cra-audit-report.html');
}

/** Opens a file with the OS default handler, best-effort. */
function openInBrowser(filePath) {
  try {
    let cmd;
    let args;
    if (process.platform === 'win32') {
      cmd = 'cmd';
      args = ['/c', 'start', '', filePath];
    } else if (process.platform === 'darwin') {
      cmd = 'open';
      args = [filePath];
    } else {
      cmd = 'xdg-open';
      args = [filePath];
    }
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    // Ignore: the path was already printed for manual opening.
  }
}

module.exports = { visualizeCommand };
