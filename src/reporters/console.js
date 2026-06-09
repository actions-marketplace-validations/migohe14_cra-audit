'use strict';

const { logger, color } = require('../utils/logger');

const SEVERITY_COLORS = {
  critical: color.red,
  high: color.red,
  moderate: color.yellow,
  low: color.yellow,
  info: color.gray,
  unknown: color.gray,
};

/**
 * Renders a full audit report to the terminal.
 * @param {import('../core/auditor').AuditResult} report
 */
function reportConsole(report) {
  logger.heading('  CRA Audit — Cyber Resilience Act (EU 2024/2847) · BSI TR-03183');
  logger.detail(`Project: ${report.project.name}@${report.project.version}`);
  if (report.policySource) {
    logger.detail(`Policy: ${report.policySource}`);
  }

  if (report.sections.vulnerabilities) renderVulnerabilities(report.sections.vulnerabilities);
  if (report.sections.sbom) renderSbom(report.sections.sbom);
  if (report.sections.licenses) renderLicenses(report.sections.licenses);

  renderSummary(report);
}

function renderVulnerabilities(section) {
  logger.heading('1) Known vulnerabilities (CRA Art. 13)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }

  const c = section.counts;
  if (c.total === 0) {
    logger.success('No known vulnerabilities. Meets the "zero exploitable vulnerabilities" requirement.');
    return;
  }

  logger.log(
    `  ${color.red(`${c.critical} critical`)} · ${color.red(`${c.high} high`)} · ` +
    `${color.yellow(`${c.moderate} moderate`)} · ${color.yellow(`${c.low} low`)} · ${color.gray(`${c.info} info`)}`
  );

  const top = section.vulnerabilities.slice(0, 15);
  for (const vuln of top) {
    const sev = (SEVERITY_COLORS[vuln.severity] || color.gray)(vuln.severity.toUpperCase().padEnd(8));
    const fix = describeFix(vuln.fixAvailable);
    logger.log(`  ${sev} ${color.bold(vuln.name)} ${color.gray(vuln.range || '')} ${fix}`);
    const adv = vuln.sources[0];
    if (adv && adv.title) logger.detail(`${adv.title}${adv.url ? ' — ' + adv.url : ''}`);
  }
  if (section.vulnerabilities.length > top.length) {
    logger.detail(`… and ${section.vulnerabilities.length - top.length} more.`);
  }
}

function describeFix(fix) {
  if (fix === true) return color.green('(fix available)');
  if (fix && typeof fix === 'object') {
    return color.green(`(fix: ${fix.name}@${fix.version}${fix.breaking ? ', breaking' : ''})`);
  }
  return color.gray('(no fix)');
}

function renderSbom(section) {
  logger.heading('2) Software Bill of Materials · SBOM (CRA Annex I)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }
  logger.detail(`Format: ${section.format} · Components: ${section.componentCount}`);

  if (section.validation) {
    const v = section.validation;
    for (const check of v.checks) {
      const mark = check.passed ? color.green('✔') : color.red('✖');
      logger.log(`  ${mark} ${check.label}`);
    }
    if (v.valid) {
      logger.success('The SBOM meets the TR-03183 §6 minimum elements.');
    } else {
      logger.warn(`The SBOM does not meet ${v.failedChecks.length} minimum requirement(s).`);
    }
  }
  if (section.outputPath) {
    logger.detail(`SBOM written to: ${section.outputPath}`);
  }
}

function renderLicenses(section) {
  logger.heading('3) Third-party component licenses (TR-03183 §6)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }
  const s = section.summary;
  logger.detail(`Documented: ${s.documented}/${s.total}`);

  if (s.missing.length) {
    logger.warn(`${s.missing.length} component(s) without a documented license:`);
    for (const c of s.missing.slice(0, 10)) logger.log(`    ${color.gray('•')} ${c.name}@${c.version}`);
  }
  if (s.denied.length) {
    logger.error(`${s.denied.length} component(s) with a license denied by the policy:`);
    for (const c of s.denied) logger.log(`    ${color.red('•')} ${c.name}@${c.version} (${c.license})`);
  }
  if (s.notAllowed.length) {
    logger.warn(`${s.notAllowed.length} component(s) with a license outside the allowlist:`);
    for (const c of s.notAllowed.slice(0, 10)) logger.log(`    ${color.yellow('•')} ${c.name}@${c.version} (${c.license})`);
  }
  if (!s.missing.length && !s.denied.length && !s.notAllowed.length) {
    logger.success('All licenses are documented and allowed.');
  }
}

function renderSummary(report) {
  logger.heading('Result');
  for (const item of report.gate.reasons) {
    const mark = item.passed ? color.green('✔') : color.red('✖');
    logger.log(`  ${mark} ${item.label}`);
  }
  logger.log('');
  if (report.gate.passed) {
    logger.success(color.bold('AUDIT PASSED — the project meets the configured CRA policy.'));
  } else {
    logger.error(color.bold('AUDIT FAILED — CRA compliance issues were detected.'));
  }
  logger.log('');
}

module.exports = { reportConsole };
