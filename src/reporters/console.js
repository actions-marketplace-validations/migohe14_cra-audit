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
  logger.heading('  CRA Audit — Cyber Resilience Act (UE 2024/2847) · BSI TR-03183');
  logger.detail(`Proyecto: ${report.project.name}@${report.project.version}`);
  if (report.policySource) {
    logger.detail(`Política: ${report.policySource}`);
  }

  if (report.sections.vulnerabilities) renderVulnerabilities(report.sections.vulnerabilities);
  if (report.sections.sbom) renderSbom(report.sections.sbom);
  if (report.sections.licenses) renderLicenses(report.sections.licenses);

  renderSummary(report);
}

function renderVulnerabilities(section) {
  logger.heading('1) Vulnerabilidades conocidas (Art. 13 CRA)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }

  const c = section.counts;
  if (c.total === 0) {
    logger.success('Sin vulnerabilidades conocidas. Cumple el requisito de "cero vulnerabilidades explotables".');
    return;
  }

  logger.log(
    `  ${color.red(`${c.critical} críticas`)} · ${color.red(`${c.high} altas`)} · ` +
    `${color.yellow(`${c.moderate} moderadas`)} · ${color.yellow(`${c.low} bajas`)} · ${color.gray(`${c.info} info`)}`
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
    logger.detail(`… y ${section.vulnerabilities.length - top.length} más.`);
  }
}

function describeFix(fix) {
  if (fix === true) return color.green('(fix disponible)');
  if (fix && typeof fix === 'object') {
    return color.green(`(fix: ${fix.name}@${fix.version}${fix.breaking ? ', breaking' : ''})`);
  }
  return color.gray('(sin fix)');
}

function renderSbom(section) {
  logger.heading('2) Lista de Materiales de Software · SBOM (Anexo I CRA)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }
  logger.detail(`Formato: ${section.format} · Componentes: ${section.componentCount}`);

  if (section.validation) {
    const v = section.validation;
    for (const check of v.checks) {
      const mark = check.passed ? color.green('✔') : color.red('✖');
      logger.log(`  ${mark} ${check.label}`);
    }
    if (v.valid) {
      logger.success('El SBOM cumple los elementos mínimos de TR-03183 §6.');
    } else {
      logger.warn(`El SBOM no cumple ${v.failedChecks.length} requisito(s) mínimo(s).`);
    }
  }
  if (section.outputPath) {
    logger.detail(`SBOM escrito en: ${section.outputPath}`);
  }
}

function renderLicenses(section) {
  logger.heading('3) Licencias de componentes de terceros (TR-03183 §6)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }
  const s = section.summary;
  logger.detail(`Documentadas: ${s.documented}/${s.total}`);

  if (s.missing.length) {
    logger.warn(`${s.missing.length} componente(s) sin licencia documentada:`);
    for (const c of s.missing.slice(0, 10)) logger.log(`    ${color.gray('•')} ${c.name}@${c.version}`);
  }
  if (s.denied.length) {
    logger.error(`${s.denied.length} componente(s) con licencia prohibida por la política:`);
    for (const c of s.denied) logger.log(`    ${color.red('•')} ${c.name}@${c.version} (${c.license})`);
  }
  if (s.notAllowed.length) {
    logger.warn(`${s.notAllowed.length} componente(s) con licencia fuera de la allowlist:`);
    for (const c of s.notAllowed.slice(0, 10)) logger.log(`    ${color.yellow('•')} ${c.name}@${c.version} (${c.license})`);
  }
  if (!s.missing.length && !s.denied.length && !s.notAllowed.length) {
    logger.success('Todas las licencias están documentadas y permitidas.');
  }
}

function renderSummary(report) {
  logger.heading('Resultado');
  for (const item of report.gate.reasons) {
    const mark = item.passed ? color.green('✔') : color.red('✖');
    logger.log(`  ${mark} ${item.label}`);
  }
  logger.log('');
  if (report.gate.passed) {
    logger.success(color.bold('AUDITORÍA SUPERADA — el proyecto cumple la política CRA configurada.'));
  } else {
    logger.error(color.bold('AUDITORÍA FALLIDA — se han detectado incumplimientos del CRA.'));
  }
  logger.log('');
}

module.exports = { reportConsole };
