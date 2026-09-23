'use strict';

const path = require('node:path');
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

  if (report.sections.vulnerabilities) renderVulnerabilities(report.sections.vulnerabilities, report.reporting);
  if (report.sections.sbom) renderSbom(report.sections.sbom);
  if (report.sections.licenses) renderLicenses(report.sections.licenses);

  renderSummary(report);
}

function renderVulnerabilities(section, reporting) {
  logger.heading('1) Known vulnerabilities (CRA Annex I · Art. 14)');
  if (!section.ok) {
    logger.error(section.error);
    return;
  }
  logger.detail(describeSources(section));
  for (const warning of section.warnings || []) logger.warn(warning);
  for (const note of (section.input && section.input.notes) || []) logger.detail(note);

  const c = section.counts;
  if (c.total === 0) {
    logger.success('No known vulnerabilities. Meets the "no known exploitable vulnerabilities" requirement.');
    return;
  }

  logger.log(
    `  ${color.red(`${c.critical} critical`)} · ${color.red(`${c.high} high`)} · ` +
    `${color.yellow(`${c.moderate} moderate`)} · ${color.yellow(`${c.low} low`)} · ${color.gray(`${c.info} info`)}` +
    (c.unknown ? color.gray(` · ${c.unknown} unrated`) : '') +
    (c.kev ? ` · ${color.red(color.bold(`${c.kev} actively exploited (KEV)`))}` : '') +
    (c.malicious ? ` · ${color.red(color.bold(`${c.malicious} MALICIOUS`))}` : '')
  );

  // Malicious and exploited findings first: they are the urgent ones.
  const urgency = (v) => (v.malicious ? 2 : v.kev ? 1 : 0);
  const ordered = [...section.vulnerabilities].sort((a, b) => urgency(b) - urgency(a));
  const top = ordered.slice(0, 15);
  for (const vuln of top) {
    const sev = (SEVERITY_COLORS[vuln.severity] || color.gray)(vuln.severity.toUpperCase().padEnd(8));
    const tags = (vuln.malicious ? color.red(color.bold('[MALICIOUS] ')) : '') + (vuln.kev ? color.red(color.bold('[KEV] ')) : '');
    const label = vuln.version ? `${vuln.name}@${vuln.version}` : vuln.name;
    const fix = vuln.malicious ? color.red('(remove it and rotate any exposed credentials)') : describeFix(vuln.fixAvailable);
    logger.log(`  ${sev} ${tags}${color.bold(label)} ${color.gray(vuln.range || '')} ${fix}`);
    for (const adv of vuln.sources.slice(0, 3)) {
      const kev = adv.kev ? color.red(` [KEV since ${adv.kev.dateAdded}]`) : '';
      const id = adv.id ? `${adv.id}${(adv.aliases || []).filter((a) => a.startsWith('CVE-')).map((a) => ` / ${a}`).join('')} ` : '';
      logger.detail(`${id}${adv.title || ''}${kev}${adv.url ? ' — ' + adv.url : ''}`);
    }
    if (vuln.sources.length > 3) logger.detail(`… and ${vuln.sources.length - 3} more advisories.`);
  }
  if (ordered.length > top.length) {
    logger.detail(`… and ${ordered.length - top.length} more.`);
  }

  if (c.kev) renderArticle14Notice(reporting);
  if (c.malicious) {
    logger.log('');
    logger.error(color.bold('Malicious package(s) detected: treat this as a security incident.'));
    logger.detail('Remove the package, reinstall from a clean lockfile, and rotate every credential');
    logger.detail('available to machines that installed it (npm/GitHub tokens, cloud keys, CI secrets).');
  }
}

function describeSources(section) {
  if (section.source !== 'osv') return 'Source: npm audit';
  const kev = section.kev && section.kev.checked
    ? `CISA KEV ${section.kev.catalogVersion || ''} (${section.kev.entries} entries)`.replace('  ', ' ')
    : `CISA KEV not checked (${(section.kev && section.kev.error) || 'unavailable'})`;
  const scope = section.input
    ? `${section.scanned} components from ${section.input.format === 'manifest' ? section.input.file : shortPath(section.input.file)} (${(section.ecosystems || []).join(', ')})` +
      (section.input.unidentified ? ` · ${section.input.unidentified} ${section.input.format === 'manifest' ? 'not pinned, skipped' : 'without purl skipped'}` : '')
    : `${section.scanned} components${(section.ecosystems || []).length > 1 ? ` (${section.ecosystems.join(', ')})` : ''}`;
  return `Sources: OSV.dev (GitHub advisories + OpenSSF malicious packages) · ${kev} · ${scope}`;
}

/** CRA Art. 14 reporting clock, shown when a KEV-listed vulnerability is found. */
function renderArticle14Notice(reporting) {
  const local = reporting && reporting.local;
  logger.log('');
  logger.warn(color.bold('CRA Art. 14 — actively exploited vulnerability in a dependency'));
  logger.detail('If it affects a product with digital elements you place on the EU market, notify');
  logger.detail(`${local ? `${local.csirt} and ENISA` : 'the coordinating CSIRT and ENISA'} through the Single Reporting Platform (SRP):`);
  logger.detail('  • Early warning ........ within 24 hours of becoming aware');
  logger.detail('  • Notification ......... within 72 hours');
  logger.detail('  • Final report ......... within 14 days after a corrective measure is available');
  logger.detail('Assess exploitability in your product first; document the decision either way.');
  if (local) {
    logger.log('');
    logger.detail(color.bold(`${local.csirt} (${local.country}) — access to the SRP:`));
    local.srpAccess.steps.forEach((step, i) => logger.detail(`  ${i + 1}. ${step}`));
    logger.detail(`  ${local.srpAccess.advice}`);
    logger.detail(`  ${local.whenInDoubt}`);
    logger.detail(`  Source: ${local.source}`);
  } else {
    logger.detail(`SRP: ${reporting ? reporting.srp.url : 'https://portal.cra-srp.enisa.europa.eu'} · Set your country (--country, e.g. ES) for its CSIRT's steps.`);
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
  if (section.manifest) {
    logger.detail(`Components read from ${section.files.join(', ')} (${section.ecosystems.join(', ')}): ${section.componentCount}`);
    logger.warn('cra-audit builds TR-03183 SBOMs from npm lockfiles. For these ecosystems, commit the SBOM your');
    logger.detail('build tooling produces (Syft, cdxgen, cyclonedx-maven-plugin, cyclonedx-py…) and audit it with -i.');
    return;
  }
  logger.detail(`${section.input ? `Input SBOM: ${shortPath(section.input)} · ` : ''}Format: ${section.format} · Components: ${section.componentCount}`);

  if (section.validation) {
    const v = section.validation;
    for (const check of v.checks) {
      const mark = check.passed ? color.green('✔') : color.red('✖');
      logger.log(`  ${mark} ${check.label}`);
    }
    if (v.valid) {
      logger.success('The SBOM meets the TR-03183-2 required data fields.');
    } else {
      logger.warn(`The SBOM does not meet ${v.failedChecks.length} minimum requirement(s).`);
    }
  }
  if (section.outputPath) {
    logger.detail(`SBOM written to: ${section.outputPath}`);
  }
}

function renderLicenses(section) {
  logger.heading('3) Third-party component licenses (TR-03183-2 §5.2)');
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
    const mark = !item.passed ? color.red('✖') : item.warning ? color.yellow('!') : color.green('✔');
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

/** A path relative to the working directory when it is inside it. */
function shortPath(file) {
  const rel = path.relative(process.cwd(), file);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : file;
}

module.exports = { reportConsole };
