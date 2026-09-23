'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { buildVex, normalizeAllowlist, acceptance } = require('../src/core/vex');
const { buildSarif, findEntryLine } = require('../src/reporters/sarif');
const { checkReadiness, writeTemplates, parseSecurityTxt } = require('../src/core/readiness');

// A scanVulnerabilities() result, as produced from OSV + KEV.
const VULNS = {
  ok: true,
  source: 'osv',
  vulnerabilities: [
    {
      name: 'jquery', version: '3.4.1', severity: 'moderate', direct: true, malicious: false, kev: true,
      fixAvailable: { name: 'jquery', version: '3.5.0', breaking: false },
      sources: [
        { id: 'GHSA-jpcq-cgw6-v4j6', aliases: ['CVE-2020-11023'], title: 'Potential XSS in jQuery', url: 'https://osv.dev/vulnerability/GHSA-jpcq-cgw6-v4j6', severity: 'moderate', cvss: 6.9, cwe: ['CWE-79'], fixed: '3.5.0', kev: { cve: 'CVE-2020-11023', dateAdded: '2025-01-23' } },
      ],
    },
    {
      name: 'lodash', version: '4.17.20', severity: 'high', direct: false, malicious: false, kev: false,
      fixAvailable: { name: 'lodash', version: '4.17.21', breaking: false },
      sources: [
        { id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], title: 'Command Injection in lodash', url: 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm', severity: 'high', cvss: 7.2, cwe: ['CWE-94'], fixed: '4.17.21', kev: null },
      ],
    },
    {
      name: '@ctrl/tinycolor', version: '4.1.1', severity: 'critical', direct: true, malicious: true, kev: false,
      fixAvailable: false,
      sources: [{ id: 'MAL-2025-47141', aliases: [], title: 'Malicious code in @ctrl/tinycolor', url: 'https://osv.dev/vulnerability/MAL-2025-47141', severity: 'critical', cvss: null, cwe: [], fixed: null, kev: null }],
    },
  ],
};

const POLICY = {
  vulnerabilities: {
    allowlist: [
      { id: 'CVE-2020-11023', package: 'jquery', status: 'not_affected', justification: 'code_not_reachable', detail: 'No untrusted HTML reaches jQuery.' },
      { id: 'GHSA-35jh-r3h4-6jhm', status: 'affected', detail: 'Upgrade scheduled.' },
      { id: 'MAL-2025-47141', status: 'not_affected', justification: 'code_not_present' },
    ],
  },
};

const byName = (list, name) => list.find((v) => v.name === name);

// --- Allowlist / VEX -------------------------------------------------------------

test('normalizes legacy string entries and assessment objects', () => {
  const entries = normalizeAllowlist({ vulnerabilities: { allowlist: ['lodash', { id: 'CVE-1', status: 'bogus', justification: 'nope' }] } });
  assert.deepEqual(entries[0], { id: 'lodash', package: null, status: 'not_affected', justification: null, detail: null, legacy: true });
  assert.deepEqual(entries[1], { id: 'CVE-1', package: null, status: 'not_affected', justification: null, detail: null });
});

test('only not_affected assessments accept a finding; malicious never', () => {
  assert.deepEqual(acceptance(byName(VULNS.vulnerabilities, 'jquery'), POLICY), { accepted: true, unjustified: 0 });
  assert.equal(acceptance(byName(VULNS.vulnerabilities, 'lodash'), POLICY).accepted, false);
  assert.equal(acceptance(byName(VULNS.vulnerabilities, '@ctrl/tinycolor'), POLICY).accepted, false);
  // Legacy entries still accept by package name, but count as unjustified.
  assert.deepEqual(acceptance(byName(VULNS.vulnerabilities, 'lodash'), { vulnerabilities: { allowlist: ['lodash'] } }), { accepted: true, unjustified: 1 });
});

test('CycloneDX VEX records the analysis of every advisory', () => {
  const vex = buildVex({ name: 'shop', version: '1.0.0' }, VULNS, POLICY);
  assert.equal(vex.specVersion, '1.6');
  assert.equal(vex.metadata.component.purl, 'pkg:npm/shop@1.0.0');

  const jquery = vex.vulnerabilities.find((v) => v.id === 'CVE-2020-11023');
  assert.deepEqual(jquery.affects, [{ ref: 'pkg:npm/jquery@3.4.1' }]);
  assert.equal(jquery.analysis.state, 'not_affected');
  assert.equal(jquery.analysis.justification, 'code_not_reachable');
  assert.match(jquery.analysis.detail, /CISA KEV.*No untrusted HTML/);
  assert.equal(jquery.ratings[0].severity, 'medium');
  assert.deepEqual(jquery.cwes, [79]);
  assert.deepEqual(jquery.references.map((r) => r.id), ['GHSA-jpcq-cgw6-v4j6']);

  const lodash = vex.vulnerabilities.find((v) => v.id === 'CVE-2021-23337');
  assert.equal(lodash.analysis.state, 'exploitable');
  assert.deepEqual(lodash.analysis.response, ['update']);

  const mal = vex.vulnerabilities.find((v) => v.id === 'MAL-2025-47141');
  assert.equal(mal.analysis.state, 'exploitable'); // the allowlist cannot clear malware
});

test('OpenVEX statements carry the status-specific fields', () => {
  const vex = buildVex({ name: 'shop', version: '1.0.0' }, VULNS, POLICY, { format: 'openvex', author: 'security@shop.example' });
  assert.equal(vex['@context'], 'https://openvex.dev/ns/v0.2.0');
  assert.equal(vex.author, 'security@shop.example');

  const [jquery, lodash, mal] = vex.statements;
  assert.equal(jquery.status, 'not_affected');
  assert.equal(jquery.justification, 'vulnerable_code_not_in_execute_path');
  assert.ok(jquery.impact_statement);
  assert.deepEqual(jquery.products, [{ '@id': 'pkg:npm/shop@1.0.0', subcomponents: [{ '@id': 'pkg:npm/jquery@3.4.1' }] }]);

  assert.equal(lodash.status, 'affected');
  assert.equal(lodash.action_statement, 'Update lodash to 4.17.21 or later.');
  assert.equal(mal.status, 'affected');
  assert.match(mal.action_statement, /Remove @ctrl\/tinycolor/);
});

test('findings without an assessment are in triage', () => {
  const vex = buildVex({ name: 'shop', version: '1.0.0' }, VULNS, {});
  assert.equal(vex.vulnerabilities.find((v) => v.id === 'CVE-2021-23337').analysis.state, 'in_triage');
  const open = buildVex({ name: 'shop', version: '1.0.0' }, VULNS, {}, { format: 'openvex' });
  assert.equal(open.statements[0].status, 'under_investigation');
});

// --- SARIF -----------------------------------------------------------------------

function npmProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-sarif-'));
  fs.mkdirSync(path.join(dir, '.git'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'shop', version: '1.0.0' }));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'shop' },
      'node_modules/@ctrl/tinycolor': { version: '4.1.1' },
      'node_modules/jquery': { version: '3.4.1' },
      'node_modules/lodash': { version: '4.17.20' },
    },
  }, null, 2));
  return dir;
}

test('SARIF results point at the lockfile entry with GitHub severities', () => {
  const report = {
    sections: {
      vulnerabilities: VULNS,
      licenses: { ok: true, summary: { denied: [{ name: 'lodash', version: '4.17.20', license: 'GPL-3.0' }], notAllowed: [], missing: [] } },
    },
  };
  const sarif = buildSarif(report, npmProject(), POLICY);
  const run = sarif.runs[0];
  assert.equal(sarif.version, '2.1.0');
  assert.equal(run.tool.driver.name, 'cra-audit');

  const result = (text) => run.results.find((r) => r.message.text.includes(text));
  const lodash = result('Command Injection');
  assert.equal(lodash.level, 'error');
  assert.equal(lodash.locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  assert.equal(lodash.locations[0].physicalLocation.region.startLine, 13);
  assert.match(lodash.message.text, /Fixed in 4\.17\.21\. Transitive dependency\./);

  const jquery = result('jquery@3.4.1');
  assert.equal(jquery.level, 'note'); // assessed not_affected in the policy
  assert.equal(jquery.suppressions[0].status, 'accepted');
  assert.match(jquery.suppressions[0].justification, /code_not_reachable/);
  assert.match(jquery.message.text, /CISA KEV since 2025-01-23/);

  const mal = result('[MALICIOUS]');
  assert.equal(mal.level, 'error');
  assert.equal(mal.suppressions, undefined);
  const malRule = run.tool.driver.rules.find((r) => r.id === 'MAL-2025-47141');
  assert.equal(malRule.properties['security-severity'], '10.0');
  assert.ok(malRule.properties.tags.includes('malicious'));

  assert.equal(result('GPL-3.0').ruleId, 'cra-audit/license-denied');
});

test('finds entry lines in Yarn and pnpm lockfiles', () => {
  const yarn = ['# yarn lockfile v1', '', '"@scope/w@^1.0.0":', '  version "1.0.2"', '', 'left-pad@^1.3.0:', '  version "1.3.0"'];
  assert.equal(findEntryLine(yarn, 'left-pad', '1.3.0'), 6);
  assert.equal(findEntryLine(yarn, '@scope/w', '1.0.2'), 3);
  const berry = ['"left-pad@npm:^1.3.0":', '  version: 1.3.0'];
  assert.equal(findEntryLine(berry, 'left-pad', '1.3.0'), 1);
  const pnpm = ['packages:', '  react-dom@18.3.1:', '  react@18.3.1:'];
  assert.equal(findEntryLine(pnpm, 'react', '18.3.1'), 3);
  assert.equal(findEntryLine(pnpm, 'missing', '1.0.0'), 1);
});

// --- Readiness --------------------------------------------------------------------

function projectWith(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-ready-'));
  const all = {
    'package.json': JSON.stringify({ name: 'shop', version: '2.0.0', repository: 'github:acme/shop' }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {} } }),
    ...files,
  };
  for (const [rel, content] of Object.entries(all)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

const status = (result) => Object.fromEntries(result.checks.map((c) => [c.id, c.passed]));

test('readiness fails without a security policy', () => {
  const result = checkReadiness(projectWith({}));
  assert.equal(result.passed, false);
  const s = status(result);
  assert.equal(s['security-policy'], false);
  assert.equal(s['security-contact'], false);
  assert.equal(s['support-period'], false);
  assert.equal(s.sbom, true);
});

test('--init templates pass once the placeholders are filled', () => {
  const dir = projectWith({});
  const now = new Date('2026-09-23T00:00:00Z');
  const created = writeTemplates(dir, { now });
  assert.deepEqual(created.map((c) => c.created), [true, true]);

  const before = checkReadiness(dir, { now });
  assert.equal(status(before).placeholders, false);

  for (const file of ['SECURITY.md', '.well-known/security.txt']) {
    const full = path.join(dir, file);
    fs.writeFileSync(full, fs.readFileSync(full, 'utf8')
      .replace(/TODO: security@example\.com|TODO-security@example\.com/g, 'security@shop.example')
      .replace(/TODO: YYYY-MM-DD/g, '2031-12-31'));
  }
  const after = checkReadiness(dir, { now });
  assert.equal(after.passed, true, JSON.stringify(after.checks.filter((c) => !c.passed)));
  assert.ok(after.checks.every((c) => c.passed));

  // Existing files are never overwritten.
  assert.deepEqual(writeTemplates(dir, { now }).map((c) => c.created), [false, false]);
});

test('an expired security.txt fails', () => {
  const dir = projectWith({ '.well-known/security.txt': 'Contact: mailto:s@shop.example\nExpires: 2025-01-01T00:00:00Z\n' });
  const s = status(checkReadiness(dir, { now: new Date('2026-09-23T00:00:00Z') }));
  assert.equal(s['security-txt-contact'], true);
  assert.equal(s['security-txt-expires'], false);
});

test('parses security.txt fields', () => {
  assert.deepEqual(parseSecurityTxt('# c\nContact: mailto:a@b.c\ncontact: https://x\nExpires: 2027-01-01T00:00:00Z\n'),
    { contact: ['mailto:a@b.c', 'https://x'], expires: '2027-01-01T00:00:00Z', policy: [] });
});
