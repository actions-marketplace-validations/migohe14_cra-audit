'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { reportingGuide, supportedCountries } = require('../src/core/reporting');
const { checkReadiness, writeTemplates } = require('../src/core/readiness');

test('Spain reports to INCIBE-CERT, with SRP access requested from INCIBE', () => {
  const guide = reportingGuide('es');
  assert.equal(guide.country, 'ES');
  assert.equal(guide.local.csirt, 'INCIBE-CERT');
  assert.equal(guide.local.srpAccess.contact, 'cve-coordination@incibe.es');
  assert.deepEqual(guide.local.otherChannels.map((c) => c.contact), ['incidencias@incibe-cert.es', 'cve-coordination@incibe.es']);
  assert.match(guide.local.source, /^https:\/\/www\.incibe\.es\//);
  assert.match(guide.recipients, /INCIBE-CERT/);
  assert.equal(guide.deadlines.incident[2].deadline, '1 month after the 72-hour notification');
  assert.ok(supportedCountries().includes('ES'));
});

test('other or unknown countries get the generic EU procedure', () => {
  for (const country of [null, undefined, 'FR']) {
    const guide = reportingGuide(country);
    assert.equal(guide.local, null);
    assert.equal(guide.srp.url, 'https://portal.cra-srp.enisa.europa.eu');
    assert.match(guide.recipients, /CSIRT designated as coordinator/);
  }
});

function fillTemplates(dir) {
  for (const file of ['SECURITY.md', '.well-known/security.txt']) {
    const full = path.join(dir, file);
    fs.writeFileSync(full, fs.readFileSync(full, 'utf8')
      .replace(/TODO: security@example\.com|TODO-security@example\.com/g, 'security@shop.example')
      .replace(/TODO: (YYYY|AAAA)-MM-DD/g, '2031-12-31'));
  }
}

test('Spanish templates with the INCIBE section pass readiness', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-es-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'tienda', version: '1.0.0', repository: 'github:acme/tienda' }));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {} } }));
  const now = new Date('2026-09-24T00:00:00Z');

  writeTemplates(dir, { now, lang: 'es', country: 'ES' });
  const md = fs.readFileSync(path.join(dir, 'SECURITY.md'), 'utf8');
  assert.match(md, /^# Política de seguridad/);
  assert.match(md, /INCIBE-CERT/);
  assert.match(md, /cve-coordination@incibe\.es/);
  assert.match(fs.readFileSync(path.join(dir, '.well-known/security.txt'), 'utf8'), /Preferred-Languages: es, en/);

  fillTemplates(dir);
  const result = checkReadiness(dir, { now, country: 'ES' });
  assert.equal(result.passed, true, JSON.stringify(result.checks.filter((c) => !c.passed)));
  assert.ok(result.checks.every((c) => c.passed));
  assert.ok(result.checks.some((c) => c.id === 'coordinating-csirt'));
});

test('an English SECURITY.md without the CSIRT is flagged for Spain', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-es-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{}');
  writeTemplates(dir, { lang: 'en' });
  const csirt = checkReadiness(dir, { country: 'ES' }).checks.find((c) => c.id === 'coordinating-csirt');
  assert.equal(csirt.passed, false);
  assert.match(csirt.detail, /cve-coordination@incibe\.es/);
  // Without a country, the check does not apply.
  assert.ok(!checkReadiness(dir).checks.some((c) => c.id === 'coordinating-csirt'));
});
