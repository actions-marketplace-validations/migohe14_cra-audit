'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { scanVulnerabilities } = require('../src/core/vuln-scanner');
const { runAudit } = require('../src/core/auditor');
const { DEFAULT_POLICY } = require('../src/core/policy');
const {
  queryOsv, osvSeverity, fixedVersion, compareSemver, cvss3BaseScore,
} = require('../src/core/osv');

// --- Fake OSV.dev + CISA KEV ---------------------------------------------------

const RECORDS = {
  'MAL-2025-47141': {
    id: 'MAL-2025-47141',
    summary: 'Malicious code in @ctrl/tinycolor (npm)',
    affected: [{ package: { name: '@ctrl/tinycolor', ecosystem: 'npm' }, versions: ['4.1.1'] }],
  },
  'GHSA-lodash': {
    id: 'GHSA-lodash',
    summary: 'Command Injection in lodash',
    aliases: ['CVE-2021-23337'],
    database_specific: { severity: 'HIGH', cwe_ids: ['CWE-94'] },
    affected: [{
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    }],
  },
  'GHSA-exploited': {
    id: 'GHSA-exploited',
    summary: 'Remote code execution in widget',
    aliases: ['CVE-2099-0001'],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [{
      package: { name: 'widget', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
    }],
  },
};

const VULNS_BY_PACKAGE = {
  '@ctrl/tinycolor@4.1.1': ['MAL-2025-47141'],
  'lodash@4.17.20': ['GHSA-lodash'],
  'widget@1.0.2': ['GHSA-exploited'],
};

const KEV = {
  catalogVersion: '2099.01.01',
  vulnerabilities: [{ cveID: 'CVE-2099-0001', vulnerabilityName: 'Widget RCE', dateAdded: '2099-01-01', dueDate: '2099-01-22' }],
};

let realFetch;
let osvDown;
let kevDown;
let requests;

beforeEach(() => {
  realFetch = globalThis.fetch;
  osvDown = false;
  kevDown = false;
  requests = [];
  globalThis.fetch = async (url, init = {}) => {
    requests.push(url);
    const json = (status, body) => ({ ok: status < 400, status, json: async () => body, headers: new Map() });
    if (url.includes('osv.dev')) {
      if (osvDown) return json(503, {});
      if (url.endsWith('/querybatch')) {
        const { queries } = JSON.parse(init.body);
        return json(200, {
          results: queries.map((q) => ({
            vulns: (VULNS_BY_PACKAGE[`${q.package.name}@${q.version}`] || []).map((id) => ({ id })),
          })),
        });
      }
      const id = decodeURIComponent(url.split('/vulns/')[1]);
      return RECORDS[id] ? json(200, RECORDS[id]) : json(404, {});
    }
    if (url.includes('known_exploited_vulnerabilities')) {
      return kevDown ? json(503, {}) : json(200, KEV);
    }
    throw new Error(`unexpected request ${url}`);
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

/** npm project: tinycolor (malicious), lodash (vulnerable), widget (KEV, dev only). */
function project() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-vuln-'));
  const pkg = {
    name: 'app',
    version: '1.0.0',
    dependencies: { '@ctrl/tinycolor': '4.1.1', lodash: '4.17.20' },
    devDependencies: { widget: '^1.0.0' },
  };
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0', dependencies: pkg.dependencies, devDependencies: pkg.devDependencies },
      'node_modules/@ctrl/tinycolor': { version: '4.1.1' },
      'node_modules/lodash': { version: '4.17.20' },
      'node_modules/widget': { version: '1.0.2', dev: true },
      'node_modules/safe': { version: '1.0.0', dev: true },
    },
  };
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(lock));
  return dir;
}

// --- Scanner -------------------------------------------------------------------

test('reports malicious, vulnerable and actively exploited components', async () => {
  const result = await scanVulnerabilities(project());
  assert.equal(result.ok, true);
  assert.equal(result.source, 'osv');
  assert.equal(result.scanned, 4);
  assert.deepEqual(result.kev, { checked: true, catalogVersion: '2099.01.01', entries: 1 });

  const byName = Object.fromEntries(result.vulnerabilities.map((v) => [v.name, v]));
  assert.equal(byName['@ctrl/tinycolor'].malicious, true);
  assert.equal(byName['@ctrl/tinycolor'].severity, 'critical');
  assert.equal(byName['@ctrl/tinycolor'].fixAvailable, false);

  assert.equal(byName.lodash.severity, 'high');
  assert.deepEqual(byName.lodash.fixAvailable, { name: 'lodash', version: '4.17.21', breaking: false });
  assert.equal(byName.lodash.direct, true);

  assert.equal(byName.widget.kev, true);
  assert.equal(byName.widget.severity, 'critical'); // computed from CVSS 9.8
  assert.equal(byName.widget.sources[0].kev.dateAdded, '2099-01-01');
  assert.equal(byName.widget.fixAvailable.breaking, true);

  assert.equal(result.counts.malicious, 1);
  assert.equal(result.counts.kev, 1);
  assert.equal(result.counts.total, 3);
});

test('production mode follows the graph from package.json dependencies', async () => {
  const result = await scanVulnerabilities(project(), { production: true });
  assert.equal(result.scanned, 2);
  assert.ok(!result.vulnerabilities.some((v) => v.name === 'widget'));
});

test('an unreachable KEV catalogue is reported, not silently passed', async () => {
  kevDown = true;
  const result = await scanVulnerabilities(project());
  assert.equal(result.kev.checked, false);
  assert.match(result.kev.error, /unreachable/);
  // Both the primary feed and the GitHub mirror were tried.
  assert.equal(requests.filter((u) => u.includes('known_exploited')).length, 2);
});

test('queryOsv reports failure when OSV.dev is down', async () => {
  osvDown = true;
  const result = await queryOsv([{ name: 'lodash', version: '4.17.20' }]);
  assert.equal(result.ok, false);
  assert.match(result.error, /HTTP 503/);
});

// --- Audit gate ------------------------------------------------------------------

test('malicious packages fail the audit even when allowlisted', async () => {
  const policy = {
    ...DEFAULT_POLICY,
    failOn: 'critical',
    vulnerabilities: { allowlist: ['MAL-2025-47141', '@ctrl/tinycolor', 'GHSA-exploited'] },
  };
  const report = await runAudit(project(), policy, null, { only: 'vulnerabilities' });
  const failed = report.gate.reasons.filter((r) => !r.passed).map((r) => r.label);
  assert.equal(report.gate.passed, false);
  assert.ok(failed.some((l) => /malicious package/.test(l)));
  assert.ok(!failed.some((l) => /KEV/.test(l))); // allowlisted with justification
});

test('KEV findings fail by default and only warn with failOnKev: false', async () => {
  const dir = project();
  VULNS_BY_PACKAGE['@ctrl/tinycolor@4.1.1'] = [];
  try {
    const strict = await runAudit(dir, { ...DEFAULT_POLICY, failOn: 'critical' }, null, { only: 'vulnerabilities' });
    const kevReason = strict.gate.reasons.find((r) => /KEV/.test(r.label));
    assert.equal(kevReason.passed, false);
    assert.match(kevReason.label, /Art\. 14/);

    const lenient = await runAudit(dir, { ...DEFAULT_POLICY, failOn: 'critical', failOnKev: false }, null, { only: 'vulnerabilities' });
    const warned = lenient.gate.reasons.find((r) => /KEV/.test(r.label));
    assert.equal(warned.passed, true);
    assert.equal(warned.warning, true);
  } finally {
    VULNS_BY_PACKAGE['@ctrl/tinycolor@4.1.1'] = ['MAL-2025-47141'];
  }
});

test('allowlisting by CVE alias accepts a finding', async () => {
  const policy = {
    ...DEFAULT_POLICY,
    failOn: 'high',
    failOnKev: false,
    vulnerabilities: { allowlist: ['CVE-2021-23337', 'CVE-2099-0001'] },
  };
  VULNS_BY_PACKAGE['@ctrl/tinycolor@4.1.1'] = [];
  try {
    const report = await runAudit(project(), policy, null, { only: 'vulnerabilities' });
    assert.equal(report.gate.passed, true, JSON.stringify(report.gate.reasons));
  } finally {
    VULNS_BY_PACKAGE['@ctrl/tinycolor@4.1.1'] = ['MAL-2025-47141'];
  }
});

// --- OSV helpers -------------------------------------------------------------------

test('computes CVSS v3 base scores', () => {
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3BaseScore('garbage'), null);
});

test('maps OSV records to npm severities', () => {
  assert.equal(osvSeverity(RECORDS['MAL-2025-47141']), 'critical');
  assert.equal(osvSeverity({ database_specific: { severity: 'MODERATE' } }), 'moderate');
  assert.equal(osvSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' }] }), 'moderate');
  assert.equal(osvSeverity({}), 'unknown');
});

test('picks the fixed version of the range containing the installed version', () => {
  const record = {
    affected: [{
      package: { name: 'x' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }, { introduced: '2.0.0' }, { fixed: '2.0.5' }] }],
    }],
  };
  assert.equal(fixedVersion(record, 'x', '1.0.0'), '1.2.3');
  assert.equal(fixedVersion(record, 'x', '2.0.1'), '2.0.5');
  assert.equal(fixedVersion(record, 'x', '1.5.0'), null);
  assert.equal(fixedVersion(record, 'other', '1.0.0'), null);
});

test('compares semver including prereleases', () => {
  assert.ok(compareSemver('1.10.0', '1.9.0') > 0);
  assert.ok(compareSemver('1.0.0-alpha', '1.0.0') < 0);
  assert.ok(compareSemver('1.0.0-alpha.2', '1.0.0-alpha.10') < 0);
  assert.ok(compareSemver('1.0.0-beta', '1.0.0-alpha') > 0);
  assert.equal(compareSemver('1.0.0+build', '1.0.0'), 0);
});
