'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readSbom, parsePurl } = require('../src/core/sbom-reader');
const { scanVulnerabilities } = require('../src/core/vuln-scanner');
const { runAudit } = require('../src/core/auditor');
const { DEFAULT_POLICY } = require('../src/core/policy');
const { buildVex } = require('../src/core/vex');
const { buildSarif } = require('../src/reporters/sarif');

function write(dir, name, content) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  return file;
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-input-'));

// A Java + Python + Go service, as cdxgen/Syft would describe it.
const CDX = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  metadata: { component: { 'bom-ref': 'root', type: 'application', name: 'billing', version: '1.4.0', purl: 'pkg:maven/com.acme/billing@1.4.0' } },
  components: [
    { 'bom-ref': 'log4j', type: 'library', group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.14.1', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', licenses: [{ license: { id: 'Apache-2.0' } }] },
    { 'bom-ref': 'django', type: 'library', name: 'Django', version: '3.0', purl: 'pkg:pypi/django@3.0?package-id=abc', licenses: [{ expression: 'BSD-3-Clause' }] },
    {
      'bom-ref': 'bundle', type: 'library', name: 'bundle', version: '1.0', purl: 'pkg:golang/example.com/bundle@v1.0.0',
      components: [{ 'bom-ref': 'x-text', type: 'library', name: 'text', version: 'v0.3.5', purl: 'pkg:golang/golang.org/x/text@v0.3.5', scope: 'optional' }],
    },
    { 'bom-ref': 'f', type: 'file', name: 'README' },
    { 'bom-ref': 'nopurl', type: 'library', name: 'vendored-lib', version: '0.1' },
  ],
  dependencies: [
    { ref: 'root', dependsOn: ['log4j', 'django', 'bundle'] },
    { ref: 'bundle', dependsOn: ['x-text'] },
  ],
};

// --- Package URLs --------------------------------------------------------------

test('parses Package URLs into OSV names', () => {
  assert.deepEqual(
    (({ type, osvName, version, canonical }) => ({ type, osvName, version, canonical }))(parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar')),
    { type: 'maven', osvName: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', canonical: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' },
  );
  assert.equal(parsePurl('pkg:npm/%40ctrl/tinycolor@4.1.1').osvName, '@ctrl/tinycolor');
  assert.equal(parsePurl('pkg:npm/@ctrl/tinycolor').version, null); // an unencoded scope is not a version
  assert.equal(parsePurl('pkg:golang/golang.org/x/text@v0.3.5').osvName, 'golang.org/x/text');
  assert.equal(parsePurl('pkg:pypi/django@3.0#sub/path').canonical, 'pkg:pypi/django@3.0');
  assert.equal(parsePurl('not-a-purl'), null);
});

// --- Reading SBOMs -----------------------------------------------------------------

test('reads a CycloneDX SBOM of any ecosystem', () => {
  const parsed = readSbom(write(tmp(), 'bom.json', CDX));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.format, 'cyclonedx');
  assert.equal(parsed.unidentified, 1); // vendored-lib has no purl; the file is not a component
  assert.deepEqual(parsed.root, {
    name: 'billing', version: '1.4.0', purl: 'pkg:maven/com.acme/billing@1.4.0',
    dependsOn: ['pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'pkg:pypi/django@3.0', 'pkg:golang/example.com/bundle@v1.0.0'],
  });

  const byKey = Object.fromEntries(parsed.components.map((c) => [c.key, c]));
  const log4j = byKey['pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'];
  assert.equal(log4j.name, 'org.apache.logging.log4j:log4j-core');
  assert.equal(log4j.ecosystem, 'maven');
  assert.equal(log4j.license, 'Apache-2.0');
  assert.equal(byKey['pkg:pypi/django@3.0'].license, 'BSD-3-Clause');
  // Nested components are read, with their scope and graph edges.
  assert.equal(byKey['pkg:golang/golang.org/x/text@v0.3.5'].optional, true);
  assert.deepEqual(byKey['pkg:golang/example.com/bundle@v1.0.0'].dependsOn, ['pkg:golang/golang.org/x/text@v0.3.5']);
});

test('reads an SPDX 2.3 SBOM as Syft writes it', () => {
  const spdx = {
    spdxVersion: 'SPDX-2.3',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'svc',
    packages: [
      { SPDXID: 'SPDXRef-root', name: 'svc', versionInfo: '2.0.0' },
      { SPDXID: 'SPDXRef-a', name: 'smallvec', versionInfo: '1.6.0', licenseConcluded: 'NOASSERTION', licenseDeclared: 'MIT OR Apache-2.0', externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:cargo/smallvec@1.6.0' }] },
      { SPDXID: 'SPDXRef-b', name: 'Newtonsoft.Json', versionInfo: '12.0.1', externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:nuget/Newtonsoft.Json@12.0.1' }] },
    ],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-root' },
      { spdxElementId: 'SPDXRef-root', relationshipType: 'CONTAINS', relatedSpdxElement: 'SPDXRef-a' },
      { spdxElementId: 'SPDXRef-b', relationshipType: 'DEPENDENCY_OF', relatedSpdxElement: 'SPDXRef-a' },
    ],
  };
  const parsed = readSbom(write(tmp(), 'sbom.spdx.json', spdx));
  assert.equal(parsed.format, 'spdx');
  assert.equal(parsed.root.name, 'svc');
  assert.equal(parsed.root.purl, 'pkg:generic/svc@2.0.0');
  assert.deepEqual(parsed.root.dependsOn, ['pkg:cargo/smallvec@1.6.0']);
  const smallvec = parsed.components.find((c) => c.ecosystem === 'cargo');
  assert.equal(smallvec.license, 'MIT OR Apache-2.0');
  assert.deepEqual(smallvec.dependsOn, ['pkg:nuget/Newtonsoft.Json@12.0.1']);
});

test('reads SPDX 3.0 packages and relationships', () => {
  const doc = {
    '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
    '@graph': [
      { type: 'SpdxDocument', spdxId: 'urn:doc', rootElement: ['urn:root'] },
      { type: 'software_Package', spdxId: 'urn:root', name: 'app', software_packageVersion: '1.0.0' },
      { type: 'software_Package', spdxId: 'urn:rails', name: 'rails', software_packageVersion: '5.2.0', software_packageUrl: 'pkg:gem/rails@5.2.0' },
      { type: 'Relationship', spdxId: 'urn:rel', from: 'urn:root', relationshipType: 'dependsOn', to: ['urn:rails'] },
    ],
  };
  const parsed = readSbom(write(tmp(), 'spdx3.json', doc));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.root.name, 'app');
  assert.deepEqual(parsed.root.dependsOn, ['pkg:gem/rails@5.2.0']);
});

test('reports unreadable or foreign files', () => {
  const dir = tmp();
  assert.match(readSbom(path.join(dir, 'missing.json')).error, /file not found/);
  assert.match(readSbom(write(dir, 'x.json', { hello: 'world' })).error, /not a CycloneDX or SPDX/);
});

// --- Scanning by purl ---------------------------------------------------------------

const LOG4SHELL = {
  id: 'GHSA-jfh8-c2jp-5v3q',
  summary: 'Remote code injection in Log4j',
  aliases: ['CVE-2021-44228'],
  database_specific: { severity: 'CRITICAL' },
  affected: [{
    package: { name: 'org.apache.logging.log4j:log4j-core', ecosystem: 'Maven' },
    ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.13.0' }, { fixed: '2.15.0' }] }],
  }],
};
const DJANGO = {
  id: 'GHSA-hmr4-m2h5-33qx',
  summary: 'SQL injection in Django',
  aliases: ['CVE-2020-7471'],
  database_specific: { severity: 'CRITICAL' },
  affected: [{ package: { name: 'Django', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '3.0' }, { fixed: '3.0.3' }] }] }],
};

let realFetch;
let queries;
beforeEach(() => {
  realFetch = globalThis.fetch;
  queries = [];
  globalThis.fetch = async (url, init = {}) => {
    const json = (status, body) => ({ ok: status < 400, status, json: async () => body, headers: new Map() });
    if (url.endsWith('/querybatch')) {
      const body = JSON.parse(init.body);
      queries.push(...body.queries);
      return json(200, {
        results: body.queries.map((q) => {
          const purl = q.package.purl || '';
          if (purl.startsWith('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1')) return { vulns: [{ id: LOG4SHELL.id }] };
          if (purl.startsWith('pkg:pypi/django@3.0')) return { vulns: [{ id: DJANGO.id }] };
          return {};
        }),
      });
    }
    if (url.includes('/vulns/')) {
      const id = decodeURIComponent(url.split('/vulns/')[1]);
      return json(200, { [LOG4SHELL.id]: LOG4SHELL, [DJANGO.id]: DJANGO }[id]);
    }
    if (url.includes('known_exploited')) {
      return json(200, { catalogVersion: 'test', vulnerabilities: [{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }] });
    }
    throw new Error(`unexpected ${url}`);
  };
});
afterEach(() => { globalThis.fetch = realFetch; });

test('queries OSV by purl and resolves fixes with each ecosystem naming', async () => {
  const parsed = readSbom(write(tmp(), 'bom.json', CDX));
  const result = await scanVulnerabilities(tmp(), { parsed });

  assert.ok(queries.every((q) => q.package.purl && !q.version && !q.package.ecosystem));
  assert.equal(result.scanned, 4);
  assert.deepEqual(result.ecosystems, ['golang', 'maven', 'pypi']);
  assert.deepEqual(result.input, { file: parsed.sourceFile, format: 'cyclonedx', unidentified: 1 });

  const log4j = result.vulnerabilities.find((v) => v.ecosystem === 'maven');
  assert.equal(log4j.kev, true);
  assert.equal(log4j.direct, true);
  assert.equal(log4j.purl, 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
  assert.deepEqual(log4j.fixAvailable, { name: 'org.apache.logging.log4j:log4j-core', version: '2.15.0', breaking: false });

  // PyPI names compare case-insensitively ("Django" in OSV, "django" in the purl).
  assert.equal(result.vulnerabilities.find((v) => v.ecosystem === 'pypi').fixAvailable.version, '3.0.3');

  const prod = await scanVulnerabilities(tmp(), { parsed, production: true });
  assert.equal(prod.scanned, 3); // the optional x/text is skipped
});

test('npm audit cannot scan an input SBOM', async () => {
  const parsed = readSbom(write(tmp(), 'bom.json', CDX));
  const result = await scanVulnerabilities(tmp(), { parsed, source: 'npm' });
  assert.equal(result.ok, false);
  assert.match(result.error, /cannot scan an input SBOM/);
});

test('audits an input SBOM without a package.json', async () => {
  const dir = tmp();
  const file = write(dir, 'bom.json', CDX);
  const report = await runAudit(dir, DEFAULT_POLICY, null, { input: file });

  assert.deepEqual(report.project, { name: 'billing', version: '1.4.0', sbom: file });
  assert.equal(report.sections.sbom.input, file);
  assert.equal(report.sections.licenses.summary.documented, 2);

  const labels = report.gate.reasons.map((r) => `${r.passed ? (r.warning ? '!' : '+') : '-'} ${r.label}`);
  assert.ok(labels.some((l) => /^- 1 component\(s\) with actively exploited/.test(l)));
  // TR-03183 gaps of a third-party SBOM warn instead of failing.
  assert.ok(labels.some((l) => /^! Input SBOM misses \d+ TR-03183-2/.test(l)));
});

test('VEX and SARIF use the purls and lines of the input SBOM', async () => {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, '.git'));
  const file = write(dir, 'bom.json', CDX);
  const report = await runAudit(dir, DEFAULT_POLICY, null, { input: file, only: 'vulnerabilities' });

  const vex = buildVex({ name: 'billing', version: '1.4.0', purl: 'pkg:maven/com.acme/billing@1.4.0' }, report.sections.vulnerabilities, {});
  assert.equal(vex.metadata.component.purl, 'pkg:maven/com.acme/billing@1.4.0');
  assert.deepEqual(vex.vulnerabilities.find((v) => v.id === 'CVE-2021-44228').affects, [{ ref: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' }]);

  const sarif = buildSarif(report, dir, {});
  const results = sarif.runs[0].results;
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (const result of results) {
    const loc = result.locations[0].physicalLocation;
    assert.equal(loc.artifactLocation.uri, 'bom.json');
    assert.ok(lines[loc.region.startLine - 1].includes('"purl"'), `line ${loc.region.startLine} holds a purl`);
  }
  const django = results.find((r) => r.message.text.includes('django'));
  assert.ok(lines[django.locations[0].physicalLocation.region.startLine - 1].includes('pkg:pypi/django@3.0'));
});
