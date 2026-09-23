'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readManifests, hasManifests } = require('../src/core/manifest-reader');
const { loadProject, findAnyProjectRoot } = require('../src/core/project-source');
const { runAudit } = require('../src/core/auditor');
const { DEFAULT_POLICY } = require('../src/core/policy');
const { buildSarif } = require('../src/reporters/sarif');

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-manifest-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

const keys = (parsed) => parsed.components.map((c) => c.key);
const byKey = (parsed, key) => parsed.components.find((c) => c.key === key);

// --- Python --------------------------------------------------------------------------

test('reads pinned requirements, following includes and skipping ranges', () => {
  const dir = project({
    'requirements.txt': [
      '# production',
      '-r requirements-base.txt',
      'Django==3.0 ; python_version >= "3.8"',
      'requests[socks]==2.19.0 \\',
      '    --hash=sha256:abc',
      'flask>=2.0',
      '-e git+https://example.com/pkg.git#egg=pkg',
      '--index-url https://pypi.org/simple',
    ].join('\n'),
    'requirements-base.txt': 'urllib3===1.24.1\n',
    'requirements-dev.txt': 'pytest==7.0.0\n',
  });
  const parsed = readManifests(dir);
  assert.deepEqual(keys(parsed), [
    'pkg:pypi/django@3.0', 'pkg:pypi/pytest@7.0.0', 'pkg:pypi/requests@2.19.0', 'pkg:pypi/urllib3@1.24.1',
  ]);
  assert.equal(parsed.unidentified, 1); // flask>=2.0 is not pinned
  assert.match(parsed.notes.join(), /1 requirement\(s\) without an exact == pin/);
  assert.deepEqual(byKey(parsed, 'pkg:pypi/django@3.0').location, { file: 'requirements.txt', line: 3 });
  assert.deepEqual(byKey(parsed, 'pkg:pypi/urllib3@1.24.1').location, { file: 'requirements-base.txt', line: 1 });
  assert.equal(byKey(parsed, 'pkg:pypi/pytest@7.0.0').optional, true); // requirements-dev.txt
});

test('prefers an exact Python lockfile over requirements', () => {
  const dir = project({
    'requirements.txt': 'django==1.0\n',
    'poetry.lock': [
      '[[package]]',
      'name = "Django"',
      'version = "3.0"',
      'description = "A web framework"',
      '',
      '[package.dependencies]',
      'sqlparse = ">=0.2.2"',
      '',
      '[[package]]',
      'name = "sqlparse"',
      'version = "0.4.1"',
      '',
      '[metadata]',
      'lock-version = "2.0"',
    ].join('\n'),
  });
  const parsed = readManifests(dir);
  assert.deepEqual(parsed.files, ['poetry.lock']);
  assert.deepEqual(keys(parsed), ['pkg:pypi/django@3.0', 'pkg:pypi/sqlparse@0.4.1']);
  assert.equal(byKey(parsed, 'pkg:pypi/sqlparse@0.4.1').location.line, 9);
});

test('reads uv.lock and skips the project itself', () => {
  const dir = project({
    'uv.lock': [
      'version = 1',
      '[[package]]',
      'name = "my-service"',
      'version = "2.1.0"',
      'source = { editable = "." }',
      'dependencies = [{ name = "jinja2" }]',
      '',
      '[[package]]',
      'name = "jinja2"',
      'version = "2.4.1"',
      'source = { registry = "https://pypi.org/simple" }',
    ].join('\n'),
  });
  const parsed = readManifests(dir);
  assert.deepEqual(keys(parsed), ['pkg:pypi/jinja2@2.4.1']);
  assert.deepEqual([parsed.root.name, parsed.root.version], ['my-service', '2.1.0']);
});

test('reads Pipfile.lock default and develop groups', () => {
  const dir = project({
    'Pipfile.lock': JSON.stringify({
      _meta: {},
      default: { requests: { version: '==2.19.0' } },
      develop: { pytest: { version: '==7.0.0' } },
    }, null, 2),
  });
  const parsed = readManifests(dir);
  assert.deepEqual(keys(parsed), ['pkg:pypi/pytest@7.0.0', 'pkg:pypi/requests@2.19.0']);
  assert.equal(byKey(parsed, 'pkg:pypi/pytest@7.0.0').optional, true);
});

// --- Go ----------------------------------------------------------------------------------

test('reads go.mod requires and applies replace directives', () => {
  const dir = project({
    'go.mod': [
      'module example.com/team/svc',
      '',
      'go 1.21',
      '',
      'require github.com/gin-gonic/gin v1.6.0',
      '',
      'require (',
      '\tgolang.org/x/text v0.3.5 // indirect',
      '\tgithub.com/old/lib v1.0.0 // pinned for reasons',
      ')',
      '',
      'replace github.com/old/lib => github.com/new/lib v1.2.3',
    ].join('\n'),
  });
  const parsed = readManifests(dir);
  assert.deepEqual(keys(parsed), [
    'pkg:golang/github.com/gin-gonic/gin@v1.6.0', 'pkg:golang/github.com/new/lib@v1.2.3', 'pkg:golang/golang.org/x/text@v0.3.5',
  ]);
  assert.equal(byKey(parsed, 'pkg:golang/golang.org/x/text@v0.3.5').direct, false);
  assert.equal(byKey(parsed, 'pkg:golang/github.com/gin-gonic/gin@v1.6.0').location.line, 5);
  assert.equal(parsed.root.name, 'svc');
});

// --- Java ----------------------------------------------------------------------------------

test('reads pom.xml with properties, dependencyManagement and scopes', () => {
  const pom = `<project>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>9.9.9</version></parent>
  <artifactId>billing</artifactId>
  <version>1.4.0</version>
  <properties>
    <log4j.version>2.14.1</log4j.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.9.8</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>\${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>shared</artifactId>
      <version>\${project.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
    <!-- <dependency><groupId>x</groupId><artifactId>commented</artifactId><version>1</version></dependency> -->
    <dependency>
      <groupId>org.from</groupId>
      <artifactId>parent-bom</artifactId>
    </dependency>
    <dependency>
      <groupId>org.range</groupId>
      <artifactId>ranged</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
  </dependencies>
</project>`;
  const parsed = readManifests(project({ 'pom.xml': pom }));
  assert.deepEqual(keys(parsed), [
    'pkg:maven/com.acme/shared@1.4.0',
    'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8',
    'pkg:maven/junit/junit@4.12',
    'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
  ]);
  const log4j = byKey(parsed, 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
  assert.equal(log4j.name, 'org.apache.logging.log4j:log4j-core');
  assert.equal(log4j.location.line, 20); // the <artifactId> line
  assert.equal(byKey(parsed, 'pkg:maven/junit/junit@4.12').optional, true);
  assert.equal(parsed.unidentified, 2); // parent-managed version and a range
  assert.match(parsed.notes.join(), /declared dependencies only/);
  assert.deepEqual([parsed.root.name, parsed.root.version], ['billing', '1.4.0']);
});

test('reads gradle.lockfile', () => {
  const parsed = readManifests(project({
    'gradle.lockfile': [
      '# This is a Gradle generated file',
      'org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath',
      'junit:junit:4.12=testCompileClasspath,testRuntimeClasspath',
      'empty=annotationProcessor',
    ].join('\n'),
  }));
  assert.deepEqual(keys(parsed), ['pkg:maven/junit/junit@4.12', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1']);
  assert.equal(byKey(parsed, 'pkg:maven/junit/junit@4.12').optional, true);
});

// --- Project detection -----------------------------------------------------------------------

test('detects projects without a package.json and mixes ecosystems', () => {
  const py = project({ 'svc/requirements.txt': 'django==3.0\n', 'svc/app/main.py': '' });
  assert.equal(hasManifests(path.join(py, 'svc')), true);
  assert.equal(findAnyProjectRoot(path.join(py, 'svc', 'app')), path.join(py, 'svc'));
  assert.equal(loadProject(path.join(py, 'svc')).mode, 'manifest');

  const mixed = project({
    'package.json': JSON.stringify({ name: 'web', version: '1.0.0' }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' } } }),
    'go.mod': 'module example.com/api\n\nrequire golang.org/x/text v0.3.5\n',
  });
  const loaded = loadProject(mixed);
  assert.equal(loaded.mode, 'npm+manifest');
  assert.deepEqual(loaded.parsed.components.map((c) => c.key || c.name).sort(), ['lodash', 'pkg:golang/golang.org/x/text@v0.3.5']);
});

// --- End to end (OSV/KEV mocked) ---------------------------------------------------------------

let realFetch;
beforeEach(() => {
  realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const json = (status, body) => ({ ok: status < 400, status, json: async () => body, headers: new Map() });
    if (url.endsWith('/querybatch')) {
      const { queries } = JSON.parse(init.body);
      return json(200, { results: queries.map((q) => ((q.package.purl || '').includes('log4j-core@2.14.1') ? { vulns: [{ id: 'GHSA-jfh8-c2jp-5v3q' }] } : {})) });
    }
    if (url.includes('/vulns/')) {
      return json(200, {
        id: 'GHSA-jfh8-c2jp-5v3q', summary: 'Remote code injection in Log4j', aliases: ['CVE-2021-44228'],
        database_specific: { severity: 'CRITICAL' },
        affected: [{ package: { name: 'org.apache.logging.log4j:log4j-core' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.13.0' }, { fixed: '2.15.0' }] }] }],
      });
    }
    if (url.includes('known_exploited')) return json(200, { vulnerabilities: [{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }] });
    throw new Error(`unexpected ${url}`);
  };
});
afterEach(() => { globalThis.fetch = realFetch; });

test('audits a Maven project straight from pom.xml, with SARIF on the pom line', async () => {
  const dir = project({
    '.git/HEAD': '',
    'pom.xml': '<project>\n  <artifactId>billing</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n    </dependency>\n  </dependencies>\n</project>\n',
  });
  const report = await runAudit(dir, DEFAULT_POLICY, null);

  assert.deepEqual(report.project, { name: 'billing', version: '1.0.0', manifests: ['pom.xml'] });
  const vulns = report.sections.vulnerabilities;
  assert.equal(vulns.input.format, 'manifest');
  assert.equal(vulns.vulnerabilities[0].kev, true);
  assert.deepEqual(vulns.vulnerabilities[0].fixAvailable, { name: 'org.apache.logging.log4j:log4j-core', version: '2.15.0', breaking: false });

  const labels = report.gate.reasons.map((r) => `${r.passed ? (r.warning ? '!' : '+') : '-'} ${r.label}`);
  assert.ok(labels.some((l) => /^- 1 component\(s\) with actively exploited/.test(l)));
  assert.ok(labels.some((l) => /^! No SBOM generated for maven/.test(l)));
  assert.ok(labels.some((l) => /^! Licenses are not declared in pom\.xml/.test(l)));

  const result = buildSarif(report, dir, {}).runs[0].results[0];
  assert.deepEqual(result.locations[0].physicalLocation.artifactLocation, { uri: 'pom.xml', uriBaseId: '%SRCROOT%' });
  assert.equal(result.locations[0].physicalLocation.region.startLine, 7);
});
