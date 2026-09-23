'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { parseLockfile, parseIntegrity } = require('../src/core/lockfile-parser');
const { generateSbom } = require('../src/core/sbom-generator');
const { validateSbom } = require('../src/core/sbom-validator');
const { creatorFromManifest, repositoryUrl } = require('../src/core/installed-metadata');

const fixture = (name) => path.join(__dirname, 'fixtures', name);

const SHA512 = 'sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==';

/** Writes a throwaway project: { 'relative/path': string | object }. */
function makeProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  }
  return dir;
}

/** npm v3 project with node_modules installed, as after `npm ci`. */
function installedNpmProject() {
  return makeProject({
    'package.json': { name: 'shop', version: '2.1.0', author: 'Acme <security@acme.example>', license: 'MIT', dependencies: { widget: '^1.0.0' } },
    'package-lock.json': {
      name: 'shop',
      version: '2.1.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'shop', version: '2.1.0', dependencies: { widget: '^1.0.0' } },
        'node_modules/widget': {
          version: '1.0.2',
          resolved: 'https://registry.npmjs.org/widget/-/widget-1.0.2.tgz',
          integrity: SHA512,
          license: 'Apache-2.0',
          dependencies: { 'left-pad': '^1.3.0' },
        },
        'node_modules/left-pad': {
          version: '1.3.0',
          resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
          integrity: SHA512,
          license: 'WTFPL',
        },
      },
    },
    'node_modules/widget/package.json': { name: 'widget', version: '1.0.2', author: { name: 'Widget Co', email: 'dev@widget.example' } },
    'node_modules/left-pad/package.json': { name: 'left-pad', version: '1.3.0', repository: 'git+https://github.com/stevemao/left-pad.git' },
  });
}

// --- Dependency graph ------------------------------------------------------

for (const name of ['yarn-classic', 'yarn-berry', 'pnpm']) {
  test(`builds the dependency graph from ${name}`, () => {
    const parsed = parseLockfile(fixture(name));
    const widget = parsed.components.find((c) => c.name === '@scope/widget');
    assert.deepEqual(parsed.root.dependsOn, ['@scope/widget@1.0.2', 'left-pad@1.3.0']);
    assert.deepEqual(widget.dependsOn, ['left-pad@1.3.0']);
    assert.equal(parsed.dependencyGraphComplete, true);
  });
}

test('resolves npm v3 edges through nested node_modules', () => {
  const dir = makeProject({
    'package.json': { name: 'app', version: '1.0.0' },
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { a: '1', b: '1' } },
        'node_modules/a': { version: '1.0.0', dependencies: { c: '^2' } },
        'node_modules/a/node_modules/c': { version: '2.0.0' },
        'node_modules/b': { version: '1.0.0', dependencies: { c: '^1' } },
        'node_modules/c': { version: '1.0.0' },
      },
    },
  });
  const parsed = parseLockfile(dir);
  const byKey = Object.fromEntries(parsed.components.map((c) => [`${c.name}@${c.version}`, c.dependsOn]));
  assert.deepEqual(byKey['a@1.0.0'], ['c@2.0.0']);
  assert.deepEqual(byKey['b@1.0.0'], ['c@1.0.0']);
  assert.equal(parsed.dependencyGraphComplete, true);
});

test('resolves npm v1 `requires` against the nearest scope', () => {
  const dir = makeProject({
    'package.json': { name: 'app', version: '1.0.0', dependencies: { a: '1' } },
    'package-lock.json': {
      lockfileVersion: 1,
      dependencies: {
        a: { version: '1.0.0', requires: { c: '^2' }, dependencies: { c: { version: '2.0.0' } } },
        c: { version: '1.0.0' },
      },
    },
  });
  const parsed = parseLockfile(dir);
  assert.deepEqual(parsed.root.dependsOn, ['a@1.0.0']);
  assert.deepEqual(parsed.components.find((c) => c.name === 'a').dependsOn, ['c@2.0.0']);
});

test('flags the graph as incomplete when a dependency is missing', () => {
  const dir = makeProject({
    'package.json': { name: 'app', version: '1.0.0' },
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { a: '1' } },
        'node_modules/a': { version: '1.0.0', dependencies: { ghost: '1' }, optionalDependencies: { maybe: '1' } },
      },
    },
  });
  assert.equal(parseLockfile(dir).dependencyGraphComplete, false);
});

test('parses pnpm v6 peer suffixes and v5 slash keys', () => {
  const v6 = makeProject({
    'package.json': { name: 'app', version: '1.0.0' },
    'pnpm-lock.yaml': [
      "lockfileVersion: '6.0'",
      'dependencies:',
      '  react-dom:',
      '    specifier: ^18.0.0',
      '    version: 18.3.1(react@18.3.1)',
      '  react:',
      '    specifier: ^18.0.0',
      '    version: 18.3.1',
      'packages:',
      '  /react@18.3.1:',
      '    resolution: {integrity: sha512-abc}',
      '  /react-dom@18.3.1(react@18.3.1):',
      '    resolution: {integrity: sha512-abc}',
      '    dependencies:',
      '      react: 18.3.1',
    ].join('\n'),
  });
  const parsed = parseLockfile(v6);
  assert.deepEqual(parsed.root.dependsOn, ['react-dom@18.3.1', 'react@18.3.1']);
  assert.deepEqual(parsed.components.find((c) => c.name === 'react-dom').dependsOn, ['react@18.3.1']);

  const v5 = makeProject({
    'package.json': { name: 'app', version: '1.0.0' },
    'pnpm-lock.yaml': [
      'lockfileVersion: 5.4',
      'dependencies:',
      '  react-dom: 18.3.1_react@18.3.1',
      'packages:',
      '  /react-dom/18.3.1_react@18.3.1:',
      '    resolution: {integrity: sha512-abc}',
      '    dependencies:',
      '      react: 18.3.1',
      '  /react/18.3.1:',
      '    resolution: {integrity: sha512-abc}',
    ].join('\n'),
  });
  const parsed5 = parseLockfile(v5);
  assert.deepEqual(parsed5.components.map((c) => `${c.name}@${c.version}`), ['react@18.3.1', 'react-dom@18.3.1']);
  assert.deepEqual(parsed5.root.dependsOn, ['react-dom@18.3.1']);
});

test('drops integrity digests of the wrong length', () => {
  assert.equal(parseIntegrity(SHA512).algorithm, 'SHA-512');
  assert.deepEqual(parseIntegrity('sha512-abc='), { algorithm: null, hash: null });
});

// --- CycloneDX 1.6 / TR-03183-2 ------------------------------------------------

test('generates a CycloneDX 1.6 SBOM with the TR-03183-2 fields', () => {
  const { document } = generateSbom(installedNpmProject());

  assert.equal(document.specVersion, '1.6');
  assert.deepEqual(document.metadata.manufacturer, { name: 'Acme', contact: [{ email: 'security@acme.example' }] });

  const widget = document.components.find((c) => c.name === 'widget');
  assert.deepEqual(widget.manufacturer, { name: 'Widget Co', contact: [{ email: 'dev@widget.example' }] });
  assert.deepEqual(widget.licenses.map((l) => l.license.acknowledgement), ['declared', 'concluded']);
  const props = Object.fromEntries(widget.properties.map((p) => [p.name, p.value]));
  assert.equal(props['bsi:component:filename'], 'widget-1.0.2.tgz');
  assert.equal(props['bsi:component:archive'], 'archive');
  const dist = widget.externalReferences.find((r) => r.type === 'distribution');
  assert.equal(dist.hashes[0].alg, 'SHA-512');

  // Creator falls back to the repository URL when there is no email.
  const leftPad = document.components.find((c) => c.name === 'left-pad');
  assert.deepEqual(leftPad.manufacturer, { url: ['https://github.com/stevemao/left-pad'] });

  const graph = Object.fromEntries(document.dependencies.map((d) => [d.ref, d.dependsOn]));
  assert.deepEqual(graph['pkg:npm/shop@2.1.0'], ['pkg:npm/widget@1.0.2']);
  assert.deepEqual(graph['pkg:npm/widget@1.0.2'], ['pkg:npm/left-pad@1.3.0']);
  assert.deepEqual(graph['pkg:npm/left-pad@1.3.0'], []);
  assert.equal(document.compositions[0].aggregate, 'complete');

  const validation = validateSbom(document);
  assert.equal(validation.valid, true, JSON.stringify(validation.failedChecks));
});

test('the --creator option overrides the package.json author', () => {
  const { document } = generateSbom(installedNpmProject(), { creator: 'https://acme.example/security' });
  assert.deepEqual(document.metadata.manufacturer, { url: ['https://acme.example/security'] });
});

test('strips the Yarn sha1 fragment from the distribution URL', () => {
  const { document } = generateSbom(fixture('yarn-classic'));
  const leftPad = document.components.find((c) => c.name === 'left-pad');
  assert.equal(leftPad.externalReferences[0].url, 'https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz');
});

test('SPDX output declares DEPENDS_ON relationships', () => {
  const { document } = generateSbom(installedNpmProject(), { format: 'spdx' });
  const dependsOn = document.relationships.filter((r) => r.relationshipType === 'DEPENDS_ON');
  assert.equal(dependsOn.length, 2);
  assert.match(document.creationInfo.creators[0], /^Organization: Acme/);
});

// --- Validator ---------------------------------------------------------------

test('validator rejects CycloneDX < 1.6 and missing TR-03183 fields', () => {
  const { document } = generateSbom(fixture('yarn-classic'));
  document.specVersion = '1.5';
  const failed = validateSbom(document).failedChecks.map((c) => c.id);
  assert.ok(failed.includes('specVersion'));
  assert.ok(failed.includes('author')); // fixture package.json has no author
  assert.ok(failed.includes('componentCreators')); // nothing installed
  assert.ok(!failed.includes('dependencyGraph'));
});

test('validator flags components left out of the dependency graph', () => {
  const { document } = generateSbom(installedNpmProject());
  document.dependencies = document.dependencies.slice(0, 1);
  delete document.compositions;
  const failed = validateSbom(document).failedChecks.map((c) => c.id);
  assert.ok(failed.includes('dependencyGraph'));
  assert.ok(failed.includes('dependencyCompleteness'));
});

test('SPDX 2.3 is flagged: TR-03183-2 v2.1 requires SPDX >= 3.0.1', () => {
  const { document } = generateSbom(installedNpmProject(), { format: 'spdx' });
  const failed = validateSbom(document).failedChecks.map((c) => c.id);
  assert.deepEqual(failed, ['specVersion']);
});

// --- Installed metadata ------------------------------------------------------

test('derives creator contacts from npm person fields', () => {
  assert.deepEqual(creatorFromManifest({ author: 'Jane Doe <jane@x.example> (https://x.example)' }),
    { name: 'Jane Doe', email: 'jane@x.example', url: null });
  assert.deepEqual(creatorFromManifest({ author: 'Jane Doe', homepage: 'https://x.example' }),
    { name: 'Jane Doe', email: null, url: 'https://x.example' });
  assert.deepEqual(creatorFromManifest({ maintainers: [{ name: 'm', email: 'm@x.example' }] }),
    { name: 'm', email: 'm@x.example', url: null });
  assert.equal(creatorFromManifest({ author: 'Nobody' }), null);
});

test('normalizes repository URLs', () => {
  assert.equal(repositoryUrl('git+https://github.com/a/b.git'), 'https://github.com/a/b');
  assert.equal(repositoryUrl({ url: 'git@github.com:a/b.git' }), 'https://github.com/a/b');
  assert.equal(repositoryUrl('github:a/b'), 'https://github.com/a/b');
  assert.equal(repositoryUrl('a/b'), 'https://github.com/a/b');
  assert.equal(repositoryUrl('gitlab:a/b'), 'https://gitlab.com/a/b');
});
