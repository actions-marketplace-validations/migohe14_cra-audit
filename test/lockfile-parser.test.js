'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { parseLockfile, toNpmLockfile } = require('../src/core/lockfile-parser');
const { parseYaml } = require('../src/utils/yaml');

const fixture = (name) => path.join(__dirname, 'fixtures', name);

function byName(components) {
  return Object.fromEntries(components.map((c) => [c.name, c]));
}

test('parses an npm package-lock.json (v3)', () => {
  const parsed = parseLockfile(fixture('demo-app'));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.manager, 'npm');
  const map = byName(parsed.components);
  assert.equal(map['left-pad'].version, '1.3.0');
  assert.equal(map['left-pad'].license, 'WTFPL');
  assert.ok(map['mystery-lib']);
});

test('parses a classic Yarn v1 lockfile with exact versions', () => {
  const parsed = parseLockfile(fixture('yarn-classic'));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.manager, 'yarn');
  assert.equal(parsed.lockfileVersion, 1);
  const map = byName(parsed.components);
  assert.equal(map['left-pad'].version, '1.3.0');
  assert.equal(map['@scope/widget'].version, '1.0.2');
  // SRI integrity is preserved and decoded into a hash.
  assert.equal(map['left-pad'].hashAlgorithm, 'SHA-512');
  assert.ok(map['left-pad'].hashValue);
  assert.equal(map['left-pad'].purl, 'pkg:npm/left-pad@1.3.0');
});

test('parses a Yarn Berry (v2+) lockfile', () => {
  const parsed = parseLockfile(fixture('yarn-berry'));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.manager, 'yarn');
  assert.equal(parsed.lockfileVersion, 'berry');
  const map = byName(parsed.components);
  assert.equal(map['left-pad'].version, '1.3.0');
  assert.equal(map['@scope/widget'].version, '1.0.2');
  // Berry checksums are cache keys, not npm SRI hashes, so integrity stays null.
  assert.equal(map['left-pad'].integrity, null);
});

test('parses a pnpm-lock.yaml (v9) with integrity hashes', () => {
  const parsed = parseLockfile(fixture('pnpm'));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.manager, 'pnpm');
  const map = byName(parsed.components);
  assert.equal(map['left-pad'].version, '1.3.0');
  assert.equal(map['@scope/widget'].version, '1.0.2');
  assert.equal(map['left-pad'].hashAlgorithm, 'SHA-512');
  assert.ok(map['left-pad'].hashValue);
});

test('synthesizes a valid npm lockfile from a parsed Yarn project', () => {
  const parsed = parseLockfile(fixture('yarn-classic'));
  const { packageJson, packageLock } = toNpmLockfile(parsed);

  assert.equal(packageLock.lockfileVersion, 3);
  assert.equal(packageLock.packages[''].name, 'yarn-classic-app');
  assert.equal(packageLock.packages['node_modules/left-pad'].version, '1.3.0');
  assert.equal(packageLock.packages['node_modules/@scope/widget'].version, '1.0.2');
  assert.equal(packageJson.dependencies['left-pad'], '1.3.0');
});

test('synthetic lockfile nests duplicate versions under unique paths', () => {
  const parsed = {
    root: { name: 'dup', version: '1.0.0' },
    components: [
      { name: 'a', version: '1.0.0' },
      { name: 'a', version: '2.0.0' },
      { name: 'a', version: '3.0.0' },
    ],
  };
  const { packageLock } = toNpmLockfile(parsed);
  const keys = Object.keys(packageLock.packages).filter((k) => k.includes('node_modules/a'));
  assert.equal(new Set(keys).size, keys.length); // all unique
  assert.equal(keys.length, 3);
});

test('minimal YAML parser handles nested maps and inline flow collections', () => {
  const doc = parseYaml([
    "lockfileVersion: '9.0'",
    'packages:',
    '  left-pad@1.3.0:',
    '    resolution: {integrity: sha512-abc==}',
    '    engines: {node: \'>=10\'}',
    "  '@scope/widget@1.0.2': {}",
  ].join('\n'));

  assert.equal(doc.lockfileVersion, '9.0');
  assert.equal(doc.packages['left-pad@1.3.0'].resolution.integrity, 'sha512-abc==');
  assert.equal(doc.packages['left-pad@1.3.0'].engines.node, '>=10');
  assert.deepEqual(doc.packages['@scope/widget@1.0.2'], {});
});

test('reports a clear error when no lockfile is present', () => {
  const parsed = parseLockfile(path.join(__dirname, 'fixtures'));
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /yarn\.lock|pnpm-lock\.yaml/);
});
