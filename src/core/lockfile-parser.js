'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readJson, exists } = require('../utils/fs');
const { parseYaml } = require('../utils/yaml');

/**
 * Detection order: npm lockfiles take precedence (they carry the richest
 * metadata and let `npm audit` run natively), followed by Yarn (classic v1
 * and Berry v2+) and pnpm.
 */
const LOCKFILES = [
  { name: 'package-lock.json', manager: 'npm' },
  { name: 'npm-shrinkwrap.json', manager: 'npm' },
  { name: 'yarn.lock', manager: 'yarn' },
  { name: 'pnpm-lock.yaml', manager: 'pnpm' },
];

/**
 * Parses the project lockfile (npm `package-lock.json`/`npm-shrinkwrap.json`,
 * Yarn `yarn.lock` classic or Berry, or pnpm `pnpm-lock.yaml`) into a
 * normalized list of components. CRA / TR-03183 require traceability of every
 * direct and transitive dependency, including integrity hashes.
 *
 * @param {string} projectRoot
 * @returns {{
 *   ok: boolean,
 *   manager: 'npm'|'yarn'|'pnpm'|null,
 *   lockfileName: string|null,
 *   lockfileVersion: number|string|null,
 *   root: { name: string, version: string },
 *   components: Array<object>,
 *   error?: string
 * }}
 */
function parseLockfile(projectRoot) {
  let lockPath = null;
  let lockfileName = null;
  let manager = null;

  for (const candidate of LOCKFILES) {
    const full = path.join(projectRoot, candidate.name);
    if (exists(full)) {
      lockPath = full;
      lockfileName = candidate.name;
      manager = candidate.manager;
      break;
    }
  }

  const pkgPath = path.join(projectRoot, 'package.json');
  const rootPkg = readJson(pkgPath) || {};
  const root = {
    name: rootPkg.name || path.basename(projectRoot),
    version: rootPkg.version || '0.0.0',
  };

  if (!lockPath) {
    return {
      ok: false,
      manager: null,
      lockfileName: null,
      lockfileVersion: null,
      root,
      components: [],
      error:
        'No lockfile found (package-lock.json, npm-shrinkwrap.json, ' +
        'yarn.lock or pnpm-lock.yaml). The CRA requires deterministic dependency ' +
        'traceability: run `npm install` (or `yarn` / `pnpm install`) to generate the lockfile.',
    };
  }

  try {
    if (manager === 'npm') return parseNpmLock(lockPath, lockfileName, root);
    if (manager === 'yarn') return parseYarnLock(lockPath, lockfileName, root);
    if (manager === 'pnpm') return parsePnpmLock(lockPath, lockfileName, root);
  } catch (err) {
    return {
      ok: false,
      manager,
      lockfileName,
      lockfileVersion: null,
      root,
      components: [],
      error: `Could not parse ${lockfileName}: ${err.message}`,
    };
  }

  return { ok: true, manager, lockfileName, lockfileVersion: null, root, components: [] };
}

/** npm: package-lock.json (v1/v2/v3) or npm-shrinkwrap.json. */
function parseNpmLock(lockPath, lockfileName, root) {
  const lock = readJson(lockPath);
  const lockfileVersion = lock.lockfileVersion || 1;

  let components;
  if (lock.packages) {
    components = parsePackagesField(lock.packages);
  } else if (lock.dependencies) {
    components = parseDependenciesField(lock.dependencies);
  } else {
    components = [];
  }

  return { ok: true, manager: 'npm', lockfileName, lockfileVersion, root, components };
}

/** Lockfile v2/v3 store everything under the `packages` map keyed by path. */
function parsePackagesField(packages) {
  const components = [];

  for (const [pkgPath, info] of Object.entries(packages)) {
    // The root project is stored under the empty key.
    if (pkgPath === '') continue;
    if (info.link) continue; // local symlinked workspace, not a third-party artifact

    const name = info.name || nameFromPath(pkgPath);
    if (!name) continue;

    components.push(normalizeComponent({
      name,
      version: info.version,
      resolved: info.resolved,
      integrity: info.integrity,
      license: info.license,
      dev: Boolean(info.dev),
      optional: Boolean(info.optional),
      path: pkgPath,
    }));
  }

  return dedupe(components);
}

/** Lockfile v1 nests dependencies recursively under `dependencies`. */
function parseDependenciesField(dependencies, acc = []) {
  for (const [name, info] of Object.entries(dependencies)) {
    acc.push(normalizeComponent({
      name,
      version: info.version,
      resolved: info.resolved,
      integrity: info.integrity,
      license: info.license,
      dev: Boolean(info.dev),
      optional: Boolean(info.optional),
      path: `node_modules/${name}`,
    }));
    if (info.dependencies) {
      parseDependenciesField(info.dependencies, acc);
    }
  }
  return dedupe(acc);
}

function nameFromPath(pkgPath) {
  const idx = pkgPath.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  return pkgPath.slice(idx + 'node_modules/'.length);
}

// --- Yarn ------------------------------------------------------------------

/** Yarn: dispatches between the classic v1 text format and Berry's YAML. */
function parseYarnLock(lockPath, lockfileName, root) {
  const content = fs.readFileSync(lockPath, 'utf8');
  const isBerry = /^__metadata:/m.test(content) || /\n {2}resolution:/.test(content);
  const components = isBerry ? parseYarnBerry(content) : parseYarnClassic(content);
  return {
    ok: true,
    manager: 'yarn',
    lockfileName,
    lockfileVersion: isBerry ? 'berry' : 1,
    root,
    components: dedupe(components),
  };
}

/**
 * Yarn classic (v1) lockfiles use a custom, non-YAML text format: a block per
 * resolved entry whose header lists one or more `name@range` descriptors.
 */
function parseYarnClassic(content) {
  const components = [];
  const blocks = content.split(/\r?\n(?=\S)/);

  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    const header = lines[0];
    if (!header || header.startsWith('#') || !header.trim().endsWith(':')) continue;

    const descriptors = header.replace(/:\s*$/, '').split(',').map((d) => stripQuotes(d.trim()));
    const name = packageNameFromDescriptor(descriptors[0]);
    if (!name) continue;

    let version = null;
    let resolved = null;
    let integrity = null;
    for (const raw of lines.slice(1)) {
      const line = raw.trim();
      if (line.startsWith('version ')) version = stripQuotes(line.slice('version '.length).trim());
      else if (line.startsWith('resolved ')) resolved = stripQuotes(line.slice('resolved '.length).trim());
      else if (line.startsWith('integrity ')) integrity = stripQuotes(line.slice('integrity '.length).trim());
    }
    if (!version) continue;

    components.push(normalizeComponent({ name, version, resolved, integrity, path: `node_modules/${name}` }));
  }
  return components;
}

/** Yarn Berry (v2+) lockfiles are YAML keyed by descriptor lists. */
function parseYarnBerry(content) {
  const doc = parseYaml(content) || {};
  const components = [];

  for (const [key, info] of Object.entries(doc)) {
    if (key === '__metadata' || !info || typeof info !== 'object') continue;
    if (!info.version) continue;

    const resolution = typeof info.resolution === 'string' ? info.resolution : '';
    const name = packageNameFromDescriptor(resolution || String(key).split(',')[0].trim());
    if (!name) continue;

    components.push(normalizeComponent({
      name,
      version: info.version,
      // Berry's `checksum` is a cache key, not an npm SRI hash, so we omit it.
      integrity: null,
      path: `node_modules/${name}`,
    }));
  }
  return components;
}

// --- pnpm ------------------------------------------------------------------

/** pnpm: `pnpm-lock.yaml` (lockfileVersion 5.x / 6.x / 9.x). */
function parsePnpmLock(lockPath, lockfileName, root) {
  const doc = parseYaml(fs.readFileSync(lockPath, 'utf8')) || {};
  const packages = doc.packages && typeof doc.packages === 'object' ? doc.packages : {};
  const components = [];

  for (const [key, info] of Object.entries(packages)) {
    const parsed = packageKeyToNameVersion(key);
    if (!parsed) continue;
    const resolution = info && typeof info === 'object' ? info.resolution : null;
    const integrity = resolution && typeof resolution === 'object' ? resolution.integrity || null : null;
    components.push(normalizeComponent({
      name: parsed.name,
      version: parsed.version,
      integrity,
      path: `node_modules/${parsed.name}`,
    }));
  }

  return {
    ok: true,
    manager: 'pnpm',
    lockfileName,
    lockfileVersion: doc.lockfileVersion || null,
    root,
    components: dedupe(components),
  };
}

/**
 * Extracts a package name from a Yarn/pnpm descriptor or resolution string,
 * e.g. `lodash@^4.17.21`, `@babel/core@npm:7.0.0`, `left-pad@1.3.0`.
 */
function packageNameFromDescriptor(descriptor) {
  if (!descriptor) return null;
  let d = stripQuotes(String(descriptor).trim());
  // Drop a protocol/range part: take everything before the version separator.
  const scoped = d.startsWith('@');
  const at = d.indexOf('@', scoped ? 1 : 0);
  return at === -1 ? d : d.slice(0, at);
}

/**
 * Splits a pnpm package map key into { name, version }. Handles the historical
 * variants: `/lodash/4.17.21`, `/lodash@4.17.21`, `lodash@4.17.21` and peer
 * suffixes like `@babel/core@7.0.0(react@18.0.0)`.
 */
function packageKeyToNameVersion(key) {
  let k = stripQuotes(String(key).trim());
  if (!k) return null;
  // Strip peer-dependency suffix: name@version(peer@x)(...).
  const peerIdx = k.indexOf('(');
  if (peerIdx !== -1) k = k.slice(0, peerIdx);

  if (k.startsWith('/')) {
    k = k.slice(1);
    // v5 uses `/` as separator: name/version (scoped: @scope/name/version).
    if (!k.includes('@', k.startsWith('@') ? 1 : 0) && k.includes('/')) {
      const idx = k.lastIndexOf('/');
      return { name: k.slice(0, idx), version: k.slice(idx + 1) };
    }
  }

  const scoped = k.startsWith('@');
  const at = k.lastIndexOf('@');
  if (at <= 0) return null;
  if (scoped && at === 0) return null;
  const name = k.slice(0, at);
  const version = k.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}

function stripQuotes(value) {
  if (typeof value !== 'string') return value;
  const t = value.trim();
  if (t.length >= 2 && ((t[0] === '"' && t[t.length - 1] === '"') || (t[0] === "'" && t[t.length - 1] === "'"))) {
    return t.slice(1, -1);
  }
  return t;
}

function normalizeComponent(raw) {
  const { algorithm, hash } = parseIntegrity(raw.integrity);
  return {
    name: raw.name,
    version: raw.version || null,
    purl: buildPurl(raw.name, raw.version),
    resolved: raw.resolved || null,
    integrity: raw.integrity || null,
    hashAlgorithm: algorithm,
    hashValue: hash,
    license: raw.license || null,
    scope: raw.dev ? 'optional' : 'required',
    dev: Boolean(raw.dev),
    optional: Boolean(raw.optional),
    path: raw.path,
  };
}

/**
 * Parses an npm Subresource Integrity string ("sha512-<base64>")
 * into a CycloneDX-friendly { algorithm, hash } pair.
 */
function parseIntegrity(integrity) {
  if (!integrity || typeof integrity !== 'string') {
    return { algorithm: null, hash: null };
  }
  const [algo, b64] = integrity.split('-');
  if (!algo || !b64) return { algorithm: null, hash: null };

  const map = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256', sha1: 'SHA-1' };
  const algorithm = map[algo.toLowerCase()] || null;
  if (!algorithm) return { algorithm: null, hash: null };

  let hex;
  try {
    hex = Buffer.from(b64, 'base64').toString('hex');
  } catch {
    hex = null;
  }
  return { algorithm, hash: hex };
}

/** Builds a Package URL (purl) per the npm purl-spec. */
function buildPurl(name, version) {
  if (!name) return null;
  let purl = 'pkg:npm/';
  if (name.startsWith('@')) {
    const [scope, pkg] = name.split('/');
    purl += `${encodeURIComponent(scope)}/${encodeURIComponent(pkg)}`;
  } else {
    purl += encodeURIComponent(name);
  }
  if (version) purl += `@${version}`;
  return purl;
}

function dedupe(components) {
  const seen = new Map();
  for (const comp of components) {
    const key = `${comp.name}@${comp.version}`;
    if (!seen.has(key)) {
      seen.set(key, comp);
    }
  }
  return Array.from(seen.values()).sort((a, b) =>
    a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version))
  );
}

/**
 * Builds a synthetic npm `package-lock.json` (v3) and matching `package.json`
 * from a parsed lockfile, so that `npm audit --package-lock-only` can scan a
 * Yarn/pnpm project without an npm lockfile. The exact versions resolved by
 * Yarn/pnpm are preserved; duplicate versions of a package are nested so each
 * is present in the tree the auditor inspects.
 *
 * @param {{ root: {name:string, version:string}, components: Array<object> }} parsed
 * @returns {{ packageJson: object, packageLock: object }}
 */
function toNpmLockfile(parsed) {
  const packages = { '': { name: parsed.root.name, version: parsed.root.version } };
  const rootDeps = {};
  const placed = new Map();

  for (const c of parsed.components) {
    if (!c.name || !c.version) continue;
    const count = placed.get(c.name) || 0;
    placed.set(c.name, count + 1);

    let key;
    if (count === 0) {
      key = `node_modules/${c.name}`;
      rootDeps[c.name] = c.version;
    } else {
      key = `node_modules/${c.name}` + `/node_modules/${c.name}`.repeat(count);
    }

    const entry = { version: c.version };
    if (c.resolved) entry.resolved = c.resolved;
    if (c.integrity) entry.integrity = c.integrity;
    if (c.license) entry.license = c.license;
    packages[key] = entry;
  }

  packages[''].dependencies = rootDeps;

  return {
    packageJson: { name: parsed.root.name, version: parsed.root.version, dependencies: rootDeps },
    packageLock: {
      name: parsed.root.name,
      version: parsed.root.version,
      lockfileVersion: 3,
      requires: true,
      packages,
    },
  };
}

module.exports = { parseLockfile, buildPurl, parseIntegrity, toNpmLockfile };
