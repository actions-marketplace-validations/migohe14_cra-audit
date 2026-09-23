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
 *   root: { name: string, version: string, dependsOn: string[] },
 *   components: Array<object>,
 *   dependencyGraphComplete: boolean,
 *   error?: string
 * }}
 *
 * Every component carries `dependsOn`: the `name@version` keys of the
 * components it directly depends on (TR-03183 §5.2.2 "Dependencies on other
 * components"). `root.dependsOn` lists the project's direct dependencies.
 * `dependencyGraphComplete` is false when a required dependency could not be
 * resolved in the lockfile, so the SBOM can declare the graph as incomplete.
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
    dependsOn: [],
  };

  if (!lockPath) {
    return {
      ok: false,
      manager: null,
      lockfileName: null,
      lockfileVersion: null,
      root,
      components: [],
      dependencyGraphComplete: false,
      error:
        'No lockfile found (package-lock.json, npm-shrinkwrap.json, ' +
        'yarn.lock or pnpm-lock.yaml). The CRA requires deterministic dependency ' +
        'traceability: run `npm install` (or `yarn` / `pnpm install`) to generate the lockfile.',
    };
  }

  try {
    let result = null;
    if (manager === 'npm') result = parseNpmLock(lockPath, rootPkg);
    else if (manager === 'yarn') result = parseYarnLock(lockPath, rootPkg);
    else if (manager === 'pnpm') result = parsePnpmLock(lockPath);

    root.dependsOn = uniqueSorted(result.rootDependsOn);
    return {
      ok: true,
      manager,
      lockfileName,
      lockfileVersion: result.lockfileVersion,
      root,
      components: dedupe(result.components),
      dependencyGraphComplete: result.complete,
    };
  } catch (err) {
    return {
      ok: false,
      manager,
      lockfileName,
      lockfileVersion: null,
      root,
      components: [],
      dependencyGraphComplete: false,
      error: `Could not parse ${lockfileName}: ${err.message}`,
    };
  }
}

/**
 * Marker returned by resolvers for dependencies that point to a local
 * workspace/link: they are first-party code, not an unresolved dependency.
 */
const LINK = Symbol('link');

/** npm: package-lock.json (v1/v2/v3) or npm-shrinkwrap.json. */
function parseNpmLock(lockPath, rootPkg) {
  const lock = readJson(lockPath);
  const lockfileVersion = lock.lockfileVersion || 1;

  if (lock.packages) {
    return { lockfileVersion, ...parsePackagesField(lock.packages) };
  }
  if (lock.dependencies) {
    return { lockfileVersion, ...parseDependenciesField(lock.dependencies, rootPkg) };
  }
  return { lockfileVersion, components: [], rootDependsOn: [], complete: true };
}

/** Lockfile v2/v3 store everything under the `packages` map keyed by path. */
function parsePackagesField(packages) {
  const components = [];
  let complete = true;

  // Node's module resolution: look in `<from>/node_modules/<dep>`, then walk
  // up through every enclosing node_modules folder until the project root.
  const resolve = (fromPath, depName) => {
    let base = fromPath;
    for (;;) {
      const info = packages[`${base ? `${base}/` : ''}node_modules/${depName}`];
      if (info) {
        if (info.link) return LINK;
        return componentKey(info.name || depName, info.version);
      }
      if (!base) return null;
      const idx = base.lastIndexOf('/node_modules/');
      base = idx === -1 ? '' : base.slice(0, idx);
    }
  };

  const edges = (fromPath, info, includeDev) => {
    const optional = new Set([
      ...Object.keys(info.optionalDependencies || {}),
      ...Object.keys(info.peerDependencies || {}),
    ]);
    const names = new Set([
      ...Object.keys(info.dependencies || {}),
      ...optional,
      ...(includeDev ? Object.keys(info.devDependencies || {}) : []),
    ]);
    const dependsOn = [];
    for (const depName of names) {
      const ref = resolve(fromPath, depName);
      if (ref === LINK) continue;
      if (ref) dependsOn.push(ref);
      else if (!optional.has(depName)) complete = false;
    }
    return dependsOn;
  };

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
      dependsOn: edges(pkgPath, info, false),
    }));
  }

  const rootDependsOn = packages[''] ? edges('', packages[''], true) : [];
  return { components, rootDependsOn, complete };
}

/**
 * Lockfile v1 nests dependencies recursively under `dependencies`; each entry
 * lists what it needs under `requires`, resolved against the nearest scope.
 */
function parseDependenciesField(dependencies, rootPkg) {
  const components = [];
  let complete = true;

  const lookup = (scopes, name) => {
    for (const scope of scopes) {
      if (scope[name]) return scope[name];
    }
    return null;
  };

  const walk = (deps, outerScopes, prefix) => {
    const scopes = [deps, ...outerScopes];
    for (const [name, info] of Object.entries(deps)) {
      const ownScopes = info.dependencies ? [info.dependencies, ...scopes] : scopes;
      const dependsOn = [];
      for (const req of Object.keys(info.requires || {})) {
        const found = lookup(ownScopes, req);
        if (found) dependsOn.push(componentKey(req, found.version));
        else complete = false;
      }

      const pkgPath = `${prefix}node_modules/${name}`;
      components.push(normalizeComponent({
        name,
        version: info.version,
        resolved: info.resolved,
        integrity: info.integrity,
        license: info.license,
        dev: Boolean(info.dev),
        optional: Boolean(info.optional),
        path: pkgPath,
        dependsOn,
      }));
      if (info.dependencies) walk(info.dependencies, scopes, `${pkgPath}/`);
    }
  };
  walk(dependencies, [], '');

  const rootDependsOn = [];
  for (const { name, optional } of rootDependencies(rootPkg)) {
    const found = dependencies[name];
    if (found) rootDependsOn.push(componentKey(name, found.version));
    else if (!optional) complete = false;
  }
  return { components, rootDependsOn, complete };
}

/**
 * Direct dependencies declared in the project's package.json, including
 * dev and optional ones, with the range each was requested with.
 */
function rootDependencies(rootPkg) {
  const list = [];
  const add = (map, optional) => {
    for (const [name, range] of Object.entries(map || {})) {
      list.push({ name, range: String(range), optional });
    }
  };
  add(rootPkg.dependencies, false);
  add(rootPkg.devDependencies, false);
  add(rootPkg.optionalDependencies, true);
  return list;
}

function nameFromPath(pkgPath) {
  const idx = pkgPath.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  return pkgPath.slice(idx + 'node_modules/'.length);
}

// --- Yarn ------------------------------------------------------------------

/** Yarn: dispatches between the classic v1 text format and Berry's YAML. */
function parseYarnLock(lockPath, rootPkg) {
  const content = fs.readFileSync(lockPath, 'utf8');
  const isBerry = /^__metadata:/m.test(content) || /\n {2}resolution:/.test(content);
  const entries = isBerry ? parseYarnBerry(content) : parseYarnClassic(content);

  // Both formats key entries by the `name@range` descriptors that resolved
  // to them, so edges are resolved by looking descriptors up.
  const byDescriptor = new Map();
  for (const entry of entries) {
    for (const descriptor of entry.descriptors) {
      byDescriptor.set(descriptor, entry.workspace ? LINK : componentKey(entry.name, entry.version));
    }
  }

  let complete = true;
  const resolve = (name, range, optional) => {
    const ref = byDescriptor.get(`${name}@${range}`) ||
      (!range.includes(':') ? byDescriptor.get(`${name}@npm:${range}`) : undefined);
    if (ref === LINK) return null;
    if (ref) return ref;
    // Local protocols never appear as third-party lockfile entries.
    if (!optional && !/^(workspace|link|portal|file):/.test(range)) complete = false;
    return null;
  };

  const components = [];
  for (const entry of entries) {
    if (entry.workspace) continue; // first-party workspace, not a third-party component
    const dependsOn = entry.dependencies
      .map((d) => resolve(d.name, d.range, d.optional))
      .filter(Boolean);
    components.push(normalizeComponent({
      name: entry.name,
      version: entry.version,
      resolved: entry.resolved,
      integrity: entry.integrity,
      path: `node_modules/${entry.name}`,
      dependsOn,
    }));
  }

  const rootDependsOn = rootDependencies(rootPkg)
    .map((d) => resolve(d.name, d.range, d.optional))
    .filter(Boolean);

  return { lockfileVersion: isBerry ? 'berry' : 1, components, rootDependsOn, complete };
}

/**
 * Yarn classic (v1) lockfiles use a custom, non-YAML text format: a block per
 * resolved entry whose header lists one or more `name@range` descriptors.
 */
function parseYarnClassic(content) {
  const entries = [];
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
    let section = null;
    const dependencies = [];
    for (const raw of lines.slice(1)) {
      const line = raw.trim();
      const indent = raw.length - raw.trimStart().length;
      if (indent <= 2) {
        section = /^(dependencies|optionalDependencies):$/.test(line) ? line.slice(0, -1) : null;
        if (line.startsWith('version ')) version = stripQuotes(line.slice('version '.length).trim());
        else if (line.startsWith('resolved ')) resolved = stripQuotes(line.slice('resolved '.length).trim());
        else if (line.startsWith('integrity ')) integrity = stripQuotes(line.slice('integrity '.length).trim());
      } else if (section) {
        // `name "range"`, `"@scope/name" "range"` or `name range`.
        const m = line.match(/^(?:"([^"]+)"|(\S+))\s+(?:"([^"]*)"|(\S+))$/);
        if (m) {
          dependencies.push({
            name: m[1] || m[2],
            range: m[3] !== undefined ? m[3] : m[4],
            optional: section === 'optionalDependencies',
          });
        }
      }
    }
    if (!version) continue;

    entries.push({ descriptors, name, version, resolved, integrity, dependencies, workspace: false });
  }
  return entries;
}

/** Yarn Berry (v2+) lockfiles are YAML keyed by descriptor lists. */
function parseYarnBerry(content) {
  const doc = parseYaml(content) || {};
  const entries = [];

  for (const [key, info] of Object.entries(doc)) {
    if (key === '__metadata' || !info || typeof info !== 'object') continue;
    if (!info.version) continue;

    const descriptors = String(key).split(',').map((d) => stripQuotes(d.trim())).filter(Boolean);
    const resolution = typeof info.resolution === 'string' ? info.resolution : '';
    const name = packageNameFromDescriptor(resolution || descriptors[0]);
    if (!name) continue;

    const optionalMeta = info.dependenciesMeta && typeof info.dependenciesMeta === 'object' ? info.dependenciesMeta : {};
    const dependencies = Object.entries(info.dependencies || {}).map(([depName, range]) => ({
      name: depName,
      range: String(range),
      optional: Boolean(optionalMeta[depName] && optionalMeta[depName].optional),
    }));
    for (const [depName, range] of Object.entries(info.optionalDependencies || {})) {
      dependencies.push({ name: depName, range: String(range), optional: true });
    }

    entries.push({
      descriptors,
      name,
      version: String(info.version),
      resolved: null,
      // Berry's `checksum` is a cache key, not an npm SRI hash, so we omit it.
      integrity: null,
      dependencies,
      workspace: /@workspace:/.test(resolution),
    });
  }
  return entries;
}

// --- pnpm ------------------------------------------------------------------

/** pnpm: `pnpm-lock.yaml` (lockfileVersion 5.x / 6.x / 9.x). */
function parsePnpmLock(lockPath) {
  const doc = parseYaml(fs.readFileSync(lockPath, 'utf8')) || {};
  const packages = doc.packages && typeof doc.packages === 'object' ? doc.packages : {};
  // v9 moved the dependency edges from `packages` to `snapshots`.
  const snapshots = doc.snapshots && typeof doc.snapshots === 'object' ? doc.snapshots : packages;

  let complete = true;
  const edges = (info) => {
    const dependsOn = [];
    if (!info || typeof info !== 'object') return dependsOn;
    for (const [group, optional] of [['dependencies', false], ['devDependencies', false], ['optionalDependencies', true]]) {
      for (const [depName, value] of Object.entries(info[group] || {})) {
        const ref = pnpmDependencyRef(depName, value);
        if (ref === LINK) continue;
        if (ref) dependsOn.push(ref);
        else if (!optional) complete = false;
      }
    }
    return dependsOn;
  };

  const edgesByKey = new Map();
  for (const [key, info] of Object.entries(snapshots)) {
    const parsed = packageKeyToNameVersion(key);
    if (!parsed) continue;
    const ref = componentKey(parsed.name, parsed.version);
    edgesByKey.set(ref, [...(edgesByKey.get(ref) || []), ...edges(info)]);
  }

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
      dependsOn: edgesByKey.get(componentKey(parsed.name, parsed.version)) || [],
    }));
  }

  // Root edges: `importers['.']` (workspaces, and every project since v9) or
  // the top-level maps of older single-project lockfiles.
  const rootImporter = doc.importers && doc.importers['.'] ? doc.importers['.'] : doc;
  const rootDependsOn = edges(rootImporter);

  return { lockfileVersion: doc.lockfileVersion || null, components, rootDependsOn, complete };
}

/**
 * Resolves one pnpm dependency value to a component key. Values are a version
 * (`1.3.0`), a version with a peer suffix (`1.3.0(react@18.0.0)` or v5's
 * `1.3.0_react@18.0.0`), an alias (`npm:other@1.0.0`, `/other@1.0.0`), an
 * importer object `{ specifier, version }`, or a local `link:`.
 */
function pnpmDependencyRef(depName, value) {
  let v = value && typeof value === 'object' ? value.version : value;
  if (v === undefined || v === null) return null;
  v = String(v);
  if (/^(link|file|workspace):/.test(v)) return LINK;

  v = v.replace(/^npm:/, '').split('(')[0];
  if (/^\d/.test(v)) {
    // Plain version; drop v5's `_peer@x` suffix (semver never contains `_`).
    return componentKey(depName, v.split('_')[0]);
  }
  const aliased = packageKeyToNameVersion(v);
  return aliased ? componentKey(aliased.name, aliased.version) : null;
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
    // v5 appends peers after an underscore: `/name/1.0.0_react@18.0.0`.
    if (/^(@[^/]+\/)?[^/@]+\/\d/.test(k)) k = k.replace(/_[^/]*$/, '');
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
    dependsOn: uniqueSorted(raw.dependsOn),
  };
}

/** Stable identity of a component across the graph: `name@version`. */
function componentKey(name, version) {
  return `${name}@${version}`;
}

function uniqueSorted(list) {
  return [...new Set(list || [])].sort();
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
  // A digest of the wrong length is corrupt: better no hash than a bogus one.
  const expectedHexLength = { 'SHA-512': 128, 'SHA-384': 96, 'SHA-256': 64, 'SHA-1': 40 }[algorithm];
  if (!hex || hex.length !== expectedHexLength) return { algorithm: null, hash: null };
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
    const key = componentKey(comp.name, comp.version);
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, comp);
    } else {
      // The same name@version installed at several paths: merge its edges.
      existing.dependsOn = uniqueSorted([...existing.dependsOn, ...comp.dependsOn]);
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

module.exports = { parseLockfile, buildPurl, parseIntegrity, toNpmLockfile, componentKey };
