'use strict';

const path = require('node:path');
const { readJson, exists } = require('../utils/fs');

/**
 * Parses an npm lockfile (package-lock.json v2/v3 or npm-shrinkwrap.json)
 * into a normalized list of components. CRA / TR-03183 require traceability
 * of every direct and transitive dependency, including integrity hashes.
 *
 * @param {string} projectRoot
 * @returns {{
 *   ok: boolean,
 *   lockfileName: string|null,
 *   lockfileVersion: number|null,
 *   root: { name: string, version: string },
 *   components: Array<object>,
 *   error?: string
 * }}
 */
function parseLockfile(projectRoot) {
  const candidates = ['package-lock.json', 'npm-shrinkwrap.json'];
  let lockPath = null;
  let lockfileName = null;

  for (const candidate of candidates) {
    const full = path.join(projectRoot, candidate);
    if (exists(full)) {
      lockPath = full;
      lockfileName = candidate;
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
      lockfileName: null,
      lockfileVersion: null,
      root,
      components: [],
      error:
        'No se encontró package-lock.json ni npm-shrinkwrap.json. ' +
        'El CRA exige trazabilidad determinista de dependencias: ejecuta `npm install` para generar el lockfile.',
    };
  }

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

  return {
    ok: true,
    lockfileName,
    lockfileVersion,
    root,
    components,
  };
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
    dev: raw.dev,
    optional: raw.optional,
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

module.exports = { parseLockfile, buildPurl, parseIntegrity };
