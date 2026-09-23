'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readJson } = require('../utils/fs');

/**
 * Reads the package.json of an installed component from node_modules.
 * Lockfiles do not carry every field TR-03183 asks for (Yarn and pnpm have no
 * licenses, none of them have the component creator), so the installed
 * manifest is the best offline source for them.
 *
 * Looks in the npm path recorded in the lockfile, the hoisted location and
 * pnpm's virtual store. Returns null when the package is not installed or the
 * installed version differs from the locked one.
 *
 * @param {string} projectRoot
 * @param {{ name: string, version: string|null, path?: string }} component
 * @returns {object|null}
 */
function readInstalledManifest(projectRoot, component) {
  const { name, version } = component;
  const candidates = [];
  if (component.path) candidates.push(path.join(projectRoot, component.path, 'package.json'));
  candidates.push(path.join(projectRoot, 'node_modules', name, 'package.json'));
  if (version) {
    const storeName = `${name.replace('/', '+')}@${version}`;
    candidates.push(path.join(projectRoot, 'node_modules', '.pnpm', storeName, 'node_modules', name, 'package.json'));
  }

  for (const candidate of candidates) {
    const pkg = readManifest(candidate);
    if (!pkg) continue;
    if (version && pkg.version && pkg.version !== version) continue;
    return pkg;
  }

  // Yarn records no install paths, so non-hoisted duplicates live somewhere
  // under a nested node_modules: fall back to an index of the whole tree.
  const nested = installedIndex(projectRoot).get(`${name}@${version}`);
  return nested ? readManifest(nested) : null;
}

function readManifest(file) {
  try {
    return readJson(file);
  } catch {
    return null; // Unreadable manifest: treat as not installed.
  }
}

const indexCache = new Map();

/**
 * Maps `name@version` to the package.json path of every package installed
 * under `<projectRoot>/node_modules`, including nested node_modules folders.
 * pnpm's `.pnpm` store is skipped: it is looked up directly by name.
 */
function installedIndex(projectRoot) {
  if (indexCache.has(projectRoot)) return indexCache.get(projectRoot);
  const index = new Map();

  const visitModules = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
      const full = path.join(dir, entry.name);
      if (entry.name.startsWith('@')) {
        let scoped = [];
        try {
          scoped = fs.readdirSync(full, { withFileTypes: true });
        } catch {
          // Unreadable scope folder: skip it.
        }
        for (const s of scoped) if (s.isDirectory()) visitPackage(path.join(full, s.name));
      } else {
        visitPackage(full);
      }
    }
  };

  const visitPackage = (dir) => {
    const manifestPath = path.join(dir, 'package.json');
    const pkg = readManifest(manifestPath);
    if (pkg && pkg.name && pkg.version) {
      const key = `${pkg.name}@${pkg.version}`;
      if (!index.has(key)) index.set(key, manifestPath);
    }
    visitModules(path.join(dir, 'node_modules'));
  };

  visitModules(path.join(projectRoot, 'node_modules'));
  indexCache.set(projectRoot, index);
  return index;
}

/** Extracts the declared license (SPDX id or expression) from a manifest. */
function licenseFromManifest(pkg) {
  if (!pkg) return null;
  if (typeof pkg.license === 'string') return pkg.license;
  if (pkg.license && pkg.license.type) return pkg.license.type;
  if (Array.isArray(pkg.licenses) && pkg.licenses.length) {
    return pkg.licenses.map((l) => (typeof l === 'string' ? l : l.type)).filter(Boolean).join(' OR ') || null;
  }
  return null;
}

/**
 * Derives the creator contact TR-03183 requires (§5.2.1 / §5.2.2): an email
 * address, or a URL when no email is available. Uses `author`, then the first
 * maintainer/contributor with an email, then `homepage` and `repository`.
 *
 * @returns {{ name: string|null, email: string|null, url: string|null }|null}
 */
function creatorFromManifest(pkg) {
  if (!pkg) return null;

  const author = parsePerson(pkg.author);
  const people = [author, ...toArray(pkg.maintainers).map(parsePerson), ...toArray(pkg.contributors).map(parsePerson)]
    .filter(Boolean);
  const withEmail = people.find((p) => p.email);
  const name = (author && author.name) || (withEmail && withEmail.name) || null;

  if (withEmail) return { name, email: withEmail.email, url: null };

  const url = (author && author.url) || httpUrl(pkg.homepage) || repositoryUrl(pkg.repository);
  if (url) return { name, email: null, url };
  return null;
}

/** Normalizes `repository` (string or object) into a browsable https URL. */
function repositoryUrl(repository) {
  if (!repository) return null;
  let url = typeof repository === 'string' ? repository : repository.url;
  if (!url || typeof url !== 'string') return null;

  // Shorthands: "user/repo", "github:user/repo", "gitlab:user/repo".
  const shorthand = url.match(/^(?:(github|gitlab|bitbucket):)?([\w.-]+\/[\w.-]+)$/);
  if (shorthand) {
    const host = { github: 'github.com', gitlab: 'gitlab.com', bitbucket: 'bitbucket.org' }[shorthand[1] || 'github'];
    return `https://${host}/${shorthand[2]}`;
  }

  url = url
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^ssh:\/\/git@/, 'https://')
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/\.git$/, '');
  return httpUrl(url);
}

/** Parses npm "person" fields: "Name <email> (url)" or { name, email, url }. */
function parsePerson(person) {
  if (!person) return null;
  if (typeof person === 'object') {
    return { name: person.name || null, email: person.email || null, url: httpUrl(person.url) };
  }
  const str = String(person);
  const email = (str.match(/<([^>]+)>/) || [])[1] || null;
  const url = (str.match(/\(([^)]+)\)/) || [])[1] || null;
  const name = str.replace(/<[^>]*>/, '').replace(/\([^)]*\)/, '').trim() || null;
  return { name, email, url: httpUrl(url) };
}

function httpUrl(value) {
  return typeof value === 'string' && /^https?:\/\//i.test(value) ? value : null;
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

module.exports = { readInstalledManifest, licenseFromManifest, creatorFromManifest, repositoryUrl };
