'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseLockfile } = require('./lockfile-parser');
const { readSbom } = require('./sbom-reader');
const { readManifests, hasManifests } = require('./manifest-reader');

/**
 * Decides where the components of a project come from:
 *
 *  - `sbom`:          an input SBOM (`-i`), any ecosystem
 *  - `npm`:           the npm/Yarn/pnpm lockfile (native, richest data)
 *  - `manifest`:      requirements.txt / poetry.lock / go.mod / pom.xml… when
 *                     there is no npm lockfile
 *  - `npm+manifest`:  both in the same folder (e.g. a JS front end next to a
 *                     Python service); vulnerabilities cover both
 *
 * `parsed` is what the scanner, license check, VEX and SARIF consume; it is
 * null for plain npm projects, which keep their existing code paths.
 *
 * @param {string} projectRoot
 * @param {{ input?: string|null }} [options]
 */
function loadProject(projectRoot, { input = null } = {}) {
  if (input) {
    const parsed = readSbom(input);
    return { mode: 'sbom', parsed, manifests: null };
  }

  const lock = parseLockfile(projectRoot);
  const manifests = hasManifests(projectRoot) ? readManifests(projectRoot) : null;

  if (lock.ok && manifests) {
    // npm components keep their name-based lookups; manifest ones use purls.
    const parsed = {
      ...lock,
      purlBased: false,
      components: [...lock.components, ...manifests.components],
      root: { ...lock.root, dependsOn: [...lock.root.dependsOn, ...manifests.root.dependsOn] },
    };
    return { mode: 'npm+manifest', parsed, manifests };
  }
  if (!lock.ok && manifests) return { mode: 'manifest', parsed: manifests, manifests };
  return { mode: 'npm', parsed: null, manifests: null };
}

/**
 * The nearest folder, walking up from `start`, with a package.json or a
 * supported manifest of another ecosystem. Null when there is none.
 */
function findAnyProjectRoot(start) {
  let dir = path.resolve(start);
  for (;;) {
    if (fs.existsSync(path.join(dir, 'package.json')) || hasManifests(dir)) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

module.exports = { loadProject, findAnyProjectRoot };
