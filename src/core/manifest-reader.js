'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Reads the dependency manifests of non-npm ecosystems straight from the
 * repository, without an SBOM generator:
 *
 *  - Python: poetry.lock, uv.lock, Pipfile.lock (exact, preferred) or
 *            requirements*.txt (only `==` pins; `-r` includes are followed)
 *  - Go:     go.mod (every required module, direct and `// indirect`)
 *  - Java:   gradle.lockfile (exact), pom.xml (declared dependencies with
 *            `${property}` and dependencyManagement resolution)
 *
 * Returns the same shape as readSbom(), so the OSV/KEV scan, VEX and SARIF
 * work unchanged. Every component records the file and line it came from.
 * Versions that are not pinned cannot be audited reliably: they are skipped
 * and reported, never guessed.
 *
 * @param {string} projectRoot
 * @returns {null | {
 *   ok: true, manager: 'manifest', purlBased: true, format: 'manifest',
 *   lockfileName: string, sourceFile: null, files: string[],
 *   root: { name: string, version: string, purl: string, dependsOn: string[] },
 *   components: object[], unidentified: number, notes: string[],
 *   dependencyGraphComplete: false, ecosystems: string[]
 * }} null when no supported manifest exists.
 */
function readManifests(projectRoot) {
  const found = [];
  const notes = [];
  let skipped = 0;

  const collect = (result) => {
    if (!result) return;
    found.push(result);
    skipped += result.skipped || 0;
    if (result.note) notes.push(result.note);
  };

  // Python: an exact lockfile wins over requirements files.
  const pyLock = firstExisting(projectRoot, ['poetry.lock', 'uv.lock', 'Pipfile.lock']);
  if (pyLock) {
    collect(pyLock === 'Pipfile.lock' ? readPipfileLock(projectRoot, pyLock) : readTomlLock(projectRoot, pyLock));
  } else {
    for (const file of requirementsFiles(projectRoot)) collect(readRequirements(projectRoot, file));
  }

  if (exists(projectRoot, 'go.mod')) collect(readGoMod(projectRoot, 'go.mod'));
  if (exists(projectRoot, 'gradle.lockfile')) collect(readGradleLock(projectRoot, 'gradle.lockfile'));
  if (exists(projectRoot, 'pom.xml')) collect(readPom(projectRoot, 'pom.xml'));

  if (!found.length) return null;

  const components = dedupe(found.flatMap((r) => r.components));
  const files = found.map((r) => r.file);
  const name = path.basename(path.resolve(projectRoot));
  const rootName = found.map((r) => r.rootName).find(Boolean) || name;
  const rootVersion = found.map((r) => r.rootVersion).find(Boolean) || '0.0.0';
  return {
    ok: true,
    manager: 'manifest',
    purlBased: true,
    format: 'manifest',
    lockfileName: files.join(', '),
    sourceFile: null,
    files,
    root: {
      name: rootName,
      version: rootVersion,
      purl: `pkg:generic/${encodeURIComponent(rootName)}@${encodeURIComponent(rootVersion)}`,
      dependsOn: components.filter((c) => c.direct).map((c) => c.key),
    },
    components,
    unidentified: skipped,
    notes,
    dependencyGraphComplete: false,
    ecosystems: [...new Set(components.map((c) => c.ecosystem))].sort(),
  };
}

/** True when the folder holds a manifest this reader understands. */
function hasManifests(projectRoot) {
  return ['poetry.lock', 'uv.lock', 'Pipfile.lock', 'go.mod', 'gradle.lockfile', 'pom.xml']
    .some((f) => exists(projectRoot, f)) || requirementsFiles(projectRoot).length > 0;
}

// --- Python ------------------------------------------------------------------------

function requirementsFiles(root) {
  let names = [];
  try {
    names = fs.readdirSync(root);
  } catch {
    return [];
  }
  return names.filter((n) => /^requirements([-_.][\w.-]+)?\.txt$/i.test(n)).sort();
}

/**
 * pip requirements: `name==1.2.3`, extras, environment markers, `--hash`
 * continuation lines and `-r other.txt` includes. Anything that is not an
 * exact pin (ranges, URLs, editable installs) is skipped and counted.
 */
function readRequirements(root, file, seen = new Set()) {
  const full = path.join(root, file);
  if (seen.has(full)) return { file, components: [], skipped: 0 };
  seen.add(full);
  const components = [];
  let skipped = 0;
  const dev = /dev|test|lint|doc/i.test(path.basename(file));

  lines(full).forEach((raw, index) => {
    const line = raw.replace(/\s+#.*$/, '').replace(/\\$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('--hash')) return;
    const include = line.match(/^(?:-r|--requirement)\s+(.+)$/);
    if (include) {
      const nested = readRequirements(root, path.join(path.dirname(file), include[1].trim()), seen);
      components.push(...nested.components);
      skipped += nested.skipped;
      return;
    }
    if (line.startsWith('-')) return; // pip options: -c, -i, --index-url, -e…
    const spec = line.split(';')[0].trim();
    const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s,]+)$/);
    if (m) components.push(pypi(m[1], m[2], file, index + 1, { dev, direct: true }));
    else skipped++;
  });
  const note = skipped ? `${file}: ${skipped} requirement(s) without an exact == pin were not audited` : null;
  return { file, components, skipped, note };
}

/** poetry.lock / uv.lock: `[[package]]` tables with `name` and `version`. */
function readTomlLock(root, file) {
  const components = [];
  let current = null;
  let rootName = null;
  let rootVersion = null;
  const flush = () => {
    if (!current || !current.name || !current.version) return;
    if (current.local) {
      rootName = rootName || current.name;
      rootVersion = rootVersion || current.version;
    } else {
      components.push(pypi(current.name, current.version, file, current.line, { direct: false }));
    }
  };
  lines(path.join(root, file)).forEach((raw, index) => {
    const line = raw.trim();
    if (line === '[[package]]') {
      flush();
      current = { line: index + 1 };
      return;
    }
    if (!current) return;
    if (/^\[/.test(line)) { // a sub-table: [package.dependencies], [package.source]…
      if (!line.startsWith('[package.')) { flush(); current = null; }
      return;
    }
    const kv = line.match(/^(name|version)\s*=\s*"([^"]+)"/);
    if (kv && !current[kv[1]]) current[kv[1]] = kv[2];
    // uv marks the project itself with an editable/virtual source.
    if (/^source\s*=\s*\{\s*(editable|virtual)\s*=/.test(line)) current.local = true;
  });
  flush();
  return { file, components, rootName, rootVersion };
}

/** Pipfile.lock (JSON): `default` and `develop` maps of `"==version"`. */
function readPipfileLock(root, file) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
  } catch {
    return { file, components: [], skipped: 0, note: `${file} could not be parsed` };
  }
  const text = lines(path.join(root, file));
  const components = [];
  for (const [group, dev] of [['default', false], ['develop', true]]) {
    for (const [name, info] of Object.entries(doc[group] || {})) {
      const version = info && typeof info.version === 'string' ? info.version.replace(/^===?/, '') : null;
      if (!version) continue;
      const line = text.findIndex((l) => l.includes(`"${name}": {`)) + 1 || 1;
      components.push(pypi(name, version, file, line, { dev, direct: true }));
    }
  }
  return { file, components };
}

function pypi(name, version, file, line, { dev = false, direct = false } = {}) {
  // PEP 503 normalisation, as purl and OSV use it.
  const normalized = name.toLowerCase().replace(/[-_.]+/g, '-');
  return component({
    ecosystem: 'pypi', name: normalized, osvName: normalized, version,
    purl: `pkg:pypi/${normalized}@${version}`, file, line, dev, direct,
  });
}

// --- Go ------------------------------------------------------------------------------

/** go.mod `require` directives (single and block form); `replace` is applied. */
function readGoMod(root, file) {
  const text = lines(path.join(root, file));
  const requires = [];
  const replaces = new Map();
  let block = null;
  let moduleName = null;

  text.forEach((raw, index) => {
    const line = raw.replace(/\/\/(?!\s*indirect).*$/, '').trim();
    const mod = line.match(/^module\s+(\S+)/);
    if (mod) moduleName = mod[1];
    if (/^(require|replace|exclude|retract)\s*\($/.test(line)) { block = line.split(/\s/)[0]; return; }
    if (line === ')') { block = null; return; }
    const single = line.match(/^(require|replace)\s+(.+)$/);
    const kind = single ? single[1] : block;
    const body = single ? single[2] : line;
    if (kind === 'require') {
      const m = body.match(/^(\S+)\s+(v\S+)(\s+\/\/\s*indirect)?/);
      if (m) requires.push({ module: m[1], version: m[2], indirect: Boolean(m[3]), line: index + 1 });
    } else if (kind === 'replace') {
      const m = body.match(/^(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)\s+(v\S+)/);
      if (m) replaces.set(m[1], { module: m[2], version: m[3] });
    }
  });

  const components = requires.map((r) => {
    const target = replaces.get(r.module) || { module: r.module, version: r.version };
    return component({
      ecosystem: 'golang', name: target.module, osvName: target.module, version: target.version,
      purl: `pkg:golang/${target.module}@${target.version}`, file, line: r.line, direct: !r.indirect,
    });
  });
  return { file, components, rootName: moduleName ? moduleName.split('/').pop() : null };
}

// --- Java --------------------------------------------------------------------------------

/** gradle.lockfile: `group:artifact:version=configurations`. */
function readGradleLock(root, file) {
  const components = [];
  lines(path.join(root, file)).forEach((raw, index) => {
    const m = raw.trim().match(/^([^:#\s]+):([^:\s]+):([^=\s]+)=(.*)$/);
    if (!m) return;
    const configs = m[4];
    const dev = configs && !/(runtimeClasspath|compileClasspath)/.test(configs);
    components.push(maven(m[1], m[2], m[3], file, index + 1, { dev, direct: false }));
  });
  return { file, components };
}

/**
 * pom.xml declared dependencies. Versions come from the dependency itself,
 * `${property}` values in <properties> (and project.version) or the
 * <dependencyManagement> section. Transitive dependencies need Maven to be
 * resolved, so only the declared ones are audited.
 */
function readPom(root, file) {
  const xml = fs.readFileSync(path.join(root, file), 'utf8');
  const stripped = xml.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));

  const tag = (block, name) => {
    const m = block.match(new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`));
    return m ? m[1] : null;
  };
  // Top-level project fields, ignoring <parent>, <dependencies> and the like.
  const topLevel = stripped
    .replace(/<parent>[\s\S]*?<\/parent>/, '')
    .replace(/<(dependencies|dependencyManagement|build|profiles|plugins|reporting)>[\s\S]*?<\/\1>/g, '');
  const parentBlock = (stripped.match(/<parent>([\s\S]*?)<\/parent>/) || [])[1] || '';
  const props = {
    'project.version': tag(topLevel, 'version') || tag(parentBlock, 'version'),
    'project.groupId': tag(topLevel, 'groupId') || tag(parentBlock, 'groupId'),
  };
  const propsBlock = (stripped.match(/<properties>([\s\S]*?)<\/properties>/) || [])[1] || '';
  for (const m of propsBlock.matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props[m[1]] = m[2];
  const resolve = (value) => {
    let v = value;
    for (let i = 0; i < 5 && v && /\$\{([^}]+)\}/.test(v); i++) {
      v = v.replace(/\$\{([^}]+)\}/g, (_, key) => (props[key] !== undefined && props[key] !== null ? props[key] : `\${${key}}`));
    }
    return v;
  };

  const managedBlock = (stripped.match(/<dependencyManagement>([\s\S]*?)<\/dependencyManagement>/) || [])[1] || '';
  const managed = new Map();
  for (const m of managedBlock.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = resolve(tag(m[1], 'groupId'));
    const a = resolve(tag(m[1], 'artifactId'));
    const v = resolve(tag(m[1], 'version'));
    if (g && a && v) managed.set(`${g}:${a}`, v);
  }

  const components = [];
  let skipped = 0;
  const outside = stripped.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, (c) => c.replace(/[^\n]/g, ' '));
  for (const m of outside.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = m[1];
    const g = resolve(tag(block, 'groupId'));
    const a = resolve(tag(block, 'artifactId'));
    let v = resolve(tag(block, 'version')) || managed.get(`${g}:${a}`) || null;
    if (!g || !a || !v || /\$\{|[[\]()]/.test(v)) { skipped++; continue; } // unresolved or a version range
    const scope = tag(block, 'scope');
    const line = outside.slice(0, m.index).split('\n').length + block.slice(0, block.indexOf('<artifactId>')).split('\n').length - 1;
    components.push(maven(g, a, v, file, line, { dev: scope === 'test' || scope === 'provided', direct: true }));
  }
  const notes = ['pom.xml: declared dependencies only; commit a Maven-generated SBOM (cyclonedx-maven-plugin) to audit transitive ones'];
  if (skipped) notes.push(`pom.xml: ${skipped} dependency(ies) with a version inherited from a parent/BOM or a range were not audited`);
  return {
    file, components, skipped, note: notes.join('; '),
    rootName: tag(topLevel, 'artifactId'), rootVersion: props['project.version'],
  };
}

function maven(group, artifact, version, file, line, { dev = false, direct = false } = {}) {
  return component({
    ecosystem: 'maven', name: `${group}:${artifact}`, osvName: `${group}:${artifact}`, version,
    purl: `pkg:maven/${group}/${artifact}@${version}`, file, line, dev, direct,
  });
}

// --- Shared ------------------------------------------------------------------------------

function component({ ecosystem, name, osvName, version, purl, file, line, dev = false, direct = false }) {
  return {
    key: purl,
    name,
    version,
    purl,
    ecosystem,
    osvName,
    license: null,
    scope: dev ? 'optional' : 'required',
    dev,
    optional: dev,
    direct,
    dependsOn: [],
    location: { file, line },
  };
}

function dedupe(components) {
  const seen = new Map();
  for (const c of components) {
    const existing = seen.get(c.key);
    if (!existing) seen.set(c.key, c);
    else {
      existing.direct = existing.direct || c.direct;
      existing.optional = existing.optional && c.optional;
      existing.dev = existing.optional;
      existing.scope = existing.optional ? 'optional' : 'required';
    }
  }
  return [...seen.values()].sort((a, b) => a.key.localeCompare(b.key));
}

function lines(file) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/);
  } catch {
    return [];
  }
}

function exists(root, file) {
  return fs.existsSync(path.join(root, file));
}

function firstExisting(root, files) {
  return files.find((f) => exists(root, f)) || null;
}

module.exports = { readManifests, hasManifests };
