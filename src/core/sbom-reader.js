'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Reads an existing SBOM (CycloneDX JSON, SPDX 2.x JSON or SPDX 3.0 JSON-LD)
 * into the same shape parseLockfile() returns, so the vulnerability scan, the
 * license check, the VEX and the SARIF work for any ecosystem: Python, Java,
 * Go, Rust, .NET, PHP, Ruby… Each component is identified by its Package URL
 * (purl), which OSV.dev resolves directly.
 *
 * Generate the SBOM with the ecosystem's tooling (Syft, cdxgen, Trivy,
 * cyclonedx-py, the CycloneDX Maven/Gradle plugins…) and pass it with `-i`.
 *
 * @param {string} file
 * @returns {{
 *   ok: boolean, error?: string, manager: 'sbom', format: 'cyclonedx'|'spdx',
 *   lockfileName: string, sourceFile: string, document: object,
 *   root: { name: string, version: string, dependsOn: string[] },
 *   components: Array<object>, unidentified: number, dependencyGraphComplete: boolean
 * }}
 */
function readSbom(file) {
  let document;
  try {
    document = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return fail(file, `Could not read the SBOM ${file}: ${err.code === 'ENOENT' ? 'file not found' : err.message}`);
  }

  let result;
  if (document && (document.bomFormat === 'CycloneDX' || Array.isArray(document.components))) {
    result = fromCycloneDx(document);
  } else if (document && document.spdxVersion) {
    result = fromSpdx2(document);
  } else if (document && Array.isArray(document['@graph'])) {
    result = fromSpdx3(document);
  } else {
    return fail(file, `${file} is not a CycloneDX or SPDX JSON document.`);
  }

  // Only components with a purl can be looked up; keep the count visible.
  const identified = result.components.filter((c) => c.purl);
  return {
    ok: true,
    manager: 'sbom',
    format: result.format,
    lockfileName: path.basename(file),
    sourceFile: file,
    document,
    root: result.root,
    components: dedupe(identified),
    unidentified: result.components.length - identified.length,
    dependencyGraphComplete: result.complete,
  };
}

// --- CycloneDX ---------------------------------------------------------------

function fromCycloneDx(doc) {
  const byRef = new Map();
  const components = [];
  const visit = (list) => {
    for (const c of list || []) {
      if (!c || typeof c !== 'object') continue;
      if (c.type !== 'file' && c.type !== 'operating-system') {
        const comp = component({
          purl: c.purl,
          name: c.group ? `${c.group}/${c.name}` : c.name,
          version: c.version,
          license: cdxLicense(c.licenses),
          optional: c.scope === 'optional' || c.scope === 'excluded',
        });
        components.push(comp);
        if (c['bom-ref']) byRef.set(c['bom-ref'], comp);
      }
      visit(c.components); // nested components (assemblies)
    }
  };
  visit(doc.components);

  const meta = (doc.metadata && doc.metadata.component) || {};
  const root = rootInfo(meta.name, meta.version, meta.purl);
  const rootRef = meta['bom-ref'];

  let complete = Array.isArray(doc.dependencies) && doc.dependencies.length > 0;
  for (const dep of doc.dependencies || []) {
    const targets = (dep.dependsOn || []).map((ref) => byRef.get(ref)).filter(Boolean).map((c) => c.key);
    if (dep.ref === rootRef) root.dependsOn.push(...targets);
    const from = byRef.get(dep.ref);
    if (from) from.dependsOn.push(...targets);
  }
  if ((doc.compositions || []).some((c) => c && c.aggregate && c.aggregate !== 'complete')) complete = false;
  return { format: 'cyclonedx', components, root, complete };
}

function cdxLicense(licenses) {
  if (!Array.isArray(licenses) || !licenses.length) return null;
  const ids = licenses.map((l) => l.expression || (l.license && (l.license.id || l.license.name))).filter(Boolean);
  return ids.length ? [...new Set(ids)].join(' AND ') : null;
}

// --- SPDX 2.x ----------------------------------------------------------------

function fromSpdx2(doc) {
  const byId = new Map();
  const components = [];
  const described = new Set(doc.documentDescribes || []);
  for (const r of doc.relationships || []) {
    if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === 'SPDXRef-DOCUMENT') described.add(r.relatedSpdxElement);
  }

  let rootPkg = null;
  for (const pkg of doc.packages || []) {
    const ref = (pkg.externalRefs || []).find((r) => r.referenceType === 'purl');
    if (described.has(pkg.SPDXID) && !rootPkg) {
      rootPkg = pkg;
      continue;
    }
    const comp = component({
      purl: ref && ref.referenceLocator,
      name: pkg.name,
      version: pkg.versionInfo,
      license: spdxLicense(pkg.licenseConcluded) || spdxLicense(pkg.licenseDeclared),
    });
    components.push(comp);
    byId.set(pkg.SPDXID, comp);
  }

  const rootRef = rootPkg && (rootPkg.externalRefs || []).find((r) => r.referenceType === 'purl');
  const root = rootInfo((rootPkg && rootPkg.name) || doc.name, rootPkg && rootPkg.versionInfo, rootRef && rootRef.referenceLocator);
  const rootId = rootPkg && rootPkg.SPDXID;

  let edges = 0;
  for (const r of doc.relationships || []) {
    // A DEPENDS_ON B; B DEPENDENCY_OF A; A CONTAINS B.
    let from = r.spdxElementId;
    let to = r.relatedSpdxElement;
    if (r.relationshipType === 'DEPENDENCY_OF') [from, to] = [to, from];
    else if (!['DEPENDS_ON', 'CONTAINS', 'RUNTIME_DEPENDENCY_OF', 'DEV_DEPENDENCY_OF'].includes(r.relationshipType)) continue;
    if (r.relationshipType.endsWith('_DEPENDENCY_OF')) [from, to] = [to, from];
    const target = byId.get(to);
    if (!target) continue;
    edges++;
    if (from === rootId) root.dependsOn.push(target.key);
    else if (byId.has(from)) byId.get(from).dependsOn.push(target.key);
    if (r.relationshipType === 'DEV_DEPENDENCY_OF') target.optional = true;
  }
  return { format: 'spdx', components, root, complete: edges > 0 };
}

function spdxLicense(value) {
  return value && value !== 'NOASSERTION' && value !== 'NONE' ? value : null;
}

// --- SPDX 3.0 (JSON-LD) ----------------------------------------------------------

function fromSpdx3(doc) {
  const byId = new Map();
  const components = [];
  let rootId = null;

  for (const el of doc['@graph']) {
    if (el.type === 'SpdxDocument' && Array.isArray(el.rootElement)) rootId = rootId || el.rootElement[0];
  }
  let root = rootInfo(doc.name);

  for (const el of doc['@graph']) {
    if (el.type !== 'software_Package') continue;
    const id = el.spdxId || el['@id'];
    if (id && id === rootId) {
      root = rootInfo(el.name || root.name, el.software_packageVersion, el.software_packageUrl);
      continue;
    }
    const comp = component({
      purl: el.software_packageUrl,
      name: el.name,
      version: el.software_packageVersion,
      license: null,
    });
    components.push(comp);
    if (id) byId.set(id, comp);
  }

  let edges = 0;
  for (const el of doc['@graph']) {
    if (el.type !== 'Relationship' || !['dependsOn', 'contains'].includes(el.relationshipType)) continue;
    for (const to of el.to || []) {
      const target = byId.get(to);
      if (!target) continue;
      edges++;
      if (el.from === rootId) root.dependsOn.push(target.key);
      else if (byId.has(el.from)) byId.get(el.from).dependsOn.push(target.key);
    }
  }
  return { format: 'spdx', components, root, complete: edges > 0 };
}

/**
 * The product the SBOM describes. Without a purl in the SBOM it gets a
 * `pkg:generic` one, so VEX statements still name the product unambiguously.
 */
function rootInfo(name, version, purl) {
  const n = name || 'unknown';
  const v = version || '0.0.0';
  const parsed = parsePurl(purl);
  return { name: n, version: v, purl: parsed ? parsed.canonical : `pkg:generic/${encodeURIComponent(n)}@${encodeURIComponent(v)}`, dependsOn: [] };
}

// --- Components -------------------------------------------------------------------

/**
 * Normalizes an SBOM component. The name and version come from the purl when
 * there is one (it is what OSV understands), else from the SBOM fields.
 */
function component({ purl, name, version, license, optional = false }) {
  const parsed = parsePurl(purl);
  const clean = parsed ? parsed.canonical : null;
  const displayName = parsed ? parsed.displayName : name || 'unknown';
  const ver = (parsed && parsed.version) || version || null;
  return {
    key: clean || `${displayName}@${ver}`,
    name: displayName,
    version: ver,
    purl: clean,
    ecosystem: parsed ? parsed.type : null,
    osvName: parsed ? parsed.osvName : displayName,
    license: license || null,
    scope: optional ? 'optional' : 'required',
    dev: optional,
    optional,
    dependsOn: [],
  };
}

/**
 * Minimal Package URL parser (https://github.com/package-url/purl-spec).
 * Returns the canonical purl without qualifiers/subpath and the name in the
 * form each ecosystem uses (OSV naming): Maven `group:artifact`, npm
 * `@scope/name`, Go/Composer `namespace/name`.
 */
function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  let rest = purl.slice(4).split('#')[0].split('?')[0];
  // The version separator is the last `@` after the last `/` (an unencoded
  // npm scope, `pkg:npm/@scope/name`, is not a version).
  const at = rest.lastIndexOf('@');
  let version = null;
  let rawVersion = '';
  if (at > rest.lastIndexOf('/')) {
    rawVersion = rest.slice(at + 1);
    version = decodeURIComponent(rawVersion);
    rest = rest.slice(0, at);
  }
  const parts = rest.split('/');
  const type = parts.shift().toLowerCase();
  if (!type || !parts.length) return null;
  const name = decodeURIComponent(parts.pop());
  const namespace = parts.map(decodeURIComponent).join('/');

  let osvName = name;
  if (type === 'maven') osvName = namespace ? `${namespace}:${name}` : name;
  else if (namespace) osvName = `${namespace}/${name}`;

  return {
    type,
    namespace,
    name,
    version,
    osvName,
    displayName: osvName,
    canonical: `pkg:${rest}${rawVersion ? `@${rawVersion}` : ''}`,
  };
}

function dedupe(components) {
  const seen = new Map();
  for (const c of components) {
    const existing = seen.get(c.key);
    if (!existing) seen.set(c.key, c);
    else existing.dependsOn.push(...c.dependsOn);
  }
  for (const c of seen.values()) c.dependsOn = [...new Set(c.dependsOn)].sort();
  return [...seen.values()].sort((a, b) => a.key.localeCompare(b.key));
}

function fail(file, error) {
  return {
    ok: false, error, manager: 'sbom', format: null, lockfileName: path.basename(file), sourceFile: file,
    document: null, root: rootInfo(), components: [], unidentified: 0,
    dependencyGraphComplete: false,
  };
}

module.exports = { readSbom, parsePurl };
