'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const { readJson } = require('../utils/fs');
const { parseLockfile, buildPurl, componentKey } = require('./lockfile-parser');
const {
  readInstalledManifest, licenseFromManifest, creatorFromManifest, repositoryUrl,
} = require('./installed-metadata');

const TOOL_NAME = 'cra-audit';
const TOOL_VERSION = require('../../package.json').version;
const TOOL_URL = 'https://github.com/migohe14/cra-audit';
const NPM_REGISTRY = 'https://registry.npmjs.org';

/**
 * Generates a Software Bill of Materials from the project lockfile.
 * Supported formats: CycloneDX 1.6 (JSON) and SPDX 2.3 (JSON).
 * Required by CRA Annex I and BSI TR-03183 Part 2.
 *
 * The CycloneDX output follows the field mapping of TR-03183-2 v2.1.0
 * (appendix 8.5): SBOM creator in `metadata.manufacturer`, component creator
 * in `manufacturer`, SHA-512 of the deployable tarball on the `distribution`
 * reference, the `bsi:component:*` properties, a full `dependencies` graph and
 * its completeness in `compositions`.
 *
 * Fields a lockfile does not carry (licenses for Yarn/pnpm, component
 * creators) are read from the installed packages in node_modules.
 *
 * @param {string} projectRoot
 * @param {{ format?: string, creator?: string }} [options]
 *   `creator`: email or URL of the SBOM creator. Defaults to the project's
 *   package.json (`author`, `homepage`, `repository`).
 */
function generateSbom(projectRoot, { format = 'cyclonedx', creator } = {}) {
  const parsed = parseLockfile(projectRoot);
  if (!parsed.ok) {
    return { ok: false, error: parsed.error };
  }

  const rootPkg = readJson(path.join(projectRoot, 'package.json')) || {};
  const product = {
    ...parsed.root,
    purl: buildPurl(parsed.root.name, parsed.root.version),
    creator: creatorFromManifest(rootPkg),
    license: licenseFromManifest(rootPkg),
    sourceUrl: repositoryUrl(rootPkg.repository),
  };
  const sbomCreator = parseCreatorOption(creator) || product.creator;
  const components = parsed.components.map((c) => describeComponent(projectRoot, c));

  const normalizedFormat = String(format).toLowerCase();
  let document;
  if (normalizedFormat === 'spdx') {
    document = buildSpdx(product, components, sbomCreator);
  } else if (normalizedFormat === 'cyclonedx' || normalizedFormat === 'cdx') {
    document = buildCycloneDx(product, components, sbomCreator, parsed.dependencyGraphComplete);
  } else {
    return { ok: false, error: `Unsupported SBOM format: "${format}". Use "cyclonedx" or "spdx".` };
  }

  return {
    ok: true,
    format: normalizedFormat === 'spdx' ? 'spdx' : 'cyclonedx',
    componentCount: components.length,
    document,
  };
}

/** Adds the TR-03183 fields that come from the installed package. */
function describeComponent(projectRoot, c) {
  const manifest = readInstalledManifest(projectRoot, c);
  return {
    ...c,
    key: componentKey(c.name, c.version),
    license: c.license || licenseFromManifest(manifest),
    creator: creatorFromManifest(manifest),
    sourceUrl: manifest ? repositoryUrl(manifest.repository) : null,
    downloadUrl: c.resolved && /^https?:\/\//.test(c.resolved) ? c.resolved.split('#')[0] : registryTarballUrl(c),
    filename: tarballFilename(c),
  };
}

/** Accepts an email address or an http(s) URL for the SBOM creator. */
function parseCreatorOption(value) {
  if (!value || typeof value !== 'string') return null;
  const v = value.trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return { name: null, email: v, url: null };
  if (/^https?:\/\//i.test(v)) return { name: null, email: null, url: v };
  return null;
}

// --- CycloneDX 1.6 ---------------------------------------------------------

function buildCycloneDx(product, components, sbomCreator, graphComplete) {
  const refByKey = new Map(components.map((c) => [c.key, bomRef(c)]));
  const rootRef = product.purl || `${product.name}@${product.version}`;
  let complete = graphComplete;

  const refsFor = (keys) => keys.map((key) => {
    const ref = refByKey.get(key);
    if (!ref) complete = false; // an edge points outside the SBOM
    return ref;
  }).filter(Boolean);

  const rootComponent = {
    type: 'application',
    'bom-ref': rootRef,
    name: product.name,
    version: product.version,
    purl: product.purl || undefined,
    manufacturer: cdxEntity(product.creator),
    licenses: cdxLicenses(product.license),
    externalReferences: product.sourceUrl
      ? [{ type: 'source-distribution', url: product.sourceUrl }]
      : undefined,
  };

  const cdxComponents = components.map((c) => {
    const hashes = c.hashAlgorithm && c.hashValue ? [{ alg: c.hashAlgorithm, content: c.hashValue }] : undefined;
    const externalReferences = [];
    if (c.downloadUrl) externalReferences.push({ type: 'distribution', url: c.downloadUrl, hashes });
    if (c.sourceUrl) externalReferences.push({ type: 'source-distribution', url: c.sourceUrl });

    return {
      type: 'library',
      'bom-ref': bomRef(c),
      name: c.name,
      version: c.version || undefined,
      scope: c.scope,
      purl: c.purl || undefined,
      manufacturer: cdxEntity(c.creator),
      hashes,
      licenses: cdxLicenses(c.license),
      externalReferences: externalReferences.length ? externalReferences : undefined,
      // An npm package is a gzipped tarball: a structured, non-executable archive.
      properties: [
        { name: 'bsi:component:filename', value: c.filename },
        { name: 'bsi:component:executable', value: 'non-executable' },
        { name: 'bsi:component:archive', value: 'archive' },
        { name: 'bsi:component:structured', value: 'structured' },
      ],
    };
  });

  // Components without dependencies MUST still appear with an empty dependsOn.
  const dependencies = [
    { ref: rootRef, dependsOn: refsFor(product.dependsOn) },
    ...components.map((c) => ({ ref: bomRef(c), dependsOn: refsFor(c.dependsOn) })),
  ];

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [{
          type: 'application',
          name: TOOL_NAME,
          version: TOOL_VERSION,
          externalReferences: [{ type: 'vcs', url: TOOL_URL }],
        }],
      },
      manufacturer: cdxEntity(sbomCreator),
      component: rootComponent,
    },
    components: cdxComponents,
    dependencies,
    compositions: [{
      aggregate: complete ? 'complete' : 'incomplete',
      dependencies: dependencies.map((d) => d.ref),
    }],
  };
}

function bomRef(c) {
  return c.purl || c.key;
}

/** TR-03183 asks for an email address, or a URL when there is none. */
function cdxEntity(creator) {
  if (!creator) return undefined;
  const entity = {};
  if (creator.name) entity.name = creator.name;
  if (creator.email) entity.contact = [{ email: creator.email }];
  else if (creator.url) entity.url = [creator.url];
  else return undefined;
  return entity;
}

/**
 * License choice per TR-03183 appendix 8.5: the licence assigned by the
 * component creator ("declared", the original licence) and the one it is
 * distributed under ("concluded"). For npm packages both are the package.json
 * license. SPDX expressions can only be given once, as the concluded licence.
 */
function cdxLicenses(license) {
  if (!license) return undefined;
  const value = String(license).trim();
  if (/\s(AND|OR|WITH)\s|[()]/i.test(value)) {
    return [{ expression: value, acknowledgement: 'concluded' }];
  }
  // Unknown ids go in `name`: CycloneDX validates `id` against the SPDX list.
  const license_ = SPDX_IDS.has(value) ? { id: value } : { name: value };
  return [
    { license: { ...license_, acknowledgement: 'declared' } },
    { license: { ...license_, acknowledgement: 'concluded' } },
  ];
}

// --- SPDX 2.3 --------------------------------------------------------------

function buildSpdx(product, components, sbomCreator) {
  const rootSpdxId = 'SPDXRef-Package-root';
  const idByKey = new Map(components.map((c, index) => [c.key, `SPDXRef-Package-${index}`]));

  const packages = components.map((c) => {
    const pkg = {
      name: c.name,
      SPDXID: idByKey.get(c.key),
      versionInfo: c.version || 'NOASSERTION',
      packageFileName: c.filename,
      originator: spdxActor(c.creator),
      downloadLocation: c.downloadUrl || 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: c.license || 'NOASSERTION',
      licenseDeclared: c.license || 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: c.purl
        ? [{
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: c.purl,
          }]
        : undefined,
    };
    if (c.hashAlgorithm && c.hashValue) {
      pkg.checksums = [{ algorithm: c.hashAlgorithm.replace('-', ''), checksumValue: c.hashValue }];
    }
    return pkg;
  });

  packages.unshift({
    name: product.name,
    SPDXID: rootSpdxId,
    versionInfo: product.version,
    originator: spdxActor(product.creator),
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: product.license || 'NOASSERTION',
    licenseDeclared: product.license || 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    externalRefs: product.purl
      ? [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: product.purl }]
      : undefined,
  });

  const relationships = [{
    spdxElementId: 'SPDXRef-DOCUMENT',
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: rootSpdxId,
  }];
  const addEdges = (fromId, keys) => {
    for (const key of keys) {
      const to = idByKey.get(key);
      if (to) relationships.push({ spdxElementId: fromId, relationshipType: 'DEPENDS_ON', relatedSpdxElement: to });
    }
  };
  addEdges(rootSpdxId, product.dependsOn);
  for (const c of components) addEdges(idByKey.get(c.key), c.dependsOn);

  const creators = [`Tool: ${TOOL_NAME}-${TOOL_VERSION}`];
  const creatorActor = spdxActor(sbomCreator);
  if (creatorActor) creators.unshift(creatorActor);

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${product.name}@${product.version}`,
    documentNamespace: `https://spdx.org/spdxdocs/${product.name}-${crypto.randomUUID()}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators,
    },
    documentDescribes: [rootSpdxId],
    packages,
    relationships,
  };
}

/** SPDX 2.3 actor: "Organization: name (email)". */
function spdxActor(creator) {
  if (!creator) return undefined;
  const label = creator.name || creator.url || creator.email;
  return `Organization: ${label} (${creator.email || ''})`;
}

// --- npm tarball helpers ---------------------------------------------------

/** The actual filename of the deployable component (TR-03183 §5.2.2). */
function tarballFilename(c) {
  if (c.resolved && /^https?:\/\//.test(c.resolved)) {
    const base = c.resolved.split(/[?#]/)[0].split('/').pop();
    if (base) return base;
  }
  return `${c.name.split('/').pop()}-${c.version}.tgz`;
}

/** Canonical npm registry URL, used when the lockfile does not record one. */
function registryTarballUrl(c) {
  if (!c.name || !c.version) return null;
  return `${NPM_REGISTRY}/${c.name}/-/${c.name.split('/').pop()}-${c.version}.tgz`;
}

/** Common SPDX license ids that are safe to emit as CycloneDX `license.id`. */
const SPDX_IDS = new Set([
  '0BSD', 'AFL-2.1', 'AFL-3.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-1.1',
  'Apache-2.0', 'Artistic-2.0', 'BlueOak-1.0.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BSL-1.0',
  'CC-BY-3.0', 'CC-BY-4.0', 'CC-BY-SA-4.0', 'CC0-1.0', 'CDDL-1.0', 'CDDL-1.1', 'EPL-1.0', 'EPL-2.0',
  'EUPL-1.1', 'EUPL-1.2', 'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0-only',
  'GPL-3.0-or-later', 'ISC', 'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0',
  'LGPL-3.0-only', 'LGPL-3.0-or-later', 'MIT', 'MIT-0', 'MPL-1.1', 'MPL-2.0', 'OFL-1.1', 'Python-2.0',
  'Unicode-3.0', 'Unicode-DFS-2016', 'Unlicense', 'UPL-1.0', 'W3C', 'WTFPL', 'Zlib',
]);

module.exports = { generateSbom };
