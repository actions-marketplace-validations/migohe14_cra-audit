'use strict';

const crypto = require('node:crypto');
const { parseLockfile } = require('./lockfile-parser');

const TOOL_NAME = 'cra-audit';
const TOOL_VERSION = require('../../package.json').version;

/**
 * Generates a Software Bill of Materials from the project lockfile.
 * Supported formats: CycloneDX 1.5 (JSON) and SPDX 2.3 (JSON).
 * Required by CRA Annex I and BSI TR-03183 Part 2.
 */
function generateSbom(projectRoot, { format = 'cyclonedx' } = {}) {
  const parsed = parseLockfile(projectRoot);
  if (!parsed.ok) {
    return { ok: false, error: parsed.error };
  }

  const normalizedFormat = String(format).toLowerCase();
  let document;
  if (normalizedFormat === 'spdx') {
    document = buildSpdx(parsed);
  } else if (normalizedFormat === 'cyclonedx' || normalizedFormat === 'cdx') {
    document = buildCycloneDx(parsed);
  } else {
    return { ok: false, error: `Formato de SBOM no soportado: "${format}". Usa "cyclonedx" o "spdx".` };
  }

  return {
    ok: true,
    format: normalizedFormat === 'spdx' ? 'spdx' : 'cyclonedx',
    componentCount: parsed.components.length,
    document,
  };
}

function buildCycloneDx(parsed) {
  const timestamp = new Date().toISOString();
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

  const components = parsed.components.map((c) => {
    const component = {
      type: 'library',
      'bom-ref': c.purl || `${c.name}@${c.version}`,
      name: c.name,
      version: c.version || undefined,
      scope: c.scope,
      purl: c.purl || undefined,
    };
    if (c.hashAlgorithm && c.hashValue) {
      component.hashes = [{ alg: c.hashAlgorithm, content: c.hashValue }];
    }
    if (c.license) {
      component.licenses = [normalizeCdxLicense(c.license)];
    }
    return component;
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: 'cra-audit', name: TOOL_NAME, version: TOOL_VERSION }],
      component: {
        type: 'application',
        'bom-ref': `pkg:npm/${parsed.root.name}@${parsed.root.version}`,
        name: parsed.root.name,
        version: parsed.root.version,
      },
    },
    components,
  };
}

function normalizeCdxLicense(license) {
  if (typeof license === 'string') {
    // Use SPDX expression when it contains operators, else a license id.
    if (/\s(AND|OR|WITH)\s/i.test(license)) {
      return { expression: license };
    }
    return { license: { id: license } };
  }
  return { license: { name: String(license) } };
}

function buildSpdx(parsed) {
  const created = new Date().toISOString();
  const docNamespace = `https://spdx.org/spdxdocs/${parsed.root.name}-${crypto.randomUUID()}`;

  const packages = parsed.components.map((c, index) => {
    const spdxId = `SPDXRef-Package-${index}`;
    const pkg = {
      name: c.name,
      SPDXID: spdxId,
      versionInfo: c.version || 'NOASSERTION',
      downloadLocation: c.resolved || 'NOASSERTION',
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

  const rootSpdxId = 'SPDXRef-Package-root';
  packages.unshift({
    name: parsed.root.name,
    SPDXID: rootSpdxId,
    versionInfo: parsed.root.version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
  });

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${parsed.root.name}@${parsed.root.version}`,
    documentNamespace: docNamespace,
    creationInfo: {
      created,
      creators: [`Tool: ${TOOL_NAME}-${TOOL_VERSION}`],
    },
    documentDescribes: [rootSpdxId],
    packages,
  };
}

module.exports = { generateSbom };
