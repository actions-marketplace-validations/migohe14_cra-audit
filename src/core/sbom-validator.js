'use strict';

/**
 * Validates an SBOM document against the requirements of CRA Annex I and
 * BSI TR-03183-2 v2.1.0. It auto-detects whether the document is CycloneDX
 * or SPDX.
 *
 * TR-03183-2 v2.1.0 requirements checked:
 *  - §4:     format CycloneDX >= 1.6 or SPDX >= 3.0.1
 *  - §5.2.1: creator of the SBOM (email or URL) and timestamp
 *  - §5.2.2: for each component: creator (email or URL), name, version,
 *            filename, dependencies (and completeness of that enumeration),
 *            licence, SHA-512 hash of the deployable component and the
 *            executable / archive / structured properties
 *  - §5.2.4: unique identifier (purl, CPE, SWID)
 */
function validateSbom(document) {
  if (!document || typeof document !== 'object') {
    return invalid('The SBOM is not a valid JSON object.');
  }

  if (document.bomFormat === 'CycloneDX' || document.specVersion) {
    return validateCycloneDx(document);
  }
  if (document.spdxVersion || document.SPDXID === 'SPDXRef-DOCUMENT') {
    return validateSpdx(document);
  }

  return invalid('Unrecognized SBOM format (neither CycloneDX nor SPDX).');
}

const BSI_PROPERTIES = ['bsi:component:executable', 'bsi:component:archive', 'bsi:component:structured'];

function validateCycloneDx(doc) {
  const issues = [];
  const checks = [];
  const metadata = doc.metadata || {};

  pushCheck(checks, 'format', 'Format declared (CycloneDX)', doc.bomFormat === 'CycloneDX');
  pushCheck(checks, 'specVersion', 'Specification version CycloneDX >= 1.6 (TR-03183-2 §4)',
    compareVersions(doc.specVersion, '1.6') >= 0);
  pushCheck(checks, 'serialNumber', 'Unique document identifier (serialNumber)', Boolean(doc.serialNumber));
  pushCheck(checks, 'timestamp', 'Creation timestamp', Boolean(metadata.timestamp));
  pushCheck(checks, 'author', 'Creator of the SBOM (email or URL)',
    hasCdxContact(metadata.manufacturer) || toArray(metadata.authors).some((a) => a && a.email));
  pushCheck(checks, 'rootComponent', 'Root component (product) identified',
    Boolean(metadata.component && metadata.component.name));

  const components = toArray(doc.components);
  pushCheck(checks, 'components', 'Contains at least one component', components.length > 0);

  const graphRefs = new Set(toArray(doc.dependencies).map((d) => d && d.ref));
  const stats = {
    total: components.length,
    missingVersion: 0,
    missingCreator: 0,
    missingFilename: 0,
    missingHash: 0,
    missingLicense: 0,
    missingPurl: 0,
    missingProperties: 0,
    missingDependencies: 0,
  };

  for (const comp of components) {
    const label = comp.name || comp['bom-ref'] || 'unknown';
    const props = new Map(toArray(comp.properties).map((p) => [p && p.name, p && p.value]));

    if (!comp.version) { stats.missingVersion++; issues.push(`Component without a version: ${label}`); }
    if (!hasCdxContact(comp.manufacturer) && !hasCdxContact(comp.supplier) && !hasEmail(comp.authors)) {
      stats.missingCreator++; issues.push(`Component without a creator (email or URL): ${label}`);
    }
    if (!props.get('bsi:component:filename')) { stats.missingFilename++; issues.push(`Component without a filename: ${label}`); }
    if (!hasCdxSha512(comp)) { stats.missingHash++; issues.push(`Component without a SHA-512 hash: ${label}`); }
    if (!hasCdxLicense(comp)) { stats.missingLicense++; issues.push(`Component without a license: ${label}`); }
    if (!comp.purl && !comp.cpe && !comp.swid && !comp['bom-ref']) {
      stats.missingPurl++; issues.push(`Component without a unique identifier (purl): ${label}`);
    }
    if (BSI_PROPERTIES.some((name) => !props.get(name))) {
      stats.missingProperties++; issues.push(`Component without the executable/archive/structured properties: ${label}`);
    }
    if (!graphRefs.has(comp['bom-ref'])) {
      stats.missingDependencies++; issues.push(`Component missing from the dependency graph: ${label}`);
    }
  }

  const completeness = toArray(doc.compositions).some((c) => c && c.aggregate);

  pushCheck(checks, 'componentVersions', 'All components have a version', stats.missingVersion === 0);
  pushCheck(checks, 'componentCreators', 'All components have a creator (email or URL)', stats.missingCreator === 0);
  pushCheck(checks, 'componentFilenames', 'All components have a filename', stats.missingFilename === 0);
  pushCheck(checks, 'componentHashes', 'All components have a SHA-512 hash', stats.missingHash === 0);
  pushCheck(checks, 'componentLicenses', 'All components have a license', stats.missingLicense === 0);
  pushCheck(checks, 'componentIdentifiers', 'All components have a unique identifier', stats.missingPurl === 0);
  pushCheck(checks, 'componentProperties', 'All components declare executable/archive/structured', stats.missingProperties === 0);
  pushCheck(checks, 'dependencyGraph', 'Dependency graph covers every component', stats.missingDependencies === 0);
  pushCheck(checks, 'dependencyCompleteness', 'Completeness of the dependency graph declared (compositions)', completeness);

  return summarize('cyclonedx', checks, issues, stats);
}

function validateSpdx(doc) {
  const issues = [];
  const checks = [];
  const creators = toArray(doc.creationInfo && doc.creationInfo.creators);

  pushCheck(checks, 'format', 'Format declared (SPDX)', Boolean(doc.spdxVersion));
  const spdxVersion = String(doc.spdxVersion || '').replace(/^SPDX-/, '');
  pushCheck(checks, 'specVersion', 'Specification version SPDX >= 3.0.1 (TR-03183-2 §4; use CycloneDX)',
    compareVersions(spdxVersion, '3.0.1') >= 0);
  pushCheck(checks, 'dataLicense', 'Data license declared', Boolean(doc.dataLicense));
  pushCheck(checks, 'serialNumber', 'Unique document namespace', Boolean(doc.documentNamespace));
  pushCheck(checks, 'timestamp', 'Creation timestamp', Boolean(doc.creationInfo && doc.creationInfo.created));
  pushCheck(checks, 'author', 'Creator of the SBOM (organization or person)',
    creators.some((c) => /^(Organization|Person):/.test(String(c))));

  const packages = toArray(doc.packages);
  pushCheck(checks, 'components', 'Contains at least one package', packages.length > 0);

  const relationships = toArray(doc.relationships);
  // Dependency edges as written by SPDX tools (Syft uses CONTAINS and
  // DEPENDENCY_OF); the described package is the product, not a component.
  const graphTypes = /^(DEPENDS_ON|CONTAINS|DEPENDENCY_OF|[A-Z_]+_DEPENDENCY_OF)$/;
  const described = new Set(toArray(doc.documentDescribes));
  const inGraph = new Set();
  for (const r of relationships) {
    if (!r) continue;
    if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === 'SPDXRef-DOCUMENT') described.add(r.relatedSpdxElement);
    if (graphTypes.test(r.relationshipType)) {
      inGraph.add(r.spdxElementId);
      inGraph.add(r.relatedSpdxElement);
    }
  }

  const stats = {
    total: packages.length,
    missingVersion: 0,
    missingCreator: 0,
    missingFilename: 0,
    missingHash: 0,
    missingLicense: 0,
    missingPurl: 0,
    missingDependencies: 0,
  };
  for (const pkg of packages) {
    const label = pkg.name || pkg.SPDXID || 'unknown';
    if (pkg.SPDXID === 'SPDXRef-Package-root' || described.has(pkg.SPDXID)) continue;
    if (!pkg.versionInfo || pkg.versionInfo === 'NOASSERTION') { stats.missingVersion++; issues.push(`Package without a version: ${label}`); }
    if (!isAssertion(pkg.originator) && !isAssertion(pkg.supplier)) { stats.missingCreator++; issues.push(`Package without an originator: ${label}`); }
    if (!pkg.packageFileName) { stats.missingFilename++; issues.push(`Package without a filename: ${label}`); }
    if (!toArray(pkg.checksums).some((c) => /^SHA-?512$/i.test(String(c && c.algorithm)))) {
      stats.missingHash++; issues.push(`Package without a SHA-512 checksum: ${label}`);
    }
    if (!isAssertion(pkg.licenseConcluded)) { stats.missingLicense++; issues.push(`Package without a license: ${label}`); }
    if (!toArray(pkg.externalRefs).some((r) => r.referenceType === 'purl')) { stats.missingPurl++; issues.push(`Package without a purl: ${label}`); }
    if (packages.length > 2 && !inGraph.has(pkg.SPDXID)) {
      stats.missingDependencies++; issues.push(`Package missing from the dependency graph: ${label}`);
    }
  }

  pushCheck(checks, 'componentVersions', 'All packages have a version', stats.missingVersion === 0);
  pushCheck(checks, 'componentCreators', 'All packages have an originator', stats.missingCreator === 0);
  pushCheck(checks, 'componentFilenames', 'All packages have a filename', stats.missingFilename === 0);
  pushCheck(checks, 'componentHashes', 'All packages have a SHA-512 checksum', stats.missingHash === 0);
  pushCheck(checks, 'componentLicenses', 'All packages have a license', stats.missingLicense === 0);
  pushCheck(checks, 'componentIdentifiers', 'All packages have a purl', stats.missingPurl === 0);
  pushCheck(checks, 'dependencyGraph', 'Dependency relationships declared for every package', stats.missingDependencies === 0);

  return summarize('spdx', checks, issues, stats);
}

/** CycloneDX organizational entity with an email contact or a URL. */
function hasCdxContact(entity) {
  if (!entity || typeof entity !== 'object') return false;
  return toArray(entity.url).length > 0 || hasEmail(entity.contact);
}

function hasEmail(people) {
  return toArray(people).some((p) => p && p.email);
}

/** SHA-512 in `hashes` or on the `distribution` reference (TR-03183 mapping). */
function hasCdxSha512(comp) {
  const isSha512 = (h) => h && h.alg === 'SHA-512' && h.content;
  if (toArray(comp.hashes).some(isSha512)) return true;
  return toArray(comp.externalReferences).some((ref) => ref && toArray(ref.hashes).some(isSha512));
}

function hasCdxLicense(comp) {
  return toArray(comp.licenses).length > 0;
}

function isAssertion(value) {
  return Boolean(value) && value !== 'NOASSERTION' && value !== 'NONE';
}

/** Compares dotted numeric versions ("1.6" vs "1.5"); missing parts are 0. */
function compareVersions(a, b) {
  if (!a) return -1;
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

function pushCheck(checks, id, label, passed) {
  checks.push({ id, label, passed: Boolean(passed) });
}

function summarize(format, checks, issues, stats) {
  const failed = checks.filter((c) => !c.passed);
  return {
    ok: true,
    format,
    valid: failed.length === 0,
    checks,
    failedChecks: failed,
    issues,
    stats,
  };
}

function invalid(message) {
  return { ok: false, valid: false, error: message, checks: [], issues: [message] };
}

module.exports = { validateSbom };
