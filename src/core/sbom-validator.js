'use strict';

/**
 * Validates an SBOM document against the minimum elements required by
 * CRA Annex I (2)(1) and BSI TR-03183 Part 2. It auto-detects whether the
 * document is CycloneDX or SPDX.
 *
 * Minimum required elements (TR-03183 §6 "minimum elements"):
 *  - SBOM format declared (CycloneDX or SPDX)
 *  - Author / creator of the SBOM
 *  - Timestamp of creation
 *  - For each component: name, version, supplier/author, unique identifier,
 *    cryptographic hash, license and dependency relationship.
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

function validateCycloneDx(doc) {
  const issues = [];
  const checks = [];

  pushCheck(checks, 'format', 'Format declared (CycloneDX)', doc.bomFormat === 'CycloneDX');
  pushCheck(checks, 'specVersion', 'Specification version present', Boolean(doc.specVersion));
  pushCheck(checks, 'serialNumber', 'Unique document identifier (serialNumber)', Boolean(doc.serialNumber));
  pushCheck(checks, 'timestamp', 'Creation timestamp', Boolean(doc.metadata && doc.metadata.timestamp));
  pushCheck(checks, 'author', 'Author / generating tool declared',
    Boolean(doc.metadata && (doc.metadata.tools || doc.metadata.authors)));
  pushCheck(checks, 'rootComponent', 'Root component (product) identified',
    Boolean(doc.metadata && doc.metadata.component && doc.metadata.component.name));

  const components = Array.isArray(doc.components) ? doc.components : [];
  pushCheck(checks, 'components', 'Contains at least one component', components.length > 0);

  const stats = { total: components.length, missingVersion: 0, missingHash: 0, missingLicense: 0, missingPurl: 0 };
  for (const comp of components) {
    const label = comp.name || comp['bom-ref'] || 'unknown';
    if (!comp.version) { stats.missingVersion++; issues.push(`Component without a version: ${label}`); }
    if (!hasCdxHash(comp)) { stats.missingHash++; issues.push(`Component without a cryptographic hash: ${label}`); }
    if (!hasCdxLicense(comp)) { stats.missingLicense++; issues.push(`Component without a license: ${label}`); }
    if (!comp.purl && !comp['bom-ref']) { stats.missingPurl++; issues.push(`Component without a unique identifier (purl): ${label}`); }
  }

  pushCheck(checks, 'componentVersions', 'All components have a version', stats.missingVersion === 0);
  pushCheck(checks, 'componentHashes', 'All components have a cryptographic hash', stats.missingHash === 0);
  pushCheck(checks, 'componentLicenses', 'All components have a license', stats.missingLicense === 0);
  pushCheck(checks, 'componentIdentifiers', 'All components have a unique identifier', stats.missingPurl === 0);

  return summarize('cyclonedx', checks, issues, stats);
}

function validateSpdx(doc) {
  const issues = [];
  const checks = [];

  pushCheck(checks, 'format', 'Format declared (SPDX)', Boolean(doc.spdxVersion));
  pushCheck(checks, 'dataLicense', 'Data license declared', Boolean(doc.dataLicense));
  pushCheck(checks, 'serialNumber', 'Unique document namespace', Boolean(doc.documentNamespace));
  pushCheck(checks, 'timestamp', 'Creation timestamp', Boolean(doc.creationInfo && doc.creationInfo.created));
  pushCheck(checks, 'author', 'Author / creator declared',
    Boolean(doc.creationInfo && Array.isArray(doc.creationInfo.creators) && doc.creationInfo.creators.length));

  const packages = Array.isArray(doc.packages) ? doc.packages : [];
  pushCheck(checks, 'components', 'Contains at least one package', packages.length > 0);

  const stats = { total: packages.length, missingVersion: 0, missingHash: 0, missingLicense: 0, missingPurl: 0 };
  for (const pkg of packages) {
    const label = pkg.name || pkg.SPDXID || 'unknown';
    if (pkg.SPDXID === 'SPDXRef-Package-root') continue;
    if (!pkg.versionInfo || pkg.versionInfo === 'NOASSERTION') { stats.missingVersion++; issues.push(`Package without a version: ${label}`); }
    if (!Array.isArray(pkg.checksums) || pkg.checksums.length === 0) { stats.missingHash++; issues.push(`Package without a checksum: ${label}`); }
    if (!pkg.licenseConcluded || pkg.licenseConcluded === 'NOASSERTION') { stats.missingLicense++; issues.push(`Package without a license: ${label}`); }
    if (!Array.isArray(pkg.externalRefs) || !pkg.externalRefs.some((r) => r.referenceType === 'purl')) { stats.missingPurl++; issues.push(`Package without a purl: ${label}`); }
  }

  pushCheck(checks, 'componentVersions', 'All packages have a version', stats.missingVersion === 0);
  pushCheck(checks, 'componentHashes', 'All packages have a checksum', stats.missingHash === 0);
  pushCheck(checks, 'componentLicenses', 'All packages have a license', stats.missingLicense === 0);
  pushCheck(checks, 'componentIdentifiers', 'All packages have a purl', stats.missingPurl === 0);

  return summarize('spdx', checks, issues, stats);
}

function hasCdxHash(comp) {
  return Array.isArray(comp.hashes) && comp.hashes.length > 0;
}

function hasCdxLicense(comp) {
  return Array.isArray(comp.licenses) && comp.licenses.length > 0;
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
