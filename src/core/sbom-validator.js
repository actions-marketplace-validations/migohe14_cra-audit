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
    return invalid('El SBOM no es un objeto JSON válido.');
  }

  if (document.bomFormat === 'CycloneDX' || document.specVersion) {
    return validateCycloneDx(document);
  }
  if (document.spdxVersion || document.SPDXID === 'SPDXRef-DOCUMENT') {
    return validateSpdx(document);
  }

  return invalid('Formato de SBOM no reconocido (no es CycloneDX ni SPDX).');
}

function validateCycloneDx(doc) {
  const issues = [];
  const checks = [];

  pushCheck(checks, 'format', 'Formato declarado (CycloneDX)', doc.bomFormat === 'CycloneDX');
  pushCheck(checks, 'specVersion', 'Versión de especificación presente', Boolean(doc.specVersion));
  pushCheck(checks, 'serialNumber', 'Identificador único del documento (serialNumber)', Boolean(doc.serialNumber));
  pushCheck(checks, 'timestamp', 'Marca temporal de creación', Boolean(doc.metadata && doc.metadata.timestamp));
  pushCheck(checks, 'author', 'Autor / herramienta generadora declarada',
    Boolean(doc.metadata && (doc.metadata.tools || doc.metadata.authors)));
  pushCheck(checks, 'rootComponent', 'Componente raíz (producto) identificado',
    Boolean(doc.metadata && doc.metadata.component && doc.metadata.component.name));

  const components = Array.isArray(doc.components) ? doc.components : [];
  pushCheck(checks, 'components', 'Contiene al menos un componente', components.length > 0);

  const stats = { total: components.length, missingVersion: 0, missingHash: 0, missingLicense: 0, missingPurl: 0 };
  for (const comp of components) {
    const label = comp.name || comp['bom-ref'] || 'desconocido';
    if (!comp.version) { stats.missingVersion++; issues.push(`Componente sin versión: ${label}`); }
    if (!hasCdxHash(comp)) { stats.missingHash++; issues.push(`Componente sin hash criptográfico: ${label}`); }
    if (!hasCdxLicense(comp)) { stats.missingLicense++; issues.push(`Componente sin licencia: ${label}`); }
    if (!comp.purl && !comp['bom-ref']) { stats.missingPurl++; issues.push(`Componente sin identificador único (purl): ${label}`); }
  }

  pushCheck(checks, 'componentVersions', 'Todos los componentes tienen versión', stats.missingVersion === 0);
  pushCheck(checks, 'componentHashes', 'Todos los componentes tienen hash criptográfico', stats.missingHash === 0);
  pushCheck(checks, 'componentLicenses', 'Todos los componentes tienen licencia', stats.missingLicense === 0);
  pushCheck(checks, 'componentIdentifiers', 'Todos los componentes tienen identificador único', stats.missingPurl === 0);

  return summarize('cyclonedx', checks, issues, stats);
}

function validateSpdx(doc) {
  const issues = [];
  const checks = [];

  pushCheck(checks, 'format', 'Formato declarado (SPDX)', Boolean(doc.spdxVersion));
  pushCheck(checks, 'dataLicense', 'Licencia de los datos declarada', Boolean(doc.dataLicense));
  pushCheck(checks, 'serialNumber', 'Namespace único del documento', Boolean(doc.documentNamespace));
  pushCheck(checks, 'timestamp', 'Marca temporal de creación', Boolean(doc.creationInfo && doc.creationInfo.created));
  pushCheck(checks, 'author', 'Autor / creador declarado',
    Boolean(doc.creationInfo && Array.isArray(doc.creationInfo.creators) && doc.creationInfo.creators.length));

  const packages = Array.isArray(doc.packages) ? doc.packages : [];
  pushCheck(checks, 'components', 'Contiene al menos un paquete', packages.length > 0);

  const stats = { total: packages.length, missingVersion: 0, missingHash: 0, missingLicense: 0, missingPurl: 0 };
  for (const pkg of packages) {
    const label = pkg.name || pkg.SPDXID || 'desconocido';
    if (pkg.SPDXID === 'SPDXRef-Package-root') continue;
    if (!pkg.versionInfo || pkg.versionInfo === 'NOASSERTION') { stats.missingVersion++; issues.push(`Paquete sin versión: ${label}`); }
    if (!Array.isArray(pkg.checksums) || pkg.checksums.length === 0) { stats.missingHash++; issues.push(`Paquete sin checksum: ${label}`); }
    if (!pkg.licenseConcluded || pkg.licenseConcluded === 'NOASSERTION') { stats.missingLicense++; issues.push(`Paquete sin licencia: ${label}`); }
    if (!Array.isArray(pkg.externalRefs) || !pkg.externalRefs.some((r) => r.referenceType === 'purl')) { stats.missingPurl++; issues.push(`Paquete sin purl: ${label}`); }
  }

  pushCheck(checks, 'componentVersions', 'Todos los paquetes tienen versión', stats.missingVersion === 0);
  pushCheck(checks, 'componentHashes', 'Todos los paquetes tienen checksum', stats.missingHash === 0);
  pushCheck(checks, 'componentLicenses', 'Todos los paquetes tienen licencia', stats.missingLicense === 0);
  pushCheck(checks, 'componentIdentifiers', 'Todos los paquetes tienen purl', stats.missingPurl === 0);

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
