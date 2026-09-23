'use strict';

const crypto = require('node:crypto');
const { buildPurl } = require('./lockfile-parser');

const TOOL_NAME = 'cra-audit';
const TOOL_VERSION = require('../../package.json').version;

/**
 * VEX (Vulnerability Exploitability eXchange) states the exploitability of
 * each known vulnerability in the product. TR-03183-2 keeps vulnerability data
 * out of the SBOM and points to VEX for it, and the CRA asks manufacturers to
 * document how each vulnerability was assessed.
 *
 * The assessments come from the policy allowlist
 * (`vulnerabilities.allowlist` in .cra-audit.json). Entries can be plain ids
 * or package names (legacy), or objects:
 *
 *   { "id": "CVE-2021-23337", "package": "lodash",
 *     "status": "not_affected", "justification": "code_not_reachable",
 *     "detail": "We never call _.template with user input." }
 */

/** Statuses, as written in the policy, and whether they accept the finding. */
const STATUSES = {
  not_affected: { accepts: true, cdx: 'not_affected', openvex: 'not_affected' },
  false_positive: { accepts: true, cdx: 'false_positive', openvex: 'not_affected' },
  affected: { accepts: false, cdx: 'exploitable', openvex: 'affected' },
  under_investigation: { accepts: false, cdx: 'in_triage', openvex: 'under_investigation' },
};

/**
 * Justifications accepted in the policy (CycloneDX or OpenVEX vocabulary) and
 * their equivalent in the other format.
 */
const JUSTIFICATIONS = {
  code_not_present: { cdx: 'code_not_present', openvex: 'vulnerable_code_not_present' },
  code_not_reachable: { cdx: 'code_not_reachable', openvex: 'vulnerable_code_not_in_execute_path' },
  requires_configuration: { cdx: 'requires_configuration', openvex: 'vulnerable_code_cannot_be_controlled_by_adversary' },
  requires_dependency: { cdx: 'requires_dependency', openvex: 'vulnerable_code_not_in_execute_path' },
  requires_environment: { cdx: 'requires_environment', openvex: 'vulnerable_code_cannot_be_controlled_by_adversary' },
  protected_by_compiler: { cdx: 'protected_by_compiler', openvex: 'inline_mitigations_already_exist' },
  protected_at_runtime: { cdx: 'protected_at_runtime', openvex: 'inline_mitigations_already_exist' },
  protected_at_perimeter: { cdx: 'protected_at_perimeter', openvex: 'inline_mitigations_already_exist' },
  protected_by_mitigating_control: { cdx: 'protected_by_mitigating_control', openvex: 'inline_mitigations_already_exist' },
  component_not_present: { cdx: 'code_not_present', openvex: 'component_not_present' },
  vulnerable_code_not_present: { cdx: 'code_not_present', openvex: 'vulnerable_code_not_present' },
  vulnerable_code_not_in_execute_path: { cdx: 'code_not_reachable', openvex: 'vulnerable_code_not_in_execute_path' },
  vulnerable_code_cannot_be_controlled_by_adversary: { cdx: 'requires_environment', openvex: 'vulnerable_code_cannot_be_controlled_by_adversary' },
  inline_mitigations_already_exist: { cdx: 'protected_by_mitigating_control', openvex: 'inline_mitigations_already_exist' },
};

/**
 * Normalizes the policy allowlist into assessment objects.
 * @returns {Array<{ id: string|null, package: string|null, status: string, justification: string|null, detail: string|null }>}
 */
function normalizeAllowlist(policy) {
  const list = (policy && policy.vulnerabilities && policy.vulnerabilities.allowlist) || [];
  return list.map((entry) => {
    if (typeof entry === 'string') {
      // Legacy form: a package name, an advisory id/alias or an advisory URL fragment.
      return { id: entry, package: null, status: 'not_affected', justification: null, detail: null, legacy: true };
    }
    const status = STATUSES[entry.status] ? entry.status : 'not_affected';
    return {
      id: entry.id || null,
      package: entry.package || null,
      status,
      justification: JUSTIFICATIONS[entry.justification] ? entry.justification : null,
      detail: entry.detail || null,
    };
  });
}

/** Does an assessment apply to one advisory of a finding? */
function entryMatches(entry, finding, source) {
  if (entry.legacy && entry.id === finding.name) return true;
  if (entry.package && entry.package !== finding.name) return false;
  if (!entry.id) return Boolean(entry.package);
  const ids = [source.id, ...(source.aliases || [])].filter(Boolean);
  return ids.includes(entry.id) || Boolean(source.url && source.url.includes(entry.id));
}

/** The assessment recorded for one advisory of a finding, if any. */
function assessmentFor(finding, source, entries) {
  return entries.find((e) => entryMatches(e, finding, source)) || null;
}

/**
 * A finding is accepted when every advisory on it has an accepting assessment
 * (not_affected / false_positive). Malicious packages are never accepted.
 *
 * @returns {{ accepted: boolean, unjustified: number }}
 */
function acceptance(finding, policy) {
  const entries = normalizeAllowlist(policy);
  if (!entries.length || finding.malicious) return { accepted: false, unjustified: 0 };
  const assessments = finding.sources.map((s) => assessmentFor(finding, s, entries));
  const accepted = assessments.every((a) => a && STATUSES[a.status].accepts);
  const unjustified = accepted ? assessments.filter((a) => !a.justification && !a.detail).length : 0;
  return { accepted, unjustified };
}

// --- Documents -------------------------------------------------------------

/**
 * Builds a VEX document for the vulnerability findings of an audit.
 *
 * @param {{ name: string, version: string }} product
 * @param {object} vulnSection Result of scanVulnerabilities().
 * @param {object} policy
 * @param {{ format?: 'cyclonedx'|'openvex', author?: string|null }} [options]
 */
function buildVex(product, vulnSection, policy, { format = 'cyclonedx', author = null } = {}) {
  const entries = normalizeAllowlist(policy);
  const productPurl = buildPurl(product.name, product.version);
  const statements = [];

  for (const finding of vulnSection.vulnerabilities || []) {
    const purl = buildPurl(finding.name, finding.version);
    for (const source of finding.sources) {
      const assessment = finding.malicious ? null : assessmentFor(finding, source, entries);
      statements.push({ finding, source, purl, assessment });
    }
  }

  return format === 'openvex'
    ? buildOpenVex(productPurl, statements, author)
    : buildCycloneDxVex(product, productPurl, statements);
}

function buildCycloneDxVex(product, productPurl, statements) {
  const vulnerabilities = statements.map(({ finding, source, purl, assessment }) => {
    const { primary, others } = identifiers(source);
    const analysis = { state: cdxState(finding, assessment) };
    if (assessment && assessment.justification) analysis.justification = JUSTIFICATIONS[assessment.justification].cdx;
    const detail = analysisDetail(finding, source, assessment);
    if (detail) analysis.detail = detail;
    if (analysis.state === 'exploitable' || analysis.state === 'in_triage') {
      analysis.response = finding.malicious ? ['update'] : finding.fixAvailable ? ['update'] : ['can_not_fix'];
    }

    const vuln = {
      'bom-ref': `${primary}@${purl}`,
      id: primary,
      source: { name: 'OSV', url: `https://osv.dev/vulnerability/${source.id}` },
      references: others.map((id) => ({ id, source: { name: sourceName(id), url: advisoryUrl(id) } })),
      ratings: [{
        source: { name: 'OSV' },
        severity: cdxSeverity(source.severity),
        ...(source.cvss !== null && source.cvss !== undefined ? { score: source.cvss, method: 'CVSSv31' } : {}),
      }],
      cwes: (source.cwe || []).map((c) => parseInt(String(c).replace(/^CWE-/i, ''), 10)).filter(Number.isFinite),
      description: source.title || undefined,
      advisories: source.url ? [{ url: source.url }] : undefined,
      affects: [{ ref: purl }],
      analysis,
    };
    if (source.kev) {
      vuln.properties = [
        { name: 'cra-audit:kev', value: 'true' },
        { name: 'cra-audit:kev:dateAdded', value: String(source.kev.dateAdded) },
      ];
    }
    if (!vuln.references.length) delete vuln.references;
    if (!vuln.cwes.length) delete vuln.cwes;
    return vuln;
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: TOOL_NAME, version: TOOL_VERSION }] },
      component: { type: 'application', 'bom-ref': productPurl, name: product.name, version: product.version, purl: productPurl },
    },
    vulnerabilities,
  };
}

function buildOpenVex(productPurl, statements, author) {
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://openvex.dev/docs/public/cra-audit-${crypto.randomUUID()}`,
    author: author || TOOL_NAME,
    timestamp: new Date().toISOString(),
    version: 1,
    tooling: `${TOOL_NAME}/${TOOL_VERSION}`,
    statements: statements.map(({ finding, source, purl, assessment }) => {
      const { primary, others } = identifiers(source);
      const status = finding.malicious ? 'affected' : assessment ? STATUSES[assessment.status].openvex : 'under_investigation';
      const statement = {
        vulnerability: { name: primary, ...(others.length ? { aliases: others } : {}) },
        products: [{ '@id': productPurl, subcomponents: [{ '@id': purl }] }],
        status,
      };
      const detail = analysisDetail(finding, source, assessment);
      if (status === 'not_affected') {
        if (assessment.justification) statement.justification = JUSTIFICATIONS[assessment.justification].openvex;
        // OpenVEX requires a justification or an impact statement.
        statement.impact_statement = detail || 'Assessed as not affected; justification not recorded in the cra-audit policy.';
      } else if (status === 'affected') {
        statement.action_statement = actionStatement(finding);
      } else if (detail) {
        statement.status_notes = detail;
      }
      return statement;
    }),
  };
}

function cdxState(finding, assessment) {
  if (finding.malicious) return 'exploitable';
  return assessment ? STATUSES[assessment.status].cdx : 'in_triage';
}

function analysisDetail(finding, source, assessment) {
  const parts = [];
  if (finding.malicious) parts.push('Malicious package (OpenSSF malicious-packages): remove it and rotate exposed credentials.');
  if (source.kev) parts.push(`Listed in CISA KEV (actively exploited) since ${source.kev.dateAdded}.`);
  if (assessment && assessment.detail) parts.push(assessment.detail);
  if (assessment && !assessment.detail && !assessment.justification && STATUSES[assessment.status].accepts) {
    parts.push('Accepted in the cra-audit policy without a recorded justification.');
  }
  return parts.join(' ') || undefined;
}

function actionStatement(finding) {
  if (finding.malicious) return `Remove ${finding.name}@${finding.version}, reinstall from a clean lockfile and rotate exposed credentials.`;
  if (finding.fixAvailable && typeof finding.fixAvailable === 'object') {
    return `Update ${finding.name} to ${finding.fixAvailable.version} or later.`;
  }
  return `No fixed version of ${finding.name} is available: remove or replace the dependency, or mitigate.`;
}

/** Prefer the CVE as the VEX id; keep the rest as references/aliases. */
function identifiers(source) {
  const all = [source.id, ...(source.aliases || [])].filter(Boolean);
  const primary = all.find((id) => /^CVE-/i.test(id)) || all[0] || 'UNKNOWN';
  return { primary, others: all.filter((id) => id !== primary) };
}

function sourceName(id) {
  if (/^CVE-/i.test(id)) return 'NVD';
  if (/^GHSA-/i.test(id)) return 'GitHub';
  return 'OSV';
}

function advisoryUrl(id) {
  if (/^CVE-/i.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

/** CycloneDX uses "medium" where npm/GHSA say "moderate". */
function cdxSeverity(severity) {
  if (severity === 'moderate') return 'medium';
  return ['critical', 'high', 'medium', 'low', 'info', 'none'].includes(severity) ? severity : 'unknown';
}

module.exports = { buildVex, normalizeAllowlist, assessmentFor, acceptance, STATUSES, JUSTIFICATIONS };
