'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readJson } = require('../utils/fs');
const { parseLockfile } = require('./lockfile-parser');
const { repositoryUrl } = require('./installed-metadata');
const { readManifests } = require('./manifest-reader');

/**
 * Organisational CRA duties that can be checked from the repository itself:
 * the vulnerability disclosure policy, a contact for vulnerability reports,
 * the support period, a security.txt and the ability to produce an SBOM.
 *
 * `required` checks fail the command; `recommended` ones only warn.
 */

const SECURITY_MD_PATHS = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'];
const SECURITY_TXT_PATHS = [
  '.well-known/security.txt',
  'public/.well-known/security.txt',
  'static/.well-known/security.txt',
  'src/.well-known/security.txt',
  'security.txt',
];
const DAY = 24 * 60 * 60 * 1000;

const EMAIL = /[\w.+-]+@[\w-]+\.[\w.-]+/;
const URL = /https?:\/\/\S+/;

/**
 * @param {string} projectRoot
 * @param {{ now?: Date }} [options]
 * @returns {{ checks: Array<object>, passed: boolean, files: object }}
 */
function checkReadiness(projectRoot, { now = new Date() } = {}) {
  const checks = [];
  const add = (id, label, level, passed, detail, reference) => checks.push({ id, label, level, passed: Boolean(passed), detail, reference });

  const securityMdPath = firstExisting(projectRoot, SECURITY_MD_PATHS);
  const securityMd = securityMdPath ? read(path.join(projectRoot, securityMdPath)) : '';
  const readme = read(path.join(projectRoot, 'README.md'));
  const pkg = readJson(path.join(projectRoot, 'package.json')) || {};

  // --- Coordinated vulnerability disclosure policy --------------------------
  add('security-policy', 'Vulnerability disclosure policy (SECURITY.md)', 'required', securityMdPath,
    securityMdPath ? `Found ${securityMdPath}` : `None of ${SECURITY_MD_PATHS.join(', ')} exists`,
    'CRA Annex I Part II (5)');

  const reportingChannel = EMAIL.test(securityMd) || /security\/advisories|report[^\n]*vulnerabilit[^\n]*https?:\/\//i.test(securityMd) || URL.test(securityMd);
  add('security-contact', 'Contact address for vulnerability reports', 'required', securityMdPath && reportingChannel,
    !securityMdPath ? 'No SECURITY.md' : reportingChannel ? 'Email address or reporting URL found' : 'SECURITY.md has no email address or reporting URL',
    'CRA Annex I Part II (6) · Annex II (2)');

  // --- Support period ---------------------------------------------------------
  const supportText = `${securityMd}\n${readme}`;
  const supportMention = /support(ed)?\s+period|supported\s+until|end\s+of\s+(security\s+)?support|end[-\s]of[-\s]life|\bEOL\b/i.test(supportText);
  const supportDate = supportMention && /\b(19|20)\d{2}-\d{2}(-\d{2})?\b|\b\d+\s+years?\b/i.test(supportText);
  add('support-period', 'Support period and its end date stated', 'required', supportMention && supportDate,
    !supportMention ? 'No mention of the support period in SECURITY.md or README.md'
      : supportDate ? 'Support period with an end date or duration found' : 'Support period mentioned without an end date',
    'CRA Art. 13(8) · Annex II (7)');

  // --- Recommended content ------------------------------------------------------
  add('supported-versions', 'Supported versions listed', 'recommended',
    /supported\s+versions/i.test(securityMd), 'A "Supported Versions" section in SECURITY.md', 'CRA Annex II (7)');
  add('response-timeline', 'Response timeline for reporters', 'recommended',
    /\b\d+\s*(business\s+)?(hours?|days?|weeks?)\b/i.test(securityMd), 'Acknowledgement / fix time frames in SECURITY.md',
    'CRA Annex I Part II (5)');
  add('art14-process', 'Art. 14 reporting process (CSIRT / ENISA, 24 h / 72 h)', 'recommended',
    /ENISA|CSIRT|single\s+reporting\s+platform|24\s*h(ours)?/i.test(securityMd),
    'How actively exploited vulnerabilities and severe incidents are reported', 'CRA Art. 14');

  // --- security.txt (RFC 9116) --------------------------------------------------
  const securityTxtPath = firstExisting(projectRoot, SECURITY_TXT_PATHS);
  const txt = parseSecurityTxt(securityTxtPath ? read(path.join(projectRoot, securityTxtPath)) : '');
  if (!securityTxtPath) {
    add('security-txt', 'security.txt published (RFC 9116)', 'recommended', false,
      'No .well-known/security.txt found (recommended for products with a web presence)', 'RFC 9116 · CRA Annex II (2)');
  } else {
    const expires = txt.expires ? new Date(txt.expires) : null;
    const validExpiry = expires && !Number.isNaN(expires.getTime());
    add('security-txt', 'security.txt published (RFC 9116)', 'recommended', true, `Found ${securityTxtPath}`, 'RFC 9116');
    add('security-txt-contact', 'security.txt has a Contact field', 'required', txt.contact.length > 0,
      txt.contact.length ? txt.contact.join(', ') : 'Missing Contact:', 'RFC 9116 §2.5.3');
    add('security-txt-expires', 'security.txt Expires is set and in the future', 'required', validExpiry && expires > now,
      !txt.expires ? 'Missing Expires:' : !validExpiry ? `Invalid date: ${txt.expires}` : expires > now ? `Expires ${txt.expires}` : `Expired on ${txt.expires}`,
      'RFC 9116 §2.5.5');
    if (validExpiry && expires > now) {
      add('security-txt-expiry-window', 'security.txt Expires is less than a year away', 'recommended',
        expires - now <= 366 * DAY, `Expires in ${Math.round((expires - now) / DAY)} days`, 'RFC 9116 §2.5.5');
    }
  }

  // --- Unfilled templates (`readiness --init`) ------------------------------------
  const securityTxtText = securityTxtPath ? read(path.join(projectRoot, securityTxtPath)) : '';
  const todo = [[securityMdPath, securityMd], [securityTxtPath, securityTxtText]]
    .filter(([file, text]) => file && /\bTODO\b/.test(text))
    .map(([file, text]) => `${file} (${text.match(/\bTODO\b/g).length})`);
  if (securityMdPath || securityTxtPath) {
    add('placeholders', 'No unfilled TODO placeholders', 'required', todo.length === 0,
      todo.length ? `TODO placeholders left in ${todo.join(', ')}` : 'No placeholders', 'CRA Annex II');
  }

  // --- SBOM ---------------------------------------------------------------------
  // npm projects: a lockfile cra-audit builds the SBOM from. Other ecosystems:
  // an SBOM produced by their own tooling (Syft, cdxgen…) kept in the repo.
  const parsed = parseLockfile(projectRoot);
  const sbomFile = parsed.ok ? null : findSbomFile(projectRoot);
  const manifests = parsed.ok || sbomFile ? null : readManifests(projectRoot);
  add('sbom', 'Dependency inventory for the SBOM (lockfile, manifest or SBOM file)', 'required', parsed.ok || sbomFile || manifests,
    parsed.ok ? `${parsed.lockfileName} (${parsed.components.length} components)`
      : sbomFile ? `Found ${sbomFile}`
        : manifests ? `${manifests.files.join(', ')} (${manifests.components.length} components)`
          : 'No lockfile, supported manifest or SBOM file found.',
    'CRA Annex I Part II (1)');

  add('package-repository', 'package.json links the source repository', 'recommended', Boolean(repositoryUrl(pkg.repository)),
    repositoryUrl(pkg.repository) || 'No "repository" field', 'TR-03183-2 §5.2.4');

  const failed = checks.filter((c) => c.level === 'required' && !c.passed);
  return { checks, passed: failed.length === 0, files: { securityMd: securityMdPath, securityTxt: securityTxtPath } };
}

/** Parses the fields of a security.txt that the checks need. */
function parseSecurityTxt(text) {
  const out = { contact: [], expires: null, policy: [] };
  for (const raw of String(text).split(/\r?\n/)) {
    const m = raw.match(/^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/);
    if (!m) continue;
    const field = m[1].toLowerCase();
    if (field === 'contact') out.contact.push(m[2]);
    else if (field === 'expires') out.expires = m[2];
    else if (field === 'policy') out.policy.push(m[2]);
  }
  return out;
}

// --- Templates (`readiness --init`) --------------------------------------------

/**
 * Writes SECURITY.md and .well-known/security.txt templates prefilled from
 * package.json. Existing files are never overwritten.
 *
 * @returns {Array<{ file: string, created: boolean }>}
 */
function writeTemplates(projectRoot, { now = new Date() } = {}) {
  const pkg = readJson(path.join(projectRoot, 'package.json')) || {};
  const repo = repositoryUrl(pkg.repository);
  const advisories = repo && /github\.com/.test(repo) ? `${repo}/security/advisories/new` : null;
  const name = pkg.name || path.basename(projectRoot);
  const major = String(pkg.version || '1.0.0').split('.')[0];
  const results = [];

  const existingMd = firstExisting(projectRoot, SECURITY_MD_PATHS);
  if (existingMd) {
    results.push({ file: existingMd, created: false });
  } else {
    fs.writeFileSync(path.join(projectRoot, 'SECURITY.md'), securityMdTemplate({ name, major, advisories }));
    results.push({ file: 'SECURITY.md', created: true });
  }

  const existingTxt = firstExisting(projectRoot, SECURITY_TXT_PATHS);
  if (existingTxt) {
    results.push({ file: existingTxt, created: false });
  } else {
    const base = fs.existsSync(path.join(projectRoot, 'public')) ? 'public/.well-known' : '.well-known';
    fs.mkdirSync(path.join(projectRoot, base), { recursive: true });
    const expires = new Date(now.getTime() + 364 * DAY).toISOString().replace(/\.\d{3}Z$/, 'Z');
    fs.writeFileSync(path.join(projectRoot, base, 'security.txt'), securityTxtTemplate({ advisories, repo, expires }));
    results.push({ file: `${base}/security.txt`, created: true });
  }
  return results;
}

function securityMdTemplate({ name, major, advisories }) {
  const channel = advisories
    ? `Report it privately through [GitHub Security Advisories](${advisories}), or by email to TODO: security@example.com.`
    : 'Report it privately by email to TODO: security@example.com.';
  return `# Security Policy

## Supported Versions

| Version | Supported | End of security support |
| ------- | --------- | ----------------------- |
| ${major}.x     | ✅        | TODO: YYYY-MM-DD        |
| < ${major}.0   | ❌        | —                       |

**Support period:** security updates for ${name} ${major}.x are provided until TODO: YYYY-MM-DD
(the EU Cyber Resilience Act expects at least 5 years, or the expected time of use of the product).

## Reporting a Vulnerability

Please do **not** open a public issue for security problems.

${channel}

Include the affected version, a description of the issue and, if possible, steps to reproduce it.

## Our Process (Coordinated Vulnerability Disclosure)

- We acknowledge reports within **3 business days** and send a first assessment within **10 business days**.
- We agree a disclosure date with the reporter, normally within **90 days**, and credit reporters who wish to be named.
- Fixes are released as security updates, separate from feature updates where possible, and announced in the release notes and a GitHub Security Advisory.

## EU Cyber Resilience Act — Reporting (Art. 14)

When we become aware of an actively exploited vulnerability in ${name}, or a severe incident affecting its security,
we notify the coordinating CSIRT and ENISA through the Single Reporting Platform:

- an **early warning within 24 hours**,
- a **notification within 72 hours**,
- a **final report within 14 days** after a corrective measure is available (one month for severe incidents).

Affected users are informed of the issue and of the corrective measures to take.
`;
}

function securityTxtTemplate({ advisories, repo, expires }) {
  const lines = ['# RFC 9116 — https://securitytxt.org', 'Contact: mailto:TODO-security@example.com'];
  if (advisories) lines.push(`Contact: ${advisories}`);
  lines.push(`Expires: ${expires}`);
  if (repo) lines.push(`Policy: ${repo}/blob/HEAD/SECURITY.md`);
  lines.push('Preferred-Languages: en', '');
  return lines.join('\n');
}

/** An SBOM file at the root or in sbom/: *.cdx.json, *.spdx.json, bom.json… */
function findSbomFile(root) {
  for (const dir of ['', 'sbom']) {
    let names = [];
    try {
      names = fs.readdirSync(path.join(root, dir));
    } catch {
      continue;
    }
    const match = names.find((n) => /(\.cdx\.json|\.spdx\.json|^bom\.json|^sbom\.json)$/i.test(n));
    if (match) return dir ? `${dir}/${match}` : match;
  }
  return null;
}

function firstExisting(root, candidates) {
  return candidates.find((rel) => fs.existsSync(path.join(root, rel))) || null;
}

function read(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

module.exports = { checkReadiness, writeTemplates, parseSecurityTxt };
