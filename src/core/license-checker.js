'use strict';

const { parseLockfile } = require('./lockfile-parser');
const { readInstalledManifest, licenseFromManifest } = require('./installed-metadata');

/**
 * Resolves and evaluates the license of every third-party component.
 * CRA / TR-03183 require every component's license to be documented.
 *
 * @param {string} projectRoot
 * @param {{ allow?: string[], deny?: string[] }} [policy]
 */
function checkLicenses(projectRoot, policy = {}) {
  const parsed = parseLockfile(projectRoot);
  if (!parsed.ok) {
    return { ok: false, error: parsed.error, components: [], summary: emptySummary() };
  }

  const allow = normalizeList(policy.allow);
  const deny = normalizeList(policy.deny);

  const components = parsed.components.map((c) => {
    const license = c.license || licenseFromManifest(readInstalledManifest(projectRoot, c));
    const normalized = license ? String(license) : null;
    const status = classify(normalized, allow, deny);
    return {
      name: c.name,
      version: c.version,
      license: normalized,
      status, // 'ok' | 'missing' | 'denied' | 'not-allowed'
    };
  });

  const summary = {
    total: components.length,
    documented: components.filter((c) => c.license).length,
    missing: components.filter((c) => c.status === 'missing'),
    denied: components.filter((c) => c.status === 'denied'),
    notAllowed: components.filter((c) => c.status === 'not-allowed'),
  };

  return { ok: true, components, summary };
}

function classify(license, allow, deny) {
  if (!license || /^(unknown|unlicensed|see license)/i.test(license)) {
    return 'missing';
  }
  const ids = extractLicenseIds(license);
  if (deny.length && ids.some((id) => deny.includes(id))) {
    return 'denied';
  }
  if (allow.length && !ids.every((id) => allow.includes(id))) {
    return 'not-allowed';
  }
  return 'ok';
}

/** Splits an SPDX expression into individual license identifiers (lowercased). */
function extractLicenseIds(expression) {
  return expression
    .replace(/[()]/g, ' ')
    .split(/\s+(?:AND|OR|WITH)\s+/i)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function normalizeList(list) {
  if (!Array.isArray(list)) return [];
  return list.map((s) => String(s).trim().toLowerCase()).filter(Boolean);
}

function emptySummary() {
  return { total: 0, documented: 0, missing: [], denied: [], notAllowed: [] };
}

module.exports = { checkLicenses };
