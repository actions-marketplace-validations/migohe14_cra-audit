'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readJson } = require('../utils/fs');
const { parseLockfile } = require('./lockfile-parser');

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
    const license = c.license || readLicenseFromDisk(projectRoot, c.path, c.name);
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

/** Reads the `license` field from an installed package's package.json. */
function readLicenseFromDisk(projectRoot, pkgPath, name) {
  const candidates = [];
  if (pkgPath) candidates.push(path.join(projectRoot, pkgPath, 'package.json'));
  candidates.push(path.join(projectRoot, 'node_modules', name, 'package.json'));

  for (const candidate of candidates) {
    try {
      if (!fs.existsSync(candidate)) continue;
      const pkg = readJson(candidate);
      if (!pkg) continue;
      if (typeof pkg.license === 'string') return pkg.license;
      if (pkg.license && pkg.license.type) return pkg.license.type;
      if (Array.isArray(pkg.licenses) && pkg.licenses.length) {
        return pkg.licenses.map((l) => (typeof l === 'string' ? l : l.type)).filter(Boolean).join(' OR ');
      }
    } catch {
      // Ignore unreadable package and continue.
    }
  }
  return null;
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
