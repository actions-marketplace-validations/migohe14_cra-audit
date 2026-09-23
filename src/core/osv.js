'use strict';

const { fetchJson, mapLimit } = require('../utils/http');

const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000; // OSV querybatch limit

/**
 * Queries OSV.dev (https://osv.dev) for the advisories affecting each exact
 * `name@version`. OSV aggregates the GitHub Advisory Database (GHSA) and the
 * OpenSSF malicious-packages feed (MAL-*), which lists compromised releases
 * such as the ones published by the Shai-Hulud worm.
 *
 * Only package names and versions leave the machine.
 *
 * @param {Array<{ name: string, version: string }>} components
 * @param {{ timeout?: number, concurrency?: number }} [options]
 * @returns {Promise<{ ok: true, byComponent: Map<string, object[]> } | { ok: false, error: string }>}
 *   `byComponent` is keyed by `name@version` and holds full OSV records.
 */
async function queryOsv(components, { timeout = 30000, concurrency = 8 } = {}) {
  const idsByKey = new Map();

  for (let i = 0; i < components.length; i += BATCH_SIZE) {
    const chunk = components.slice(i, i + BATCH_SIZE);
    const res = await fetchJson(`${OSV_API}/querybatch`, {
      timeout,
      body: { queries: chunk.map((c) => ({ package: { name: c.name, ecosystem: 'npm' }, version: c.version })) },
    });
    if (!res || !res.ok || !res.json || !Array.isArray(res.json.results)) {
      return { ok: false, error: `OSV.dev query failed${res ? ` (HTTP ${res.status})` : ' (network unreachable)'}` };
    }

    for (let j = 0; j < chunk.length; j++) {
      const result = res.json.results[j] || {};
      const ids = (result.vulns || []).map((v) => v.id);
      // A package with many advisories is paginated: follow the token.
      let pageToken = result.next_page_token;
      while (pageToken) {
        const page = await fetchJson(`${OSV_API}/query`, {
          timeout,
          body: { package: { name: chunk[j].name, ecosystem: 'npm' }, version: chunk[j].version, page_token: pageToken },
        });
        if (!page || !page.ok || !page.json) break;
        ids.push(...(page.json.vulns || []).map((v) => v.id));
        pageToken = page.json.next_page_token;
      }
      if (ids.length) idsByKey.set(`${chunk[j].name}@${chunk[j].version}`, ids);
    }
  }

  // querybatch only returns ids: fetch each distinct record once.
  const uniqueIds = [...new Set([].concat(...idsByKey.values()))];
  const records = new Map();
  let failed = 0;
  await mapLimit(uniqueIds, async (id) => {
    const res = await fetchJson(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { timeout });
    if (res && res.ok && res.json) records.set(id, res.json);
    else failed++;
  }, concurrency);
  if (failed) {
    return { ok: false, error: `Could not download ${failed} advisory record(s) from OSV.dev` };
  }

  const byComponent = new Map();
  for (const [key, ids] of idsByKey) {
    const list = ids.map((id) => records.get(id)).filter((r) => r && !r.withdrawn);
    // The same advisory can appear under two ids (e.g. GHSA and its CVE).
    const seen = new Set();
    const unique = [];
    for (const record of list) {
      if (seen.has(record.id)) continue;
      [record.id, ...(record.aliases || [])].forEach((a) => seen.add(a));
      unique.push(record);
    }
    byComponent.set(key, unique);
  }
  return { ok: true, byComponent };
}

/**
 * Severity of an OSV record in npm-audit terms. Malicious packages are always
 * critical; GHSA records carry a reviewed rating; otherwise the CVSS v3 base
 * score is computed from the vector.
 *
 * @returns {'low'|'moderate'|'high'|'critical'|'unknown'}
 */
function osvSeverity(record) {
  if (isMalicious(record)) return 'critical';

  const rated = record.database_specific && record.database_specific.severity;
  if (typeof rated === 'string') {
    const s = rated.toLowerCase();
    if (s === 'medium') return 'moderate';
    if (['low', 'moderate', 'high', 'critical'].includes(s)) return s;
  }

  const score = cvssScore(record);
  if (score === null) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'moderate';
  return 'low';
}

/** CVSS v3 base score of the record, or null when it has no v3 vector. */
function cvssScore(record) {
  const v3 = (record.severity || []).find((s) => s.type === 'CVSS_V3');
  return v3 ? cvss3BaseScore(v3.score) : null;
}

/** OpenSSF malicious-packages advisories use the MAL- prefix. */
function isMalicious(record) {
  return typeof record.id === 'string' && record.id.startsWith('MAL-');
}

/**
 * Lowest version that fixes the advisory for the installed version, taken from
 * the OSV `affected[].ranges[].events` of this package.
 *
 * @returns {string|null}
 */
function fixedVersion(record, name, version) {
  let best = null;
  for (const affected of record.affected || []) {
    if (!affected.package || affected.package.name !== name) continue;
    for (const range of affected.ranges || []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      let introduced = null;
      for (const event of range.events || []) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed === undefined) continue;
        const inRange = (introduced === '0' || introduced === null || compareSemver(version, introduced) >= 0) &&
          compareSemver(version, event.fixed) < 0;
        if (inRange && (!best || compareSemver(event.fixed, best) < 0)) best = event.fixed;
      }
    }
  }
  return best;
}

/**
 * Compares two semver strings (major.minor.patch[-prerelease]).
 * Build metadata is ignored.
 */
function compareSemver(a, b) {
  const parse = (v) => {
    const [core, pre] = String(v).split('+')[0].split(/-(.*)/s);
    return { nums: core.split('.').map((n) => parseInt(n, 10) || 0), pre: pre ? pre.split('.') : [] };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const diff = (pa.nums[i] || 0) - (pb.nums[i] || 0);
    if (diff) return diff;
  }
  // A version without prerelease is greater than one with it.
  if (!pa.pre.length || !pb.pre.length) return pb.pre.length - pa.pre.length;
  for (let i = 0; i < Math.max(pa.pre.length, pb.pre.length); i++) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny && Number(x) !== Number(y)) return Number(x) - Number(y);
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const CVSS3_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

/** CVSS v3.0/v3.1 base score from a vector string (FIRST specification). */
function cvss3BaseScore(vector) {
  const m = {};
  for (const part of String(vector).split('/')) {
    const [k, v] = part.split(':');
    m[k] = v;
  }
  const scopeChanged = m.S === 'C';
  const pr = { N: 0.85, L: scopeChanged ? 0.68 : 0.62, H: scopeChanged ? 0.5 : 0.27 }[m.PR];
  const w = CVSS3_WEIGHTS;
  const values = [w.AV[m.AV], w.AC[m.AC], pr, w.UI[m.UI], w.C[m.C], w.I[m.I], w.A[m.A]];
  if (values.some((x) => x === undefined)) return null;
  const [av, ac, , ui, c, i, a] = values;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return roundUp(raw);
}

function roundUp(value) {
  const int = Math.round(value * 100000);
  return int % 10000 === 0 ? int / 100000 : (Math.floor(int / 10000) + 1) / 10;
}

module.exports = {
  queryOsv, osvSeverity, cvssScore, isMalicious, fixedVersion, compareSemver, cvss3BaseScore,
};
