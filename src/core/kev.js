'use strict';

const { fetchJson } = require('../utils/http');

/**
 * CISA Known Exploited Vulnerabilities catalogue: the most complete public
 * list of vulnerabilities with evidence of active exploitation. Under CRA
 * Art. 14 (applicable since 11 September 2026) manufacturers must report
 * actively exploited vulnerabilities in their products within 24 hours.
 *
 * The GitHub mirror maintained by CISA is used when the primary feed fails.
 */
const KEV_SOURCES = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
];

/**
 * @returns {Promise<{ ok: true, catalogVersion: string|null, count: number, byCve: Map<string, object> }
 *   | { ok: false, error: string }>}
 */
async function loadKev({ timeout = 20000 } = {}) {
  for (const url of KEV_SOURCES) {
    const res = await fetchJson(url, { timeout });
    const list = res && res.ok && res.json && res.json.vulnerabilities;
    if (!Array.isArray(list)) continue;

    const byCve = new Map();
    for (const entry of list) {
      if (!entry || !entry.cveID) continue;
      byCve.set(entry.cveID.toUpperCase(), {
        cve: entry.cveID,
        name: entry.vulnerabilityName || null,
        dateAdded: entry.dateAdded || null,
        dueDate: entry.dueDate || null,
        knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse || null,
      });
    }
    return { ok: true, catalogVersion: res.json.catalogVersion || null, count: byCve.size, byCve };
  }
  return { ok: false, error: 'CISA KEV catalogue unreachable' };
}

module.exports = { loadKev };
