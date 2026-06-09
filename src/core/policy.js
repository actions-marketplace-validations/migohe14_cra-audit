'use strict';

const path = require('node:path');
const { readJson, exists } = require('../utils/fs');

const CONFIG_FILENAMES = ['.cra-audit.json', 'cra-audit.config.json'];

/**
 * Default security policy aligned with CRA Article 13 ("no known exploitable
 * vulnerabilities") and TR-03183 transparency requirements.
 */
const DEFAULT_POLICY = {
  // Fail the audit when a vulnerability of this severity (or higher) is found.
  failOn: 'high', // info | low | moderate | high | critical
  // Require an SBOM that satisfies the minimum TR-03183 elements.
  requireSbom: true,
  sbomFormat: 'cyclonedx', // cyclonedx | spdx
  // Audit only production dependencies (recommended for shipped products).
  productionOnly: false,
  vulnerabilities: {
    // CVE/advisory ids explicitly accepted with documented justification.
    allowlist: [],
  },
  licenses: {
    // Empty allow = accept any license that is not denied.
    allow: [],
    deny: ['GPL-3.0', 'AGPL-3.0'],
    // Treat undocumented licenses as a compliance failure.
    failOnMissing: true,
  },
};

/**
 * Loads and merges the project security policy from disk over the defaults.
 *
 * @param {string} projectRoot
 * @param {string} [explicitPath] Path provided via --config.
 */
function loadPolicy(projectRoot, explicitPath) {
  let configPath = null;

  if (explicitPath) {
    configPath = path.isAbsolute(explicitPath)
      ? explicitPath
      : path.join(projectRoot, explicitPath);
    if (!exists(configPath)) {
      throw new Error(`Configuration file not found: ${explicitPath}`);
    }
  } else {
    for (const name of CONFIG_FILENAMES) {
      const candidate = path.join(projectRoot, name);
      if (exists(candidate)) {
        configPath = candidate;
        break;
      }
    }
  }

  let userPolicy = {};
  if (configPath) {
    userPolicy = readJson(configPath) || {};
  }

  return { policy: mergePolicy(DEFAULT_POLICY, userPolicy), source: configPath };
}

function mergePolicy(base, override) {
  return {
    ...base,
    ...override,
    vulnerabilities: { ...base.vulnerabilities, ...(override.vulnerabilities || {}) },
    licenses: { ...base.licenses, ...(override.licenses || {}) },
  };
}

module.exports = { loadPolicy, DEFAULT_POLICY };
