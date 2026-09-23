'use strict';

/**
 * Where and how a manufacturer reports under CRA Art. 14. Notifications go
 * through ENISA's Single Reporting Platform (SRP) to the CSIRT designated as
 * coordinator of the Member State of the manufacturer's main establishment.
 *
 * Country-specific procedures are added only when they have been verified
 * against the CSIRT's own publications (see `source`).
 */

const SRP = {
  url: 'https://portal.cra-srp.enisa.europa.eu',
  faq: 'https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions',
};

const DEADLINES = {
  vulnerability: [
    { step: 'early-warning', deadline: '24 hours after becoming aware' },
    { step: 'notification', deadline: '72 hours after becoming aware' },
    { step: 'final-report', deadline: '14 days after a corrective or mitigating measure is available' },
  ],
  incident: [
    { step: 'early-warning', deadline: '24 hours after becoming aware' },
    { step: 'notification', deadline: '72 hours after becoming aware' },
    { step: 'final-report', deadline: '1 month after the 72-hour notification' },
  ],
};

const CSIRTS = {
  ES: {
    country: 'ES',
    csirt: 'INCIBE-CERT',
    website: 'https://www.incibe.es/incibe-cert',
    srpAccess: {
      contact: 'cve-coordination@incibe.es',
      steps: [
        'Email cve-coordination@incibe.es asking for a user on the ENISA Single Reporting Platform (SRP).',
        'INCIBE replies with the information and documents it needs, and validates that you are a manufacturer bound by the CRA.',
        'Once validated, INCIBE sends the instructions to complete the SRP registration and start notifying.',
      ],
      advice: 'Request SRP access before you need it: the validation happens before you can notify, and the 24-hour clock does not wait.',
    },
    otherChannels: [
      { purpose: 'Other cybersecurity incidents (outside CRA Art. 14)', contact: 'incidencias@incibe-cert.es' },
      { purpose: 'Undisclosed (0-day) vulnerabilities needing coordination and a CVE ID (INCIBE CNA)', contact: 'cve-coordination@incibe.es' },
    ],
    whenInDoubt: 'If you are not sure a case is in CRA scope, report it through INCIBE-CERT\'s usual channels; INCIBE tells you whether to file it formally in the SRP.',
    source: 'https://www.incibe.es/incibe-cert/blog/reglamento-de-ciberresiliencia-cra-que-es-quien-afecta-y-como-prepararse',
    verified: '2026-09-09',
  },
};

/**
 * Reporting guidance for a country (ISO 3166-1 alpha-2), or the generic
 * EU procedure when the country is unknown or not yet covered.
 *
 * @param {string|null|undefined} country
 */
function reportingGuide(country) {
  const code = typeof country === 'string' ? country.trim().toUpperCase() : null;
  const local = code ? CSIRTS[code] || null : null;
  return {
    country: code,
    platform: 'ENISA Single Reporting Platform (SRP)',
    srp: SRP,
    recipients: local
      ? `${local.csirt} (CSIRT designated as coordinator) and ENISA`
      : 'the CSIRT designated as coordinator of your main establishment\'s Member State, and ENISA',
    deadlines: DEADLINES,
    local,
  };
}

function supportedCountries() {
  return Object.keys(CSIRTS);
}

module.exports = { reportingGuide, supportedCountries };
