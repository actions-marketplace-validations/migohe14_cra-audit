'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

// Resolved through the package's own "exports", as a dependent project would.
test('exports the API and package.json', () => {
  const api = require('cra-audit');
  assert.equal(typeof api.runAudit, 'function');
  assert.equal(require('cra-audit/package.json').name, 'cra-audit');
});
