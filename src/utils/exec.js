'use strict';

const { spawnSync } = require('node:child_process');

/**
 * Runs a command synchronously and returns its stdout/stderr/status
 * without throwing. Used to invoke `npm` safely.
 *
 * @param {string} command
 * @param {string[]} args
 * @param {object} [options]
 * @returns {{ status: number|null, stdout: string, stderr: string, error: Error|undefined }}
 */
function run(command, args = [], options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    shell: process.platform === 'win32',
    ...options,
  });

  return {
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error,
  };
}

/**
 * Runs a command and attempts to parse its stdout as JSON.
 * Returns { ok, data, raw, status }.
 */
function runJson(command, args = [], options = {}) {
  const result = run(command, args, options);
  let data = null;
  let parseError = null;

  if (result.stdout) {
    try {
      data = JSON.parse(result.stdout);
    } catch (err) {
      parseError = err;
    }
  }

  return {
    ok: !result.error && data !== null,
    data,
    raw: result.stdout,
    status: result.status,
    stderr: result.stderr,
    error: result.error || parseError,
  };
}

module.exports = { run, runJson };
