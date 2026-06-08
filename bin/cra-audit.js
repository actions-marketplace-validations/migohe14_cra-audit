#!/usr/bin/env node
'use strict';

const { main } = require('../src/cli');

Promise.resolve()
  .then(() => main(process.argv.slice(2)))
  .then((exitCode) => {
    process.exitCode = typeof exitCode === 'number' ? exitCode : 0;
  })
  .catch((err) => {
    process.stderr.write(`\x1b[31m✖ Error inesperado: ${err && err.message ? err.message : err}\x1b[0m\n`);
    if (process.env.CRA_AUDIT_DEBUG) {
      process.stderr.write(String(err && err.stack) + '\n');
    }
    process.exitCode = 1;
  });
