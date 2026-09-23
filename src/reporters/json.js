'use strict';

const { logger } = require('../utils/logger');
const { writeJson } = require('../utils/fs');

/**
 * Emits the audit report as machine-readable JSON, either to stdout or to a file.
 * @param {object} report
 * @param {{ outputPath?: string }} [options]
 */
function reportJson(report, { outputPath } = {}) {
  if (outputPath) {
    writeJson(outputPath, report);
    logger.success(`JSON report written to: ${outputPath}`);
  } else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }
}

module.exports = { reportJson };
