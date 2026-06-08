'use strict';

const fs = require('node:fs');
const path = require('node:path');

/** Reads and parses a JSON file. Returns null if it does not exist. */
function readJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const content = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(content);
}

/** Writes a JSON object to disk with 2-space indentation. */
function writeJson(filePath, data) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

/** Returns true if a path exists. */
function exists(filePath) {
  return fs.existsSync(filePath);
}

/**
 * Resolves the project root by locating the nearest package.json,
 * walking up from the provided starting directory.
 */
function findProjectRoot(startDir = process.cwd()) {
  let dir = path.resolve(startDir);
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (fs.existsSync(path.join(dir, 'package.json'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

module.exports = { readJson, writeJson, exists, findProjectRoot };
