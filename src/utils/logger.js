'use strict';

/**
 * Minimal ANSI logger with no external dependencies.
 * Colors are automatically disabled when output is not a TTY,
 * when NO_COLOR is set, or when --no-color was requested.
 */

const SUPPORTS_COLOR =
  process.stdout.isTTY &&
  !process.env.NO_COLOR &&
  process.env.TERM !== 'dumb';

let colorEnabled = SUPPORTS_COLOR;

const CODES = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

function paint(code, text) {
  if (!colorEnabled) return text;
  return `${CODES[code]}${text}${CODES.reset}`;
}

const color = {
  bold: (t) => paint('bold', t),
  dim: (t) => paint('dim', t),
  red: (t) => paint('red', t),
  green: (t) => paint('green', t),
  yellow: (t) => paint('yellow', t),
  blue: (t) => paint('blue', t),
  magenta: (t) => paint('magenta', t),
  cyan: (t) => paint('cyan', t),
  gray: (t) => paint('gray', t),
};

const SYMBOLS = {
  ok: () => color.green('✔'),
  fail: () => color.red('✖'),
  warn: () => color.yellow('⚠'),
  info: () => color.blue('ℹ'),
  bullet: () => color.gray('•'),
};

const logger = {
  setColor(enabled) {
    colorEnabled = Boolean(enabled) && SUPPORTS_COLOR;
  },
  log(...args) {
    process.stdout.write(args.join(' ') + '\n');
  },
  raw(text) {
    process.stdout.write(text);
  },
  info(msg) {
    this.log(`${SYMBOLS.info()} ${msg}`);
  },
  success(msg) {
    this.log(`${SYMBOLS.ok()} ${msg}`);
  },
  warn(msg) {
    this.log(`${SYMBOLS.warn()} ${color.yellow(msg)}`);
  },
  error(msg) {
    process.stderr.write(`${SYMBOLS.fail()} ${color.red(msg)}\n`);
  },
  heading(msg) {
    this.log('');
    this.log(color.bold(color.cyan(msg)));
  },
  detail(msg) {
    this.log(`  ${color.gray(msg)}`);
  },
  /**
   * Renders an in-place progress bar with a percentage and a done/total count.
   * On a TTY the same line is rewritten on each call; a trailing newline is
   * emitted once `done >= total`. On non-TTY streams nothing is written to
   * avoid flooding logs (CI pipelines), so callers should log a final summary.
   */
  progress(label, done, total) {
    if (!process.stdout.isTTY) return;
    const ratio = total > 0 ? Math.min(1, done / total) : 1;
    const pct = Math.floor(ratio * 100);
    const width = 24;
    const filled = Math.round(ratio * width);
    const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
    const line =
      `  ${color.gray(label)} ${color.cyan(`[${bar}]`)} ` +
      `${String(pct).padStart(3)}% ${color.gray(`(${done}/${total})`)}`;
    process.stdout.write(`\r\x1b[K${line}`);
    if (done >= total) process.stdout.write('\n');
  },
};

module.exports = { logger, color, SYMBOLS };
