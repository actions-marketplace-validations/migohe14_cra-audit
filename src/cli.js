'use strict';

const { logger, color } = require('./utils/logger');
const { auditCommand } = require('./commands/audit');
const { sbomCommand } = require('./commands/sbom');
const { visualizeCommand } = require('./commands/visualize');

const VERSION = require('../package.json').version;

const FLAG_ALIASES = {
  '-h': '--help',
  '-v': '--version',
  '-o': '--output',
  '-i': '--input',
  '-c': '--config',
  '-V': '--visualize',
};

const BOOLEAN_FLAGS = new Set([
  '--help', '--version', '--json', '--sbom', '--no-sbom',
  '--production', '--prod', '--no-color',
  '--visualize', '--offline', '--github', '--no-open',
]);

/**
 * Entry point invoked from bin/cra-audit.js.
 * @param {string[]} argv Arguments after `node script`.
 * @returns {Promise<number>} exit code.
 */
async function main(argv) {
  const { positionals, flags } = parseArgs(argv);

  if (flags.noColor) logger.setColor(false);

  if (flags.help) {
    printHelp();
    return 0;
  }
  if (flags.version) {
    logger.log(VERSION);
    return 0;
  }

  const command = positionals[0] || 'audit';

  // `--visualize` is a shortcut for the visual HTML report.
  if (flags.visualize && command === 'audit') {
    return visualizeCommand(flags);
  }
  // `--sbom` is a shortcut for "sbom check" regardless of the (default) command.
  if (flags.sbom && command === 'audit') {
    return sbomCommand('check', flags);
  }

  switch (command) {
    case 'audit':
      return auditCommand(flags);

    case 'visualize':
    case 'view':
    case 'report':
      return visualizeCommand(flags);

    case 'sbom':
      // `cra-audit --sbom` is handled below; here we route the subcommand form.
      return sbomCommand(positionals[1], flags);

    case 'vulnerabilities':
    case 'vuln':
    case 'vulns':
      return auditCommand(flags, 'vulnerabilities');

    case 'licenses':
    case 'license':
      return auditCommand(flags, 'licenses');

    case 'help':
      printHelp();
      return 0;

    default:
      logger.error(`Unknown command: "${command}".`);
      logger.log(`Run ${color.cyan('cra-audit --help')} to see the available commands.`);
      return 1;
  }
}

/**
 * Minimal, dependency-free argument parser.
 * Supports `--flag`, `--flag value`, `--flag=value`, short aliases and `--no-*`.
 */
function parseArgs(argv) {
  const positionals = [];
  const flags = {};

  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];

    if (!arg.startsWith('-')) {
      positionals.push(arg);
      continue;
    }

    let value;
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      value = arg.slice(eq + 1);
      arg = arg.slice(0, eq);
    }

    const canonical = FLAG_ALIASES[arg] || arg;

    if (BOOLEAN_FLAGS.has(canonical)) {
      setFlag(flags, canonical, true);
      continue;
    }

    // Value flag: take inline `=value` or the next argument.
    if (value === undefined) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        value = next;
        i++;
      } else {
        value = true;
      }
    }
    setFlag(flags, canonical, value);
  }

  return { positionals, flags };
}

function setFlag(flags, name, value) {
  switch (name) {
    case '--help': flags.help = value; break;
    case '--version': flags.version = value; break;
    case '--json': flags.json = value; break;
    case '--sbom': flags.sbom = value; break;
    case '--no-sbom': flags.noSbom = value; break;
    case '--no-color': flags.noColor = value; break;
    case '--visualize': flags.visualize = value; break;
    case '--offline': flags.offline = value; break;
    case '--github': flags.github = value; break;
    case '--no-open': flags.noOpen = value; break;
    case '--production':
    case '--prod': flags.production = value; break;
    case '--output': flags.output = value; break;
    case '--input': flags.input = value; break;
    case '--config': flags.config = value; break;
    case '--format': flags.format = String(value).toLowerCase(); break;
    case '--fail-on': flags.failOn = String(value).toLowerCase(); break;
    case '--cwd': flags.cwd = value; break;
    default:
      // Unknown flag stored under its raw name for forward compatibility.
      flags[name.replace(/^--/, '')] = value;
  }
}

function printHelp() {
  const c = color;
  logger.log(`
${c.bold('cra-audit')} — Cyber Resilience Act (EU 2024/2847) compliance audit
            and the BSI TR-03183 technical guideline, for npm projects.

${c.bold('USAGE')}
  npx cra-audit [command] [options]

${c.bold('COMMANDS')}
  ${c.cyan('audit')}                 Run ALL the checks (vulnerabilities + SBOM + licenses). Default.
  ${c.cyan('visualize')}             Generate an interactive HTML report (SBOM, licenses, versions and maintenance).
  ${c.cyan('sbom generate')}         Generate an SBOM (CycloneDX or SPDX) and print or save it.
  ${c.cyan('sbom check')}            Validate that the SBOM meets the TR-03183 minimum elements.
  ${c.cyan('vulnerabilities')}       Analyze known vulnerabilities only (alias: vuln).
  ${c.cyan('licenses')}              Analyze dependency licenses only.
  ${c.cyan('help')}                  Show this help.

${c.bold('OPTIONS')}
  ${c.cyan('--visualize, -V')}       Shortcut to generate and open the interactive HTML report.
  ${c.cyan('--github')}              Enrich the visual report with GitHub data (last commit, contributors, stars).
  ${c.cyan('--offline')}             Do not query the network when visualizing (skips maintenance metadata).
  ${c.cyan('--no-open')}             Do not open the HTML report in the browser automatically.
  ${c.cyan('--sbom')}                Shortcut equivalent to "sbom check".
  ${c.cyan('--format <fmt>')}        SBOM format: cyclonedx (default) | spdx.
  ${c.cyan('--fail-on <sev>')}       Minimum severity that fails the audit: info|low|moderate|high|critical.
  ${c.cyan('--production, --prod')}  Audit production dependencies only (skips devDependencies).
  ${c.cyan('--no-sbom')}             Do not require an SBOM in the full audit.
  ${c.cyan('--json')}                Machine-readable JSON output.
  ${c.cyan('--output, -o <path>')}   Write the result/SBOM/HTML to a file.
  ${c.cyan('--input, -i <path>')}    Existing SBOM to validate (for "sbom check").
  ${c.cyan('--config, -c <path>')}   Path to the security policy (.cra-audit.json).
  ${c.cyan('--cwd <path>')}          Project directory to audit.
  ${c.cyan('--no-color')}            Disable colors.
  ${c.cyan('--version, -v')}         Show the version.
  ${c.cyan('--help, -h')}            Show this help.

${c.bold('EXAMPLES')}
  ${c.gray('# Full CRA compliance audit')}
  npx cra-audit

  ${c.gray('# Interactive visual report (HTML) with maintenance data')}
  npx cra-audit --visualize
  npx cra-audit visualize --github

  ${c.gray('# Just the SBOM part')}
  npx cra-audit --sbom
  npx cra-audit sbom check

  ${c.gray('# Generate a CycloneDX SBOM on disk')}
  npx cra-audit sbom generate -o sbom.cdx.json

  ${c.gray('# Fail only on critical vulnerabilities, in CI')}
  npx cra-audit --fail-on critical --production --json -o cra-report.json
`);
}

module.exports = { main, parseArgs };
