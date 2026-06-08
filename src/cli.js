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
      logger.error(`Comando desconocido: "${command}".`);
      logger.log(`Ejecuta ${color.cyan('cra-audit --help')} para ver los comandos disponibles.`);
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
${c.bold('cra-audit')} — Auditoría de cumplimiento del Cyber Resilience Act (UE 2024/2847)
            y la directriz técnica BSI TR-03183 para proyectos npm.

${c.bold('USO')}
  npx cra-audit [comando] [opciones]

${c.bold('COMANDOS')}
  ${c.cyan('audit')}                 Ejecuta TODAS las comprobaciones (vulnerabilidades + SBOM + licencias). Por defecto.
  ${c.cyan('visualize')}             Genera un informe HTML interactivo (SBOM, licencias, versiones y mantenimiento).
  ${c.cyan('sbom generate')}         Genera un SBOM (CycloneDX o SPDX) y lo imprime o guarda.
  ${c.cyan('sbom check')}            Valida que el SBOM cumple los elementos mínimos de TR-03183.
  ${c.cyan('vulnerabilities')}       Analiza solo vulnerabilidades conocidas (alias: vuln).
  ${c.cyan('licenses')}              Analiza solo las licencias de las dependencias.
  ${c.cyan('help')}                  Muestra esta ayuda.

${c.bold('OPCIONES')}
  ${c.cyan('--visualize, -V')}       Atajo para generar y abrir el informe HTML interactivo.
  ${c.cyan('--github')}              Enriquece el informe visual con datos de GitHub (último commit, contribuidores, stars).
  ${c.cyan('--offline')}             No consulta la red al visualizar (omite metadatos de mantenimiento).
  ${c.cyan('--no-open')}             No abre el informe HTML en el navegador automáticamente.
  ${c.cyan('--sbom')}                Atajo equivalente a "sbom check".
  ${c.cyan('--format <fmt>')}        Formato del SBOM: cyclonedx (def.) | spdx.
  ${c.cyan('--fail-on <sev>')}       Severidad mínima que hace fallar la auditoría: info|low|moderate|high|critical.
  ${c.cyan('--production, --prod')}  Audita solo dependencias de producción (omite devDependencies).
  ${c.cyan('--no-sbom')}             No exige SBOM en la auditoría completa.
  ${c.cyan('--json')}                Salida en JSON legible por máquina.
  ${c.cyan('--output, -o <ruta>')}   Escribe el resultado/SBOM/HTML en un archivo.
  ${c.cyan('--input, -i <ruta>')}    SBOM existente a validar (para "sbom check").
  ${c.cyan('--config, -c <ruta>')}   Ruta a la política de seguridad (.cra-audit.json).
  ${c.cyan('--cwd <ruta>')}          Directorio del proyecto a auditar.
  ${c.cyan('--no-color')}            Desactiva los colores.
  ${c.cyan('--version, -v')}         Muestra la versión.
  ${c.cyan('--help, -h')}            Muestra esta ayuda.

${c.bold('EJEMPLOS')}
  ${c.gray('# Auditoría completa de cumplimiento CRA')}
  npx cra-audit

  ${c.gray('# Informe visual interactivo (HTML) con datos de mantenimiento')}
  npx cra-audit --visualize
  npx cra-audit visualize --github

  ${c.gray('# Solo la parte del SBOM')}
  npx cra-audit --sbom
  npx cra-audit sbom check

  ${c.gray('# Generar un SBOM CycloneDX en disco')}
  npx cra-audit sbom generate -o sbom.cdx.json

  ${c.gray('# Fallar solo ante vulnerabilidades críticas, en CI')}
  npx cra-audit --fail-on critical --production --json -o cra-report.json
`);
}

module.exports = { main, parseArgs };
