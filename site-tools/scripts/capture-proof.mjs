#!/usr/bin/env node
// Captures real output of the published Relvet CLI for the website.
//
// Refreshing the capture is a deliberate act: run this, then
// `pnpm --filter site-tools build`, then review the diff. Nobody edits the
// output on the pages by hand, and CI never runs this script (it needs the
// network and real, changing data).
//
//   pnpm --filter site-tools capture-proof            # version from package.json
//   pnpm --filter site-tools capture-proof 0.1.3      # a specific published version
//   pnpm --filter site-tools capture-proof --tarball ../relvet-0.2.0.tgz
//                                     # a packed build (`pnpm pack`), for a
//                                     # version that is not on npm yet
//
// Writes site-tools/proof/: run.ansi (raw stdout bytes), run.txt (the same
// without ANSI codes), run.json (the --json report), help.txt (--help) and
// meta.json. The CLI's text is never changed.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ESC = String.fromCharCode(27);
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const out = join(root, 'site-tools/proof');
const cli = process.argv.slice(2);
const tarballIndex = cli.indexOf('--tarball');
const tarball =
  tarballIndex === -1
    ? undefined
    : resolve(process.cwd(), cli[tarballIndex + 1] ?? '');
if (tarballIndex !== -1) cli.splice(tarballIndex, 2);
const version =
  cli[0] ??
  JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`Bad version ${version}`);

// The run shown on the home page: the sample firmware SBOM, CRA answers as flags.
const ARGS = [
  '--sbom',
  'test/fixtures/sbom/cyclonedx.json',
  '--non-interactive',
  '--eu-distribution',
  'yes',
  '--commercial',
  'yes',
  '--product-type',
  'firmware',
];

const env = { ...process.env, RELVET_TELEMETRY: '0' };
for (const name of ['NO_COLOR', 'FORCE_COLOR', 'CI', 'NODE_OPTIONS'])
  delete env[name];

// Install the published package from the npm registry into a scratch
// directory (npm checks the registry's integrity hash) and run its entry
// point directly, which is what `npx relvet@<version>` runs. With --tarball,
// install that packed build instead and record its own integrity hash.
const prefix = mkdtempSync(join(tmpdir(), 'relvet-proof-'));
// An empty cache of its own, so every response comes from the network now.
env.RELVET_CACHE_DIR = join(prefix, 'cache');
const install = spawnSync(
  `npm install --prefix "${prefix}" --no-audit --no-fund --ignore-scripts "${tarball ?? `relvet@${version}`}"`,
  { cwd: prefix, env, encoding: 'utf8', shell: true },
);
if (install.status !== 0)
  throw new Error(`npm install failed:\n${install.stderr}`);
const installed = join(prefix, 'node_modules/relvet');
const installedVersion = JSON.parse(
  readFileSync(join(installed, 'package.json'), 'utf8'),
).version;
if (installedVersion !== version)
  throw new Error(`Installed ${installedVersion}, expected ${version}.`);
const lock = JSON.parse(
  readFileSync(join(prefix, 'package-lock.json'), 'utf8'),
);
const integrity = tarball
  ? `sha512-${createHash('sha512').update(readFileSync(tarball)).digest('base64')}`
  : lock.packages?.['node_modules/relvet']?.integrity;
if (!integrity) throw new Error('No registry integrity hash for the package.');
const entry = join(installed, 'dist/cli.js');

function run(args, { tty = false } = {}) {
  const started = performance.now();
  const preload = pathToFileURL(join(here, 'force-tty.mjs')).href;
  const result = spawnSync(
    process.execPath,
    [...(tty ? [`--import=${preload}`] : []), entry, ...args],
    { cwd: root, env, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.error) throw result.error;
  return {
    stdout: result.stdout,
    stderr: result.stderr.toString('utf8'),
    exitCode: result.status,
    wallMs: Math.round(performance.now() - started),
  };
}

const text = run(ARGS, { tty: true });
const json = run([...ARGS, '--json']);
const help = run(['--help']);
rmSync(prefix, { recursive: true, force: true });

for (const [name, result, allowed] of [
  ['text run', text, [0, 1]],
  ['JSON run', json, [0, 1]],
  ['help', help, [0]],
]) {
  if (!allowed.includes(result.exitCode))
    throw new Error(
      `${name} exited ${result.exitCode}:\n${result.stderr.slice(0, 2000)}`,
    );
}

const ansi = text.stdout.toString('utf8');
if (!ansi.startsWith(`${ESC}[1mRelvet ${version}`))
  throw new Error(`Unexpected output:\n${ansi.slice(0, 500)}`);
const plain = ansi
  .split(ESC)
  .map((part, index) => (index === 0 ? part : part.replace(/^\[[0-9;]*m/, '')));
const report = JSON.parse(json.stdout.toString('utf8'));
if (report.tool.version !== version || report.mock)
  throw new Error('The JSON run is not a real run of the requested version.');
if (!help.stdout.toString('utf8').startsWith('Usage: relvet'))
  throw new Error('Unexpected --help output.');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
mkdirSync(out, { recursive: true });
writeFileSync(join(out, 'run.ansi'), text.stdout);
writeFileSync(join(out, 'run.txt'), plain.join(''));
writeFileSync(join(out, 'run.json'), json.stdout);
writeFileSync(join(out, 'help.txt'), help.stdout);
const capturedAt = new Date().toISOString();
writeFileSync(
  join(out, 'meta.json'),
  `${JSON.stringify(
    {
      package: `relvet@${version}`,
      ...(tarball && { source: 'packed build (not from the npm registry)' }),
      cliVersion: version,
      integrity,
      capturedAt,
      shownCommand: ['npx', 'relvet', ...ARGS].join(' '),
      args: ARGS,
      exitCode: text.exitCode,
      jsonExitCode: json.exitCode,
      wallMs: text.wallMs,
      cache: 'empty (fresh network responses)',
      node: process.version,
      sha256: {
        'run.ansi': sha256(text.stdout),
        'run.json': sha256(json.stdout),
        'help.txt': sha256(help.stdout),
      },
    },
    null,
    2,
  )}\n`,
);
console.log(
  `Captured relvet ${version} at ${capturedAt}: exit ${text.exitCode}, ${report.summary.issues} issues, ${report.summary.activelyExploited} actively exploited.`,
);
