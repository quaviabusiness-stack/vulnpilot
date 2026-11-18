// Bundles the CLI's own TypeScript for the browser (the /scan page, its parse
// worker and the scanner core) and for the /api/kev Vercel Function, with the
// tsup dev dependency the CLI already uses.
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build, type Options } from 'tsup';
import { generatedHeader, TOOLS } from './paths.js';

const banner = (sources: string) => ({ js: `// ${generatedHeader(sources)}` });

async function bundle(options: Options): Promise<string[]> {
  const outDir = mkdtempSync(join(tmpdir(), 'vulnpilot-site-'));
  try {
    await build({
      format: ['esm'],
      sourcemap: false,
      dts: false,
      clean: false,
      silent: true,
      config: false,
      ...options,
      outDir,
    });
    return readdirSync(outDir).map((name) => join(outDir, name));
  } catch (error) {
    rmSync(outDir, { recursive: true, force: true });
    throw error;
  }
}

function moveAll(files: string[], target: string): string[] {
  const names: string[] = [];
  for (const file of files) {
    const name = file.split(/[\\/]/).pop()!;
    cpSync(file, join(target, name));
    names.push(name);
  }
  if (files[0]) rmSync(join(files[0], '..'), { recursive: true, force: true });
  return names.sort();
}

export interface ScannerBuild {
  /** Served path of the page entry, for the <script type="module"> tag. */
  page: string;
  worker: string;
  files: string[];
}

/** Writes the browser chunks into `target` (site/assets/scanner). */
export async function buildScanner(
  target: string,
  version: string,
): Promise<ScannerBuild> {
  const browser: Options = {
    platform: 'browser',
    target: 'es2022',
    minify: true,
    banner: banner('src/ and site-tools/scanner/'),
    define: { __CLI_VERSION__: JSON.stringify(version) },
  };
  // The worker first: the page needs its hashed URL.
  const workerFiles = await bundle({
    ...browser,
    entry: { 'parse-worker': join(TOOLS, 'scanner/parse-worker.ts') },
    tsconfig: join(TOOLS, 'tsconfig.worker.json'),
    splitting: false,
    esbuildOptions(options) {
      options.entryNames = '[name]-[hash]';
      options.legalComments = 'none';
    },
  });
  const [worker] = moveAll(workerFiles, target);
  if (!worker || workerFiles.length !== 1)
    throw new Error('The parse worker must be a single file.');
  const workerUrl = `/assets/scanner/${worker}`;

  const pageFiles = await bundle({
    ...browser,
    entry: { 'scan-page': join(TOOLS, 'scanner/page.ts') },
    tsconfig: join(TOOLS, 'tsconfig.scanner.json'),
    splitting: true,
    define: { ...browser.define, __WORKER_URL__: JSON.stringify(workerUrl) },
    esbuildOptions(options) {
      options.entryNames = '[name]-[hash]';
      options.chunkNames = '[name]-[hash]';
      options.legalComments = 'none';
    },
  });
  const names = moveAll(pageFiles, target);
  const page = names.find((name) => name.startsWith('scan-page-'));
  if (!page) throw new Error('No scan-page entry was built.');
  return {
    page: `/assets/scanner/${page}`,
    worker: workerUrl,
    files: [worker, ...names],
  };
}

/** Writes site/api/kev.mjs, the one Vercel Function. */
export async function buildKevFunction(target: string): Promise<void> {
  const files = await bundle({
    entry: { kev: join(TOOLS, 'api/kev.ts') },
    platform: 'node',
    target: 'node20',
    minify: false,
    splitting: false,
    tsconfig: join(TOOLS, 'tsconfig.json'),
    banner: banner('site-tools/api/kev.ts and src/kev.ts'),
    outExtension: () => ({ js: '.mjs' }),
    esbuildOptions(options) {
      options.legalComments = 'none';
    },
  });
  const names = moveAll(files, target);
  if (names.join() !== 'kev.mjs')
    throw new Error(`Unexpected function output: ${names.join(', ')}`);
}
