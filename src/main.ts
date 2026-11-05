import { Command, CommanderError, Option } from 'commander';
import { CLI_VERSION, WAITLIST_URL } from './build-info.js';
import { Cache, defaultCacheDir } from './cache.js';
import { assessCra } from './cra.js';
import { createHttpClient, errorMessage } from './http.js';
import { readLockfile, readSbom } from './lockfiles/index.js';
import { createMockFetch } from './mock.js';
import { askQuestions, CancelledError } from './questions.js';
import {
  createReport,
  exitCodeFor,
  type FailOn,
  formatText,
} from './report.js';
import { scan, type ScanResult } from './scan.js';
import { sendTelemetry, telemetryEvent } from './telemetry.js';
import type { Answer, Inventory, ProductType } from './types.js';

interface CliOptions {
  path: string;
  sbom?: string;
  json?: boolean;
  telemetry: boolean;
  color: boolean;
  offline?: boolean;
  failOn?: FailOn;
  nonInteractive?: boolean;
  euDistribution?: Answer;
  commercial?: Answer;
  productType?: ProductType;
}

/** Injection points for tests; production uses the real process and network. */
export interface CliEnvironment {
  env?: NodeJS.ProcessEnv;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  interactive?: boolean;
  telemetryFetch?: typeof fetch;
}

export const EXIT = { ok: 0, issues: 1, error: 2 } as const;

function buildProgram(
  stderr: (text: string) => void,
  stdout: (text: string) => void,
) {
  return new Command()
    .name('vulnpilot')
    .description(
      'Check dependencies for known and actively exploited vulnerabilities, and screen EU Cyber Resilience Act applicability (not legal advice).',
    )
    .version(CLI_VERSION)
    .option('--path <path>', 'Project directory or lockfile', '.')
    .option('--sbom <file>', 'Scan a CycloneDX JSON SBOM instead of a lockfile')
    .option('--json', 'Print the machine-readable JSON report; skip prompts')
    .option('--offline', 'Use only cached vulnerability data (no network)')
    .addOption(
      new Option(
        '--fail-on <level>',
        'Exit 1 only for issues at this level (default: any issue)',
      ).choices(['critical', 'high', 'kev']),
    )
    .option(
      '--non-interactive',
      'Skip prompts; unanswered questions become unknown',
    )
    .addOption(
      new Option(
        '--eu-distribution <answer>',
        'Made available on the EU market?',
      ).choices(['yes', 'no', 'unknown']),
    )
    .addOption(
      new Option(
        '--commercial <answer>',
        'Part of a commercial activity?',
      ).choices(['yes', 'no', 'unknown']),
    )
    .addOption(
      new Option('--product-type <type>', 'Product category').choices([
        'app',
        'library',
        'firmware',
        'saas',
        'saas-with-client',
        'unknown',
      ]),
    )
    .option('--no-color', 'Disable coloured output')
    .option('--no-telemetry', 'Disable anonymous usage telemetry')
    .addHelpText(
      'after',
      '\nExit codes: 0 no issues, 1 issues found (see --fail-on), 2 error or incomplete data.\nNot legal advice.',
    )
    .exitOverride()
    .configureOutput({
      writeOut: (text) => stdout(text.trimEnd()),
      writeErr: (text) => stderr(text.trimEnd()),
    });
}

export async function runCli(
  argv: string[] = process.argv,
  io: CliEnvironment = {},
): Promise<number> {
  const env = io.env ?? process.env;
  const stdout = io.stdout ?? ((text: string) => console.log(text));
  const stderr = io.stderr ?? ((text: string) => console.error(text));
  const program = buildProgram(stderr, stdout);
  try {
    await program.parseAsync(argv);
  } catch (error) {
    if (
      error instanceof CommanderError &&
      [
        'commander.helpDisplayed',
        'commander.version',
        'commander.help',
      ].includes(error.code)
    )
      return EXIT.ok;
    return EXIT.error;
  }
  const options = program.opts<CliOptions>();

  let inventory: Inventory;
  try {
    inventory = options.sbom
      ? await readSbom(options.sbom)
      : await readLockfile(options.path);
  } catch (error) {
    stderr(`Vulnpilot: ${errorMessage(error)}`);
    return EXIT.error;
  }

  const mock = env.VULNPILOT_MOCK === '1';
  const context = {
    http: createHttpClient({
      ...(mock
        ? { fetch: createMockFetch() }
        : io.fetch
          ? { fetch: io.fetch }
          : {}),
      ...(io.sleep ? { sleep: io.sleep } : {}),
    }),
    cache: new Cache(
      mock ? null : defaultCacheDir(env),
      Boolean(options.offline),
    ),
  };

  // Start network work immediately so it overlaps with the questions.
  const started = performance.now();
  let durationMs = 0;
  const scanning: Promise<ScanResult> = scan(
    inventory.dependencies,
    context,
  ).then((result) => {
    durationMs = performance.now() - started;
    return result;
  });
  scanning.catch(() => {});

  const interactive =
    io.interactive ??
    (!options.json &&
      !options.nonInteractive &&
      env.CI === undefined &&
      Boolean(process.stdin.isTTY && process.stdout.isTTY));
  let answers;
  try {
    answers = await askQuestions(
      {
        ...(options.euDistribution && {
          euDistribution: options.euDistribution,
        }),
        ...(options.commercial && { commercial: options.commercial }),
        ...(options.productType && { productType: options.productType }),
      },
      interactive,
    );
  } catch (error) {
    stderr(
      `Vulnpilot: ${error instanceof CancelledError ? error.message : errorMessage(error)}`,
    );
    return EXIT.error;
  }

  let result: ScanResult;
  try {
    result = await scanning;
  } catch (error) {
    stderr(`Vulnpilot: scan failed: ${errorMessage(error)}`);
    return EXIT.error;
  }
  const now = io.now?.() ?? new Date();
  const report = createReport({
    inventory,
    scan: result,
    cra: assessCra(answers, now),
    mock,
    durationMs,
    now,
  });

  if (options.json) {
    stdout(JSON.stringify(report, null, 2));
    for (const source of report.sources)
      if (source.status !== 'ok')
        stderr(
          `Vulnpilot: ${source.name} ${source.status}: ${source.message ?? ''}`,
        );
  } else {
    stdout(
      formatText(report, {
        color:
          options.color &&
          env.NO_COLOR === undefined &&
          Boolean(process.stdout.isTTY) &&
          !io.stdout,
        waitlistUrl: WAITLIST_URL,
      }),
    );
  }

  await sendTelemetry({
    enabled: options.telemetry && !mock,
    env,
    event: telemetryEvent({
      dependencyCount: report.summary.dependencies,
      verdict: report.cra.verdict,
      kevCount: report.summary.activelyExploited,
    }),
    ...(io.telemetryFetch ? { fetch: io.telemetryFetch } : {}),
  });
  return exitCodeFor(report, options.failOn);
}
