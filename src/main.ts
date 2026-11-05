import { Command, Option } from 'commander';
import { CLI_VERSION } from './build-info.js';
import { readDependencies } from './lockfiles/index.js';
import { queryOsv } from './osv.js';
import { askQuestions } from './questions.js';
import { createReport, formatReport } from './report.js';
import { sendTelemetry } from './telemetry.js';
import type { Answer, ProductType } from './types.js';

interface CliOptions {
  path: string;
  json?: boolean;
  telemetry: boolean;
  nonInteractive?: boolean;
  euDistribution?: Answer;
  commercial?: Answer;
  productType?: ProductType;
}

export async function runCli(argv = process.argv): Promise<void> {
  const program = new Command()
    .name('vulnpilot')
    .description(
      'Check lockfile dependencies with OSV and screen CRA applicability (not legal advice).',
    )
    .version(CLI_VERSION)
    .option(
      '--path <path>',
      'Project directory or supported dependency lockfile',
      '.',
    )
    .option('--json', 'Print JSON; skip interactive prompts')
    .option('--no-telemetry', 'Disable anonymous usage telemetry')
    .option(
      '--non-interactive',
      'Skip prompts; unanswered questions become unknown',
    )
    .addOption(
      new Option(
        '--eu-distribution <answer>',
        'Sell or distribute in the EU?',
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
        'unknown',
      ]),
    );

  await program.parseAsync(argv);
  const options = program.opts<CliOptions>();
  const dependencies = await readDependencies(options.path);
  const interactive =
    !options.json &&
    !options.nonInteractive &&
    process.env.CI === undefined &&
    Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const answers = await askQuestions(
    {
      ...(options.euDistribution === undefined
        ? {}
        : { euDistribution: options.euDistribution }),
      ...(options.commercial === undefined
        ? {}
        : { commercial: options.commercial }),
      ...(options.productType === undefined
        ? {}
        : { productType: options.productType }),
    },
    interactive,
  );
  const mocked = process.env.OSV_MOCK === '1';
  const findings = await queryOsv(dependencies, { mock: mocked });
  const report = createReport(answers, findings, mocked);
  console.log(formatReport(report, Boolean(options.json)));
  await sendTelemetry({
    enabled: options.telemetry,
    dependencyCount: report.dependencyCount,
    resultBucket: report.cra.result,
  });
}
