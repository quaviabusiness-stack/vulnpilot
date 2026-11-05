import { CLI_VERSION } from './build-info.js';
import type { Answers, Finding, ResultBucket } from './types.js';

export const DISCLAIMER =
  'Placeholder screening only; not legal advice. Three answers cannot determine CRA scope or compliance. A zero count is not a security guarantee.';

export function assessCra(answers: Answers): ResultBucket {
  // TODO: Replace this preliminary heuristic with a reviewed scope assessment.
  if (answers.euDistribution === 'no') return 'likely-out-of-scope';
  if (
    answers.euDistribution === 'yes' &&
    answers.commercial === 'yes' &&
    answers.productType !== 'unknown'
  )
    return 'likely-applies';
  return 'needs-review';
}

export function createReport(
  answers: Answers,
  findings: Finding[],
  mocked: boolean,
) {
  return {
    cliVersion: CLI_VERSION,
    dataSource: mocked ? 'mock-fixture' : 'osv.dev',
    dependencyCount: findings.length,
    vulnerableDependencyCount: findings.filter(
      (item) => item.vulnerabilityIds.length > 0,
    ).length,
    // Counts distinct OSV IDs, not alias-normalized CVEs or occurrences.
    vulnerabilityCount: new Set(
      findings.flatMap((item) => item.vulnerabilityIds),
    ).size,
    cra: { result: assessCra(answers), answers },
    disclaimer: DISCLAIMER,
  };
}

export function formatReport(
  report: ReturnType<typeof createReport>,
  json: boolean,
): string {
  if (json) return JSON.stringify(report, null, 2);
  return [
    `Vulnpilot ${report.cliVersion}${report.dataSource === 'mock-fixture' ? ' (MOCK DATA)' : ''}`,
    `Dependencies checked: ${report.dependencyCount}`,
    `Known vulnerabilities (distinct OSV IDs): ${report.vulnerabilityCount}`,
    `Dependencies with known vulnerabilities: ${report.vulnerableDependencyCount}`,
    `CRA preliminary result: ${report.cra.result}`,
    report.disclaimer,
  ].join('\n');
}
