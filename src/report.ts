import { CLI_VERSION } from './build-info.js';
import type { CraAssessment } from './cra.js';
import type { Issue, ScanResult } from './scan.js';
import {
  dependencyKey,
  dependencyLabel,
  type Inventory,
  type SourceName,
  type SourceReport,
} from './types.js';

/** Bump the major version on breaking changes to the JSON output. */
export const SCHEMA_VERSION = '1.0.0';

export type FailOn = 'critical' | 'high' | 'kev';

export interface Report {
  schemaVersion: typeof SCHEMA_VERSION;
  tool: { name: 'vulnpilot'; version: string };
  generatedAt: string;
  durationMs: number;
  mock: boolean;
  input: {
    format: Inventory['format'];
    file: string;
    dependencies: number;
    skipped: number;
  };
  cra: CraAssessment;
  summary: {
    dependencies: number;
    vulnerablePackages: number;
    issues: number;
    criticalOrHigh: number;
    activelyExploited: number;
    uncheckedDependencies: number;
  };
  sources: SourceReport[];
  issues: Issue[];
}

export function createReport(options: {
  inventory: Inventory;
  scan: ScanResult;
  cra: CraAssessment;
  mock: boolean;
  durationMs: number;
  now?: Date;
}): Report {
  const { inventory, scan, cra } = options;
  const vulnerable = new Set(
    scan.issues.map((issue) => dependencyKey(issue.package)),
  );
  return {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: 'vulnpilot', version: CLI_VERSION },
    generatedAt: (options.now ?? new Date()).toISOString(),
    durationMs: Math.round(options.durationMs),
    mock: options.mock,
    input: {
      format: inventory.format,
      file: inventory.file,
      dependencies: inventory.dependencies.length,
      skipped: inventory.skipped,
    },
    cra,
    summary: {
      dependencies: inventory.dependencies.length,
      vulnerablePackages: vulnerable.size,
      issues: scan.issues.length,
      criticalOrHigh: scan.issues.filter((issue) =>
        ['critical', 'high'].includes(issue.severity.level),
      ).length,
      activelyExploited: scan.issues.filter((issue) => issue.kev).length,
      uncheckedDependencies: scan.uncheckedDependencies,
    },
    sources: scan.sources,
    issues: scan.issues,
  };
}

function source(report: Report, name: SourceName): SourceReport | undefined {
  return report.sources.find((item) => item.name === name);
}

/**
 * 0 = no matching issues, 1 = matching issues found, 2 = the scan could not
 * establish the answer (error or a required data source was unavailable).
 */
export function exitCodeFor(report: Report, failOn?: FailOn): 0 | 1 | 2 {
  const { issues } = report;
  const matched =
    failOn === 'kev'
      ? issues.some((issue) => issue.kev)
      : failOn === 'critical'
        ? issues.some((issue) => issue.severity.level === 'critical')
        : failOn === 'high'
          ? issues.some((issue) =>
              ['critical', 'high'].includes(issue.severity.level),
            )
          : issues.length > 0;
  if (matched) return 1;
  // No match, but missing data means "none" cannot be claimed.
  if (source(report, 'osv')?.status !== 'ok') return 2;
  if (failOn === 'kev' && source(report, 'cisa-kev')?.status !== 'ok') return 2;
  return 0;
}

// ---------------------------------------------------------------------------
// Plain-text output.

export const REPORTING_WARNING =
  'Under the CRA, actively exploited vulnerabilities in your product must be reported within 24 hours.';

interface TextOptions {
  color: boolean;
  waitlistUrl: string;
  limit?: number;
}

const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

function longDate(iso: string): string {
  const [year, month, day] = iso.split('-').map(Number);
  return `${day} ${MONTHS[month! - 1]} ${year}`;
}

function wrap(text: string, indent: string, width = 80): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (line && indent.length + line.length + 1 + word.length > width) {
      lines.push(indent + line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(indent + line);
  return lines;
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text;
}

/** EPSS as a percentage; never rounds a non-certain probability up to 100%. */
export function formatEpss(score: number): string {
  return score >= 0.9995 && score < 1
    ? '>99.9%'
    : `${(score * 100).toFixed(1)}%`;
}

export function ctaUrl(waitlistUrl: string): string {
  if (!waitlistUrl) return '';
  return `${waitlistUrl}${waitlistUrl.includes('?') ? '&' : '?'}utm_source=cli`;
}

const SOURCE_NAMES: Record<SourceName, string> = {
  osv: 'OSV.dev',
  'cisa-kev': 'CISA KEV',
  'first-epss': 'FIRST EPSS',
};

export function formatText(report: Report, options: TextOptions): string {
  const paint = (code: string) => (text: string) =>
    options.color ? `\u001B[${code}m${text}\u001B[0m` : text;
  const bold = paint('1');
  const dim = paint('2');
  const red = paint('1;31');
  const yellow = paint('33');
  const green = paint('32');

  const { cra, summary } = report;
  const out: string[] = [];
  out.push(
    bold(`Vulnpilot ${report.tool.version}`) +
      (report.mock ? red(' (MOCK DATA - not a real scan)') : '') +
      dim(
        ` · ${report.input.file} (${report.input.format}) · ${(report.durationMs / 1000).toFixed(1)}s`,
      ),
    '',
  );

  const verdictText = {
    likely_applies: red('LIKELY APPLIES'),
    likely_out_of_scope: green('LIKELY OUT OF SCOPE'),
    unclear: yellow('UNCLEAR'),
  }[cra.verdict];
  out.push(`${bold('EU Cyber Resilience Act:')} ${verdictText}`);
  out.push(...wrap(cra.reason, '  '));
  out.push(
    dim(
      `  Answers: EU market: ${cra.answers[0]!.answer} · commercial: ${cra.answers[1]!.answer} · product: ${cra.answers[2]!.answer}`,
    ),
  );
  out.push('  Key dates:');
  for (const item of cra.keyDates)
    out.push(
      ...wrap(
        `${longDate(item.date)}${item.inForce ? ' (in force)' : ''}: ${item.obligation}`,
        '    ',
      ),
    );
  out.push(`  ${bold(cra.disclaimer)}`, '');

  const pad = (label: string) => label.padEnd(24);
  out.push(`${pad('Dependencies')}${summary.dependencies}`);
  out.push(`${pad('Vulnerable packages')}${summary.vulnerablePackages}`);
  out.push(
    `${pad('Critical/high issues')}${summary.criticalOrHigh > 0 ? red(String(summary.criticalOrHigh)) : summary.criticalOrHigh}`,
  );
  out.push(
    `${pad('Actively exploited')}${summary.activelyExploited > 0 ? red(String(summary.activelyExploited)) : summary.activelyExploited} ${dim('(CISA KEV)')}`,
  );
  if (report.input.skipped > 0)
    out.push(
      dim(
        `${report.input.skipped} entr${report.input.skipped === 1 ? 'y' : 'ies'} skipped (local/git/workspace links or components without a supported purl).`,
      ),
    );

  if (summary.activelyExploited > 0 && cra.verdict === 'likely_applies')
    out.push('', red(`>>> ${REPORTING_WARNING}`));

  const limit = options.limit ?? 10;
  if (report.issues.length > 0) {
    out.push(
      '',
      bold(
        `Top ${Math.min(limit, report.issues.length)} of ${report.issues.length} issue(s)`,
      ) + dim(' (KEV first, then EPSS, then CVSS)'),
    );
    report.issues.slice(0, limit).forEach((issue, index) => {
      const cve = issue.cves[0] ?? issue.id;
      const severity =
        issue.severity.level === 'unknown'
          ? dim('severity unknown')
          : `${issue.severity.level.toUpperCase()}${issue.severity.score === null ? '' : ` ${issue.severity.score.toFixed(1)}`}`;
      const tags = [
        severity,
        issue.epss ? `EPSS ${formatEpss(issue.epss.score)}` : '',
        issue.kev ? red('KNOWN EXPLOITED') : '',
      ].filter(Boolean);
      out.push(
        `${String(index + 1).padStart(2)}. ${bold(dependencyLabel(issue.package))}  ${cve}  ${tags.join(' · ')}`,
      );
      out.push(
        `    ${truncate(issue.summary || (issue.detailsAvailable ? issue.id : `${issue.id} (details unavailable)`), 100)}`,
      );
      out.push(
        `    ${issue.recommendedFix ? `Fix: upgrade to ${issue.recommendedFix}` : dim('Fix: no fixed version published')}`,
      );
    });
  } else if (source(report, 'osv')?.status === 'ok') {
    out.push('', green('No known vulnerabilities found.'));
  }

  const problems = report.sources.filter(
    (item) => item.status !== 'ok' || item.message,
  );
  if (problems.length > 0) out.push('');
  for (const item of problems)
    out.push(
      yellow(
        `${SOURCE_NAMES[item.name]} ${item.status === 'ok' ? 'note' : item.status}: ${item.message ?? ''}`,
      ),
    );
  if (source(report, 'osv')?.status === 'unavailable')
    out.push(
      red('Vulnerability data could not be retrieved; results are incomplete.'),
    );

  const cta = ctaUrl(options.waitlistUrl);
  if (cta)
    out.push(
      '',
      dim(
        `Get continuous monitoring and ready-to-send 24h report drafts: ${cta}`,
      ),
    );
  return out.join('\n');
}
