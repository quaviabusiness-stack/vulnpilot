// Renders the committed proof capture (site-tools/proof/, written by
// scripts/capture-proof.mjs) into the regions of site/index.html and
// site/docs.html. The CLI's text is never changed: lines are copied from the
// capture and only their ANSI codes become the terminal classes.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Report } from '../../src/report.js';
import { ansiSegments, escapeHtml, segmentsToHtml } from '../scanner/ansi.js';
import { TOOLS } from './paths.js';

export interface ProofMeta {
  package: string;
  cliVersion: string;
  integrity: string;
  capturedAt: string;
  shownCommand: string;
  args: string[];
  exitCode: number;
  sha256: Record<string, string>;
}

export interface Proof {
  meta: ProofMeta;
  /** One entry per output line, still with ANSI codes. */
  lines: string[];
  /** The same lines without ANSI codes. */
  plain: string[];
  text: string;
  report: Report;
  help: string;
}

const PROOF = join(TOOLS, 'proof');
const read = (name: string) => readFileSync(join(PROOF, name), 'utf8');
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

export function longDate(iso: string, separator = ' '): string {
  const [year, month, day] = iso.slice(0, 10).split('-').map(Number);
  return [day, MONTHS[month! - 1], year].join(separator);
}

export function loadProof(): Proof {
  const meta = JSON.parse(read('meta.json')) as ProofMeta;
  const raw = readFileSync(join(PROOF, 'run.ansi'));
  // A capture that was edited by hand no longer matches its recorded hash.
  for (const name of ['run.ansi', 'run.json', 'help.txt'])
    if (
      createHash('sha256')
        .update(readFileSync(join(PROOF, name)))
        .digest('hex') !== meta.sha256[name]
    )
      throw new Error(`site-tools/proof/${name} does not match meta.json.`);
  const ansi = raw.toString('utf8');
  if (!ansi.endsWith('\n'))
    throw new Error('run.ansi must end with a newline.');
  const lines = ansi.slice(0, -1).split('\n');
  // Styles never span lines in the CLI's output; each line stands alone.
  const plain = lines.map((line) =>
    ansiSegments(line)
      .map((segment) => segment.text)
      .join(''),
  );
  const text = read('run.txt');
  if (`${plain.join('\n')}\n` !== text)
    throw new Error('run.txt does not match run.ansi.');
  const report = JSON.parse(read('run.json')) as Report;
  if (report.tool.version !== meta.cliVersion)
    throw new Error('run.json was not produced by the captured version.');
  return { meta, lines, plain, text, report, help: read('help.txt') };
}

interface Layout {
  craEnd: number;
  countsStart: number;
  skipped: number;
  warning: number;
  topStart: number;
  issuesEnd: number;
  cta: number;
}

/**
 * Finds the parts of the run the page annotates. If the output changes shape,
 * this fails instead of guessing: decide how the page should present it.
 */
export function runLayout(plain: string[]): Layout {
  const expect = (condition: boolean, what: string) => {
    if (!condition)
      throw new Error(
        `The proof capture changed shape (${what}). Review site-tools/build/proof.ts and the notes on the home page.`,
      );
  };
  const at = (index: number) => plain[index] ?? '';
  expect(at(0).startsWith('Vulnpilot '), 'version header');
  expect(at(1) === '', 'blank line after the header');
  expect(at(2).startsWith('EU Cyber Resilience Act:'), 'CRA screen');
  const craEnd = plain.indexOf('', 2);
  const countsStart = craEnd + 1;
  expect(at(countsStart).startsWith('Dependencies '), 'summary counts');
  expect(at(countsStart + 3).startsWith('Actively exploited '), 'KEV count');
  const skipped = countsStart + 4;
  expect(/^\d+ entr(?:y|ies) skipped /.test(at(skipped)), 'skipped line');
  expect(at(skipped + 1) === '', 'blank line before the 24-hour line');
  const warning = skipped + 2;
  expect(at(warning).startsWith('>>> '), 'the 24-hour line');
  expect(at(warning + 1) === '', 'blank line after the 24-hour line');
  const topStart = warning + 2;
  expect(/^Top 10 of \d+ issue\(s\)/.test(at(topStart)), 'ten issues shown');
  const issuesEnd = plain.indexOf('', topStart);
  expect(issuesEnd - topStart - 1 === 30, 'three lines per issue');
  const cta = issuesEnd + 1;
  expect(at(cta).startsWith('Get continuous monitoring'), 'waitlist line');
  expect(cta === plain.length - 1, 'nothing after the waitlist line');
  return { craEnd, countsStart, skipped, warning, topStart, issuesEnd, cta };
}

const PROMPT = '<span class="t-p" aria-hidden="true">$ </span>';
const lineHtml = (line: string) => segmentsToHtml(ansiSegments(line));

/** The command as the page shows it, wrapped after the input argument. */
export function commandLines(meta: ProofMeta): [string, string] {
  const [first = '', second = '', ...rest] = meta.args;
  return [`npx vulnpilot ${first} ${second} \\`, `    ${rest.join(' ')}`];
}

const pre = (html: string, className?: string) =>
  `<pre${className ? ` class="${className}"` : ''}><code>${html}</code></pre>`;

/** Generated regions of site/index.html, keyed by region name. */
export function homeRegions(proof: Proof): Record<string, string> {
  const { lines, plain, meta, report } = proof;
  const layout = runLayout(plain);
  if (meta.exitCode !== 1)
    throw new Error(
      'The home page explains exit code 1; the capture exited differently.',
    );
  const slice = (from: number, to: number, blankAfter = false) =>
    lines.slice(from, to).map(lineHtml).join('\n') + (blankAfter ? '\n' : '');
  const [command1, command2] = commandLines(meta).map(escapeHtml) as [
    string,
    string,
  ];

  // Hero: the summary through the second issue, one span per line for the
  // line-by-line reveal (classes l3 to l17 exist in the stylesheet).
  const heroLines = lines.slice(layout.countsStart, layout.topStart + 7);
  if (heroLines.length !== 15)
    throw new Error('The hero expects exactly 15 output lines.');
  const hero = [
    pre(
      `<span class="ln l1">${PROMPT}${command1}</span>\n<span class="ln l2">${command2}</span>`,
      'term-cmd',
    ),
    `<p class="term-gap"><span>Lines 1–${layout.countsStart}, the version header and the CRA screen, are in the full run below.</span></p>`,
    pre(
      heroLines
        .map(
          (line, index) =>
            `<span class="ln l${index + 3}">${lineHtml(line)}</span>`,
        )
        .join('\n'),
      'term-out',
    ),
  ].join('\n');

  const first = report.issues[0];
  if (!first) throw new Error('The capture has no issues to excerpt.');
  const excerpt = {
    schemaVersion: report.schemaVersion,
    summary: report.summary,
    issues: [
      {
        package: {
          ecosystem: first.package.ecosystem,
          name: first.package.name,
          version: first.package.version,
        },
        cves: first.cves,
        severity: { level: first.severity.level, score: first.severity.score },
        recommendedFix: first.recommendedFix,
        kev: first.kev && {
          cve: first.kev.cve,
          dateAdded: first.kev.dateAdded,
          knownRansomwareCampaignUse: first.kev.knownRansomwareCampaignUse,
        },
        epss: first.epss && { score: first.epss.score, date: first.epss.date },
      },
    ],
  };

  return {
    'proof-hero': hero,
    'proof-run-1': pre(
      `${PROMPT}${command1}\n${command2}\n${slice(0, 1, true)}`,
    ),
    'proof-run-2': pre(slice(2, layout.craEnd, true)),
    'proof-run-3': pre(slice(layout.countsStart, layout.countsStart + 4)),
    'proof-run-4': pre(slice(layout.skipped, layout.warning + 1, true)),
    'proof-run-5': pre(slice(layout.topStart, layout.topStart + 4)),
    'proof-run-6': pre(slice(layout.topStart + 4, layout.issuesEnd, true)),
    'proof-run-7': pre(
      `${slice(layout.cta, layout.cta + 1)}\n${PROMPT}echo $?\n${meta.exitCode}`,
    ),
    'proof-json': pre(escapeHtml(JSON.stringify(excerpt, null, 2))),
  };
}

/** Values filled into `data-proof` elements on any page. */
export function proofValues(proof: Proof): Record<string, string> {
  return {
    'cli-version': escapeHtml(proof.meta.cliVersion),
    'capture-date': longDate(proof.meta.capturedAt, '&nbsp;'),
    issues: String(proof.report.summary.issues),
  };
}

export function captureDate(proof: Proof): string {
  return proof.meta.capturedAt.slice(0, 10);
}

/** The --help capture for /docs. */
export function helpRegion(proof: Proof): string {
  return pre(
    `${PROMPT}npx vulnpilot --help\n${escapeHtml(proof.help.replace(/\n$/, ''))}`,
  );
}
