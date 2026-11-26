// Renders the committed proof capture (site-tools/proof/, written by
// scripts/capture-proof.mjs) into the regions of site/index.html and
// site/docs.html. The CLI's text is never changed: lines are copied from the
// capture and only their ANSI codes become the terminal classes.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Report } from '../../src/report.js';
import { ansiSegments, escapeHtml, segmentsToHtml } from '../scanner/ansi.js';
import { purlToDependency } from '../../src/lockfiles/cyclonedx.js';
import { ROOT, TOOLS } from './paths.js';

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

export interface Layout {
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

/** Issues the hero shows, three lines each. */
export const HERO_ISSUES = 5;

/** The package and CVE of a printed issue line, e.g. " 1. lodash@4.17.20  CVE-…". */
export function issueKey(plainLine: string): { pkg: string; cve: string } {
  const match = /^\s*\d+\. (\S+)\s{2}(\S+)\s{2}/.exec(plainLine);
  if (!match) throw new Error(`Not an issue line: ${plainLine}`);
  return { pkg: match[1]!, cve: match[2]! };
}

/**
 * The hero terminal: the command, then one contiguous slice of the run from
 * the summary counts to the fifth issue. Issues are wrapped three lines at a
 * time so the page can show them sorted by package first and then move them
 * to the order the CLI printed. `data-found` is that package order; the HTML
 * order is always the CLI's.
 */
function heroRegion(
  proof: Proof,
  layout: Layout,
  command1: string,
  command2: string,
): string {
  const { lines, plain } = proof;
  const head = lines.slice(layout.countsStart, layout.topStart + 1);
  const headPlain = plain.slice(layout.countsStart, layout.topStart + 1);
  const kind = (index: number, text: string) => {
    if (index < 4) return 'ln-count';
    if (text === '') return 'ln-blank';
    if (text.startsWith('>>> ')) return 'ln-warn';
    if (index === head.length - 1) return 'ln-top';
    return 'ln-note';
  };
  // Every line is its own block with its newline inside, so a wrapped line
  // can hang under its own text and a moved issue leaves no gap behind.
  const total = head.length + HERO_ISSUES * 3;
  let emitted = 0;
  const line = (className: string, html: string) => {
    emitted += 1;
    return `<span class="${className}">${html}${emitted < total ? '\n' : ''}</span>`;
  };
  const headHtml = head
    .map((source, index) =>
      line(
        `ln ${kind(index, headPlain[index]!)} l${index + 1}`,
        lineHtml(source),
      ),
    )
    .join('');

  const issues = Array.from({ length: HERO_ISSUES }, (_, index) => {
    const from = layout.topStart + 1 + index * 3;
    return {
      key: issueKey(plain[from]!),
      kev: plain[from]!.endsWith('KNOWN EXPLOITED'),
      html: lines
        .slice(from, from + 3)
        .map((source) => line('ln', lineHtml(source)))
        .join(''),
    };
  });
  const found = [...issues].sort(
    (a, b) =>
      a.key.pkg.localeCompare(b.key.pkg) || a.key.cve.localeCompare(b.key.cve),
  );
  const issuesHtml = issues
    .map(
      (issue, index) =>
        `<span class="issue i${index + 1}${issue.kev ? ' is-kev' : ''}" data-found="${found.indexOf(issue) + 1}">${issue.html}</span>`,
    )
    .join('');

  return [
    pre(
      `<span class="ln c1">${PROMPT}${command1}\n</span><span class="ln c2">${command2}</span>`,
      'term-cmd',
    ),
    pre(`${headHtml}${issuesHtml}`, 'term-out'),
  ].join('\n');
}

const fmtDate = (iso: string) => longDate(iso, '&nbsp;');

/** "log4j-core" for Maven coordinates, the name as is otherwise. */
const shortName = (name: string) => name.slice(name.lastIndexOf(':') + 1);

/** Step 1 of "How it works": what the sample SBOM contains and what was read. */
export function storyRead(proof: Proof, sbom: string): string {
  const bom = JSON.parse(sbom) as {
    metadata?: {
      component?: { type?: string; name?: string; version?: string };
    };
    specVersion?: string;
    components?: unknown[];
  };
  interface Row {
    name: string;
    version: string;
    kind: string;
    status: 'read' | 'duplicate' | 'skipped';
    why: string;
  }
  const rows: Row[] = [];
  const seen = new Set<string>();
  const visit = (components: unknown[]) => {
    for (const raw of components) {
      const component = raw as {
        group?: string;
        name?: string;
        version?: string;
        purl?: string;
        cpe?: string;
        components?: unknown[];
      };
      const dependency =
        typeof component.purl === 'string'
          ? purlToDependency(component.purl)
          : undefined;
      const name = component.group
        ? `${component.group.startsWith('@') ? `${component.group}/` : ''}${component.name ?? ''}`
        : (component.name ?? '');
      const version = component.version ?? '';
      if (!dependency) {
        rows.push({
          name,
          version,
          kind: component.purl
            ? `pkg:${component.purl.slice(4).split('/')[0]}`
            : component.cpe
              ? 'CPE only'
              : 'no purl',
          status: 'skipped',
          why: component.purl ? 'unsupported purl type' : 'no purl',
        });
      } else {
        const id = `${dependency.ecosystem}:${dependency.name}@${dependency.version}`;
        rows.push({
          name,
          version,
          kind: dependency.ecosystem || 'purl',
          status: seen.has(id) ? 'duplicate' : 'read',
          why: seen.has(id) ? 'listed twice, read once' : '',
        });
        seen.add(id);
      }
      if (Array.isArray(component.components)) visit(component.components);
    }
  };
  visit(bom.components ?? []);
  const read = rows.filter((row) => row.status === 'read').length;
  const skipped = rows.filter((row) => row.status === 'skipped').length;
  if (
    read !== proof.report.input.dependencies ||
    skipped !== proof.report.input.skipped
  )
    throw new Error(
      `The sample SBOM reads as ${read} dependencies and ${skipped} skipped, the capture says ${proof.report.input.dependencies} and ${proof.report.input.skipped}.`,
    );
  const product = bom.metadata?.component;
  const items = rows
    .map(
      (row) =>
        `<li class="file-row is-${row.status}"><span class="file-name">${escapeHtml(row.name)}</span><span class="file-version">${escapeHtml(row.version)}</span><span class="file-kind">${escapeHtml(row.kind)}</span><span class="file-status">${row.status === 'read' ? 'read' : escapeHtml(row.why)}</span></li>`,
    )
    .join('\n');
  return `<div class="story-card story-read">
<p class="story-card-head"><span class="story-file">${escapeHtml(proof.report.input.file.split('/').pop() ?? '')}</span><span>CycloneDX ${escapeHtml(bom.specVersion ?? '')} · ${escapeHtml(product?.type ?? '')} ${escapeHtml(product?.name ?? '')} ${escapeHtml(product?.version ?? '')}</span></p>
<ul class="file-rows">
${items}
</ul>
<p class="story-card-foot"><strong>${read} dependencies</strong> read · ${skipped} skipped and counted, not dropped</p>
</div>`;
}

/** Step 2: what each source was sent and what came back. */
export function storyMatch(proof: Proof): string {
  const { report } = proof;
  const kev = report.issues.filter((issue) => issue.kev);
  const cves = new Set(report.issues.flatMap((issue) => issue.cves));
  const scored = report.issues.filter((issue) => issue.epss);
  const epssDate = scored[0]?.epss?.date;
  if (!epssDate) throw new Error('The capture has no EPSS scores.');
  const { dependencies, vulnerablePackages, issues } = report.summary;
  const source = (
    name: string,
    sent: string,
    got: string,
    signal = false,
  ) => `<li class="source${signal ? ' is-signal' : ''}">
<p class="source-name">${name}</p>
<p class="source-sent">${sent}</p>
<p class="source-got">${got}</p>
</li>`;
  return `<div class="story-card story-match">
<ul class="sources">
${source('OSV.dev', `Sent: ${dependencies} package names and versions`, `<strong>${issues}</strong> known vulnerabilities in ${vulnerablePackages} of ${dependencies} packages`)}
${source('CISA KEV', 'Sent: nothing. The catalog is downloaded', `<strong>${kev.length}</strong> known exploited: ${kev.map((issue) => escapeHtml(issue.kev!.cve)).join(', ')}`, true)}
${source('FIRST EPSS', `Sent: ${cves.size} CVE IDs`, `<strong>${scored.length}</strong> exploit-likelihood scores, ${fmtDate(epssDate)}`)}
</ul>
</div>`;
}

/** Step 3: the first issues as the CLI ranked them, from its own text. */
export function storyRank(proof: Proof, layout: Layout): string {
  const { plain, report } = proof;
  const rows = Array.from({ length: HERO_ISSUES }, (_, index) => {
    const line = plain[layout.topStart + 1 + index * 3]!;
    const fix = plain[layout.topStart + 3 + index * 3]!.trim();
    const match =
      /^\s*(\d+)\. (\S+)\s{2}(\S+)\s{2}(\w+) ([\d.]+) · EPSS (\S+)( · KNOWN EXPLOITED)?$/.exec(
        line,
      );
    if (!match || !fix.startsWith('Fix: upgrade to '))
      throw new Error(`Unexpected issue line: ${line}`);
    const [, rank, pkg, cve, level, score, epss, kev] = match;
    const at = pkg!.lastIndexOf('@');
    return `<tr${kev ? ' class="is-kev"' : ''}>
<td class="rank-n">${rank}</td>
<td class="rank-pkg"><span>${escapeHtml(shortName(pkg!.slice(0, at)))}</span> <span class="rank-ver">${escapeHtml(pkg!.slice(at + 1))}</span></td>
<td class="rank-cve">${escapeHtml(cve!)}${kev ? ' <span class="kev-badge">KEV</span>' : ''}</td>
<td class="rank-cvss">${escapeHtml(level!.toLowerCase())} ${escapeHtml(score!)}</td>
<td class="rank-epss">${escapeHtml(epss!)}</td>
<td class="rank-fix">${escapeHtml(fix.slice('Fix: upgrade to '.length))}</td>
</tr>`;
  });
  return `<div class="story-card story-rank">
<table class="rank-table">
<caption class="visually-hidden">The first ${HERO_ISSUES} of ${report.summary.issues} issues, in the order the CLI printed them</caption>
<thead><tr><th scope="col">#</th><th scope="col">Package</th><th scope="col">CVE</th><th scope="col">CVSS</th><th scope="col">EPSS</th><th scope="col">Fix</th></tr></thead>
<tbody>
${rows.join('\n')}
</tbody>
</table>
<p class="story-card-foot">Showing ${HERO_ISSUES} of ${report.summary.issues}. Known exploited first, then EPSS, then CVSS.</p>
</div>`;
}

/** The CISA catalog entry behind the first issue. */
export function kevEntry(proof: Proof): string {
  const issue = proof.report.issues.find((candidate) => candidate.kev);
  if (!issue?.kev) throw new Error('The capture has no KEV issue.');
  const rank = proof.report.issues.indexOf(issue) + 1;
  const ransomware = issue.kev.knownRansomwareCampaignUse;
  return `<div class="kev-entry">
<p class="kev-entry-head"><span class="kev-badge">KEV</span> <span>${escapeHtml(issue.kev.cve)}</span></p>
<dl class="kev-facts">
<div><dt>Package</dt><dd>${escapeHtml(shortName(issue.package.name))} ${escapeHtml(issue.package.version)}</dd></div>
<div><dt>In the CISA catalog since</dt><dd>${fmtDate(issue.kev.dateAdded)}</dd></div>
<div><dt>Known ransomware use</dt><dd>${ransomware === true ? 'Yes' : ransomware === false ? 'No' : 'Unknown'}</dd></div>
<div><dt>Vulnpilot rank</dt><dd>${rank} of ${proof.report.summary.issues}</dd></div>
</dl>
</div>`;
}

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

  const hero = heroRegion(proof, layout, command1, command2);

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
    'proof-story-read': storyRead(
      proof,
      readFileSync(join(ROOT, report.input.file), 'utf8'),
    ),
    'proof-story-match': storyMatch(proof),
    'proof-story-rank': storyRank(proof, layout),
    'proof-kev-entry': kevEntry(proof),
  };
}

/** Values filled into `data-proof` elements on any page. */
export function proofValues(proof: Proof): Record<string, string> {
  return {
    'cli-version': escapeHtml(proof.meta.cliVersion),
    'capture-date': longDate(proof.meta.capturedAt, '&nbsp;'),
    issues: String(proof.report.summary.issues),
    dependencies: String(proof.report.summary.dependencies),
    'vulnerable-packages': String(proof.report.summary.vulnerablePackages),
    'critical-high': String(proof.report.summary.criticalOrHigh),
    kev: String(proof.report.summary.activelyExploited),
    skipped: String(proof.report.input.skipped),
    'scan-time': scanTime(proof),
    'first-fix': escapeHtml(proof.report.issues[0]?.recommendedFix ?? ''),
  };
}

/** The scan time the CLI printed in its header line, e.g. "2.4". */
function scanTime(proof: Proof): string {
  const match = /· ([\d.]+)s$/.exec(proof.plain[0] ?? '');
  if (!match) throw new Error('The header line has no scan time.');
  return match[1]!;
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
