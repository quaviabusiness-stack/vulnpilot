// Static checks of the built site, run in CI after the generator:
//
//   pnpm --filter site-tools check
//
// proof     CLI excerpts equal the corresponding lines of the stored capture
// faq       the FAQPage JSON-LD matches the questions shown on the home page
// links     every internal link and fragment resolves
// budgets   gzip sizes per page and for the scanner chunks
// scanner   scanner chunks load only on /scan
// security  security.txt has a contact and does not expire within 30 days
// html      html-validate on every page
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { HtmlValidate } from 'html-validate';
import { PAGES, SITE, TOOLS } from '../build/paths.js';

const failures: string[] = [];
const fail = (message: string) => failures.push(message);
const page = (name: string) => readFileSync(join(SITE, name), 'utf8');
const gzip = (content: string | Buffer) =>
  gzipSync(content, { level: 9 }).length;
const KB = 1024;

// ---------------------------------------------------------------------------
// proof: independent of the generator, rebuild the text from the page.

function unescape(html: string): string {
  return html
    .replace(/<[^>]+>/g, '')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&nbsp;', ' ')
    .replaceAll('&amp;', '&');
}

function region(html: string, name: string): string {
  const match = new RegExp(
    `<!-- generated:${name} -->([\\s\\S]*?)<!-- /generated:${name} -->`,
  ).exec(html);
  if (!match) throw new Error(`Region ${name} not found`);
  return match[1]!;
}

function codeText(html: string): string {
  const match = /<code>([\s\S]*)<\/code>/.exec(html);
  if (!match) throw new Error('No <code> in region');
  return unescape(match[1]!);
}

function checkProof(): void {
  const proof = join(TOOLS, 'proof');
  // The page provides current CRA guidance separately from the captured output.
  const run = readFileSync(join(proof, 'run.txt'), 'utf8').replace(
    /^>>> [^\n]*\n\n/m,
    '',
  );
  const help = readFileSync(join(proof, 'help.txt'), 'utf8');
  const meta = JSON.parse(readFileSync(join(proof, 'meta.json'), 'utf8')) as {
    args: string[];
    exitCode: number;
    cliVersion: string;
  };
  const home = page('index.html');
  const rows = [1, 2, 3, 4, 5, 6, 7].map((row) =>
    codeText(region(home, `proof-run-${row}`)),
  );
  // Row 1 starts with the command (two lines); row 7 ends with `$ echo $?` and the code.
  const first = rows[0]!.split('\n');
  const command = `${first[0]}\n${first[1]}`;
  const expectedCommand = `$ npx vulnpilot ${meta.args.slice(0, 2).join(' ')} \\\n    ${meta.args.slice(2).join(' ')}`;
  if (command !== expectedCommand)
    fail('proof: the command on the page is not the captured command');
  rows[0] = first.slice(2).join('\n');
  const last = rows[6]!.split('\n');
  if (last.slice(-2).join('\n') !== `$ echo $?\n${meta.exitCode}`)
    fail('proof: the exit code on the page is not the captured exit code');
  rows[6] = last.slice(0, -2).join('\n');
  const text = `${rows.join('\n')}\n`;
  if (text !== run)
    fail(
      'proof: the annotated run on the home page differs from the expected excerpt',
    );

  const hero = region(home, 'proof-hero');
  const heroLines = codeText(
    hero.slice(hero.indexOf('class="term-out"')),
  ).split('\n');
  const start = run.split('\n').indexOf(heroLines[0]!);
  if (
    start < 0 ||
    run
      .split('\n')
      .slice(start, start + heroLines.length)
      .join('\n') !== heroLines.join('\n')
  )
    fail('proof: the hero output is not a contiguous slice of the capture');

  const docs = page('docs.html');
  const helpText = codeText(region(docs, 'docs-help'));
  if (helpText !== `$ npx vulnpilot --help\n${help.replace(/\n$/, '')}`)
    fail(
      'proof: the help text on /docs differs from site-tools/proof/help.txt',
    );

  // Every flag in the docs table appears in the captured help, and the reverse.
  const table =
    /<table class="ref-table" id="flags-table">([\s\S]*?)<\/table>/.exec(
      docs,
    )?.[1] ?? '';
  const documented = new Set(
    [...unescape(table).matchAll(/--[a-z-]+/g)].map((m) => m[0]),
  );
  const helped = new Set(
    [...help.matchAll(/^\s+(?:-\w, )?(--[a-z-]+)/gm)].map((m) => m[1]!),
  );
  for (const flag of helped)
    if (!documented.has(flag))
      fail(`proof: ${flag} is in --help but not in the /docs flags table`);
  for (const flag of documented)
    if (!helped.has(flag))
      fail(`proof: ${flag} is in the /docs flags table but not in --help`);

  for (const [name, html] of [
    ['index.html', home],
    ['docs.html', docs],
  ] as const)
    for (const match of html.matchAll(
      /data-proof="cli-version"[^>]*>([^<]*)</g,
    ))
      if (match[1] !== meta.cliVersion)
        fail(`proof: ${name} shows version ${match[1]}`);
}

// ---------------------------------------------------------------------------
// faq: the FAQPage JSON-LD on the home page says exactly what the page shows.

function normalise(text: string): string {
  return unescape(text).replace(/\s+/g, ' ').trim();
}

function checkFaq(): void {
  const home = page('index.html');
  const json = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(
    home,
  )?.[1];
  if (!json) {
    fail('faq: the home page has no JSON-LD');
    return;
  }
  const graph = (JSON.parse(json) as { '@graph'?: Record<string, unknown>[] })[
    '@graph'
  ];
  const faq = graph?.find((node) => node['@type'] === 'FAQPage') as
    | {
        mainEntity: {
          name: string;
          acceptedAnswer: { text: string };
        }[];
      }
    | undefined;
  if (!faq) {
    fail('faq: no FAQPage in the JSON-LD');
    return;
  }
  const shown = [
    ...home.matchAll(
      /<details class="faq-item">\s*<summary>([\s\S]*?)<\/summary>\s*<p>([\s\S]*?)<\/p>/g,
    ),
  ].map((match) => ({ q: normalise(match[1]!), a: normalise(match[2]!) }));
  const listed = faq.mainEntity.map((item) => ({
    q: item.name,
    a: item.acceptedAnswer.text,
  }));
  if (shown.length !== listed.length)
    fail(
      `faq: the page shows ${shown.length} questions, the FAQPage lists ${listed.length}`,
    );
  for (const [index, item] of listed.entries()) {
    const visible = shown[index];
    if (visible?.q !== item.q)
      fail(
        `faq: question ${index + 1} differs: "${visible?.q}" vs "${item.q}"`,
      );
    else if (visible.a !== item.a)
      fail(`faq: the answer to "${item.q}" differs from the page`);
  }
}

// ---------------------------------------------------------------------------
// links

function ids(html: string): Set<string> {
  return new Set(
    [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]!),
  );
}

function target(path: string): string | undefined {
  if (path === '/') return 'index.html';
  const name = path.slice(1);
  for (const candidate of [name, `${name}.html`])
    try {
      readFileSync(join(SITE, candidate));
      return candidate;
    } catch {
      // try the next form
    }
  return undefined;
}

function checkLinks(): void {
  for (const name of PAGES) {
    const html = page(name);
    for (const match of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
      const value = match[1]!;
      if (/^(?:https?:|mailto:)/.test(value)) continue;
      const [pathAndQuery = '', fragment] = value.split('#');
      const path = pathAndQuery.split('?')[0] ?? '';
      const file = path === '' ? name : target(path);
      if (!file) {
        fail(`links: ${name} links to missing ${value}`);
        continue;
      }
      if (fragment && file.endsWith('.html') && !ids(page(file)).has(fragment))
        fail(`links: ${name} links to missing fragment ${value}`);
    }
  }
}

// ---------------------------------------------------------------------------
// budgets and scanner loading

function staticImports(file: string, seen = new Set<string>()): Set<string> {
  if (seen.has(file)) return seen;
  seen.add(file);
  const code = readFileSync(join(SITE, file), 'utf8');
  for (const match of code.matchAll(
    /(?:^|[;}\s])import\s*(?:[^"'()]*?from\s*)?["']\.\/([\w.-]+\.js)["']/g,
  ))
    staticImports(`assets/scanner/${match[1]}`, seen);
  return seen;
}

function loadedAtStart(html: string): string[] {
  const files: string[] = [];
  for (const match of html.matchAll(/<link rel="stylesheet" href="\/([^"]+)"/g))
    files.push(match[1]!);
  for (const match of html.matchAll(
    /<script(?![^>]*application\/ld\+json)[^>]*\ssrc="\/([^"]+)"/g,
  )) {
    const file = match[1]!;
    if (file.startsWith('assets/scanner/'))
      for (const chunk of staticImports(file)) files.push(chunk);
    else files.push(file);
  }
  return files;
}

function checkBudgets(): void {
  for (const name of PAGES) {
    const html = page(name);
    const files = loadedAtStart(html);
    const total =
      gzip(html) +
      files.reduce(
        (sum, file) => sum + gzip(readFileSync(join(SITE, file))),
        0,
      );
    console.log(
      `  ${name.padEnd(13)} ${(total / KB).toFixed(1)} KB gzip at load (${files.length} files)`,
    );
    if (total > 60 * KB)
      fail(
        `budgets: ${name} loads ${(total / KB).toFixed(1)} KB gzip (budget 60 KB)`,
      );
    if (name !== 'scan.html' && html.includes('/assets/scanner/'))
      fail(`scanner: ${name} references scanner chunks`);
  }
  const scan = page('scan.html');
  const entry = /src="\/(assets\/scanner\/scan-page-[^"]+)"/.exec(scan)?.[1];
  if (!entry) {
    fail('scanner: scan.html does not load the scan page entry');
    return;
  }
  const initial = staticImports(entry);
  const pageCode = readFileSync(join(SITE, entry), 'utf8');
  const workerFile = /\/assets\/scanner\/(parse-worker-[\w]+\.js)/.exec(
    pageCode,
  )?.[1];
  const coreFile = /import\(["']\.\/(core-[\w]+\.js)["']\)/.exec(pageCode)?.[1];
  if (!workerFile || !coreFile) {
    fail(
      'scanner: the worker or core chunk is not referenced by the page entry',
    );
    return;
  }
  const size = (file: string) =>
    gzip(readFileSync(join(SITE, 'assets/scanner', file)));
  const worker = size(workerFile);
  const core = [...staticImports(`assets/scanner/${coreFile}`)]
    .filter((file) => !initial.has(file))
    .reduce((sum, file) => sum + gzip(readFileSync(join(SITE, file))), 0);
  const pageJs = [...initial].reduce(
    (sum, file) => sum + gzip(readFileSync(join(SITE, file))),
    0,
  );
  const total = worker + core + pageJs;
  console.log(
    `  scanner       page ${(pageJs / KB).toFixed(1)} KB, worker ${(worker / KB).toFixed(1)} KB, core ${(core / KB).toFixed(1)} KB, total ${(total / KB).toFixed(1)} KB gzip`,
  );
  if (pageJs > 15 * KB)
    fail(
      `budgets: scan page script ${(pageJs / KB).toFixed(1)} KB (budget 15 KB)`,
    );
  if (worker > 6 * KB)
    fail(`budgets: parse worker ${(worker / KB).toFixed(1)} KB (budget 6 KB)`);
  if (core > 12 * KB)
    fail(`budgets: scanner core ${(core / KB).toFixed(1)} KB (budget 12 KB)`);
  if (total > 30 * KB)
    fail(`budgets: scanner total ${(total / KB).toFixed(1)} KB (budget 30 KB)`);
}

// ---------------------------------------------------------------------------
// security.txt

function checkSecurityTxt(now = new Date()): void {
  const text = readFileSync(join(SITE, '.well-known/security.txt'), 'utf8');
  const field = (name: string) =>
    new RegExp(`^${name}: (.+)$`, 'm').exec(text)?.[1];
  if (!/^mailto:\S+@\S+$/.test(field('Contact') ?? ''))
    fail('security: security.txt has no Contact: mailto: line');
  const expires = Date.parse(field('Expires') ?? '');
  const day = 24 * 60 * 60 * 1000;
  if (!Number.isFinite(expires))
    fail('security: security.txt has no valid Expires');
  else if (expires - now.getTime() < 30 * day)
    fail(
      'security: security.txt expires within 30 days; set a new Expires date',
    );
  else if (expires - now.getTime() > 366 * day)
    fail('security: security.txt Expires is more than a year away (RFC 9116)');
  if (
    field('Canonical') !==
    'https://getvulnpilot.vercel.app/.well-known/security.txt'
  )
    fail('security: security.txt Canonical is wrong');
  if (field('Preferred-Languages') !== 'en')
    fail('security: Preferred-Languages is not en');
}

// ---------------------------------------------------------------------------
// html-validate

async function checkHtml(): Promise<void> {
  const validator = new HtmlValidate({
    extends: ['html-validate:recommended', 'html-validate:prettier'],
    rules: {
      // Long attribute values (CSP-free JSON-LD, descriptions) are fine.
      'long-title': 'off',
      // Scrollable tables use role="region" with a name and tabindex so
      // keyboard users can scroll them; a <section> per table would add noise.
      'prefer-native-element': ['error', { exclude: ['region'] }],
    },
  });
  for (const name of PAGES) {
    const report = await validator.validateFile(join(SITE, name));
    for (const result of report.results)
      for (const message of result.messages)
        fail(
          `html: ${name}:${message.line}:${message.column} ${message.ruleId} ${message.message}`,
        );
  }
}

// ---------------------------------------------------------------------------
// robots.txt and sitemap.xml

function checkCrawling(): void {
  const robots = readFileSync(join(SITE, 'robots.txt'), 'utf8');
  for (const line of [
    'User-agent: *',
    'Allow: /',
    'Sitemap: https://getvulnpilot.vercel.app/sitemap.xml',
  ])
    if (!robots.split(String.fromCharCode(10)).includes(line))
      fail(`crawling: robots.txt lacks "${line}"`);
  const sitemap = readFileSync(join(SITE, 'sitemap.xml'), 'utf8');
  const listed = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(
    (match) => match[1]!,
  );
  const canonical = PAGES.filter((name) => name !== '404.html').map((name) => {
    const href = /<link rel="canonical" href="([^"]+)"/.exec(page(name))?.[1];
    if (!href) fail(`crawling: ${name} has no canonical URL`);
    return href ?? '';
  });
  if (listed.sort().join() !== canonical.sort().join())
    fail(
      `crawling: sitemap.xml lists ${listed.join(', ')}, canonical URLs are ${canonical.join(', ')}`,
    );
  if (/<link rel="canonical"/.test(page('404.html')))
    fail('crawling: 404.html has a canonical URL');
}

const checks: [string, () => void | Promise<void>][] = [
  ['proof', checkProof],
  ['faq', checkFaq],
  ['links', checkLinks],
  ['budgets', checkBudgets],
  ['security', () => checkSecurityTxt()],
  ['crawling', checkCrawling],
  ['html', checkHtml],
];
for (const [name, check] of checks) {
  console.log(`${name}`);
  try {
    await check();
  } catch (error) {
    fail(`${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}
if (failures.length > 0) {
  console.error(
    `\n${failures.length} problem(s):\n${failures.map((line) => `- ${line}`).join('\n')}`,
  );
  process.exitCode = 1;
} else console.log('\nAll site checks passed.');
