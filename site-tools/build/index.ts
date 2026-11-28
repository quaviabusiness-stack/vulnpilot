// The site's one generation step. Vercel builds nothing: everything this
// writes is committed, and CI runs it again and fails if anything differs.
//
//   pnpm --filter site-tools build
//
// Writes site/assets/ (hashed CSS, JS, fonts and the scanner bundle),
// site/api/kev.mjs, site/samples/, robots.txt, sitemap.xml, the Canonical
// field of security.txt and the generated parts of site/*.html, including
// every absolute URL on the site's own origin (SITE_URL in paths.ts).
import {
  copyFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  craInitialResult,
  craQuestionsForm,
  craQuestionsList,
  fieldReference,
} from './docs.js';
import {
  formatHtml,
  type ProofValue,
  replaceRegions,
  replaceValues,
  rewriteAssets,
} from './html.js';
import {
  ASSETS,
  contentHash,
  generatedHeader,
  PAGES,
  ROOT,
  SITE,
  SITE_SRC,
} from './paths.js';
import {
  captureDate,
  helpRegion,
  homeRegions,
  loadProof,
  proofValues,
} from './proof.js';
import { buildKevFunction, buildScanner } from './scanner.js';
import { currentOrigin, rewriteOrigin, writeCrawlFiles } from './site-url.js';

const version = (
  JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
    version: string;
  }
).version;
const proof = loadProof();
const manifest = new Map<string, string>();

rmSync(ASSETS, { recursive: true, force: true });
mkdirSync(join(ASSETS, 'fonts'), { recursive: true });
mkdirSync(join(ASSETS, 'scanner'), { recursive: true });

function emit(logical: string, content: string | Buffer): void {
  const dot = logical.lastIndexOf('.');
  const hashed = `${logical.slice(0, dot)}-${contentHash(content)}${logical.slice(dot)}`;
  writeFileSync(join(SITE, hashed), content);
  manifest.set(logical, hashed);
}

// Fonts (hashed) and their licences (as they are).
for (const name of readdirSync(join(SITE_SRC, 'fonts'))) {
  const source = join(SITE_SRC, 'fonts', name);
  if (name.endsWith('.woff2'))
    emit(`/assets/fonts/${name}`, readFileSync(source));
  else copyFileSync(source, join(ASSETS, 'fonts', name));
}

// The stylesheet, pointing at the hashed fonts.
let css = readFileSync(join(SITE_SRC, 'styles.css'), 'utf8');
css = css.replace(/\/assets\/fonts\/[a-z0-9-]+\.woff2/g, (logical) => {
  const hashed = manifest.get(logical);
  if (!hashed) throw new Error(`styles.css: unknown font ${logical}`);
  return hashed;
});
emit(
  '/assets/home.css',
  `/* ${generatedHeader('site-src/home.css')} */
${readFileSync(join(SITE_SRC, 'home.css'), 'utf8')}`,
);
emit(
  '/assets/pages.css',
  `/* ${generatedHeader('site-src/pages.css')} */
${readFileSync(join(SITE_SRC, 'pages.css'), 'utf8')}`,
);
emit(
  '/assets/styles.css',
  `/* ${generatedHeader('site-src/styles.css')} */\n${css}`,
);

// The home page script, unchanged apart from the header.
emit(
  '/assets/app.js',
  `// ${generatedHeader('site-src/app.js')}\n${readFileSync(join(SITE_SRC, 'app.js'), 'utf8')}`,
);

// The scanner and the KEV function.
const scanner = await buildScanner(join(ASSETS, 'scanner'), version);
manifest.set('/assets/scanner/scan-page.js', scanner.page);
mkdirSync(join(SITE, 'api'), { recursive: true });
await buildKevFunction(join(SITE, 'api'));

// The sample SBOM, served same-origin for "Try the sample SBOM".
mkdirSync(join(SITE, 'samples'), { recursive: true });
copyFileSync(
  join(ROOT, 'test/fixtures/sbom/cyclonedx.json'),
  join(SITE, 'samples/cyclonedx.json'),
);

// Generated parts of the pages.
const asOf = new Date(`${captureDate(proof)}T00:00:00Z`);
const regions: Record<string, string> = {
  ...homeRegions(proof),
  'docs-help': helpRegion(proof),
  'docs-fields': fieldReference(),
  'docs-cra-questions': craQuestionsList(),
  'cra-questions': craQuestionsForm(),
  'cra-result': craInitialResult(asOf),
};
const values: Record<string, ProofValue> = Object.fromEntries(
  Object.entries(proofValues(proof)).map(([key, html]) => [key, { html }]),
);
values['capture-date'] = {
  html: values['capture-date']!.html,
  datetime: captureDate(proof),
};
const partial = (name: string) =>
  readFileSync(join(SITE_SRC, 'partials', name), 'utf8')
    .replace(/^<!--[\s\S]*?-->\n/, '')
    .trimEnd();
const CURRENT: Partial<Record<(typeof PAGES)[number], string>> = {
  'scan.html': '/scan',
  'docs.html': '/docs',
};
/** The shared header: marks the current page and, away from the home page, links sections there. */
function header(page: (typeof PAGES)[number]): string {
  let html = partial('header.html');
  if (page !== 'index.html') html = html.replaceAll('href="#', 'href="/#');
  const current = CURRENT[page];
  if (current)
    html = html.replaceAll(
      `<li><a href="${current}">`,
      `<li><a href="${current}" aria-current="page">`,
    );
  // On /scan the scan button would point at the page itself.
  if (page === 'scan.html') {
    let swapped = 0;
    html = html.replace(
      /<a class="btn btn-primary( btn-small)?" href="\/scan" data-header-cta\s*>Scan a lockfile<\/a\s*>/g,
      (_match, small: string | undefined) => {
        swapped += 1;
        return `<a class="btn btn-outline${small ?? ''}" href="/#waitlist" data-header-cta>Design partners</a>`;
      },
    );
    if (swapped !== 2)
      throw new Error(
        'header.html: expected two scan buttons to swap on /scan',
      );
  }
  return html;
}
const footer = partial('footer.html');

const previousOrigin = currentOrigin();
const used = new Set<string>(['header', 'footer']);
let changed = writeCrawlFiles(previousOrigin);
for (const page of PAGES) {
  const file = join(SITE, page);
  const before = readFileSync(file, 'utf8');
  let html = rewriteOrigin(before, previousOrigin);
  html = rewriteAssets(html, manifest, page);
  html = replaceRegions(
    html,
    { ...regions, header: header(page), footer },
    page,
    used,
  );
  html = replaceValues(html, values, page);
  html = await formatHtml(html, file);
  if (html !== before) {
    writeFileSync(file, html);
    changed += 1;
  }
}
const unused = Object.keys(regions).filter((name) => !used.has(name));
if (unused.length > 0)
  throw new Error(`Regions not found in any page: ${unused.join(', ')}`);

console.log(
  `Built ${manifest.size} hashed assets and ${scanner.files.length} scanner chunks; ${changed} file(s) updated. Proof: relvet ${proof.meta.cliVersion}, captured ${captureDate(proof)}.`,
);
