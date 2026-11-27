import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Page, Route } from '@playwright/test';
import { Ajv } from 'ajv';
import { ROOT } from '../build/paths.js';
import { expect, open, test } from './support.js';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const fixture = (path: string) => join(ROOT, 'test/fixtures', path);
const schema = JSON.parse(
  readFileSync(join(ROOT, 'schema/report-v1.schema.json'), 'utf8'),
);
const { version } = JSON.parse(
  readFileSync(join(ROOT, 'package.json'), 'utf8'),
) as { version: string };

async function loadSample(page: Page) {
  await open(page, '/scan');
  await page.getByRole('button', { name: 'Try the sample SBOM' }).click();
  await expect(page.locator('#found-title')).toBeFocused();
}

async function scan(page: Page) {
  await page.locator('#scan-button').click();
  await expect(page.locator('#report-title')).toBeFocused({ timeout: 15_000 });
}

const reportText = (page: Page) => page.locator('#report-text');

function hold(network: import('./support.js').Network, prefix: string) {
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  network.override(prefix, async (route: Route, request) => {
    await released;
    await network.answer(route, request);
  });
  return release;
}

test('empty state: one sentence, the drop target and the sample button', async ({
  page,
}) => {
  await open(page, '/scan');
  await expect(page.locator('.dropzone-text')).toHaveText(
    'Drop a lockfile or CycloneDX JSON SBOM here, choose one, or paste it.',
  );
  await expect(page.getByRole('button', { name: 'Choose file' })).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Try the sample SBOM' }),
  ).toBeVisible();
  for (const id of ['found', 'sent', 'progress', 'report'])
    await expect(page.locator(`#${id}`)).toBeHidden();
  // The CRA screen works with no file and no network.
  await expect(page.locator('.cra-verdict-value')).toHaveText('UNCLEAR');
});

test('parsed and consent: what was found and what will be sent; nothing leaves yet @cross', async ({
  page,
  network,
}) => {
  await loadSample(page);
  await expect(page.locator('#found-body')).toContainText('cyclonedx');
  await expect(page.locator('#found-body')).toContainText(
    'Maven 1 · npm 2 · PyPI 2',
  );
  await expect(page.locator('#sent-list li').first()).toHaveText(
    'OSV.dev (api.osv.dev): the 5 package names and versions, in 1 request of up to 1,000.',
  );
  await expect(page.locator('#scan-label')).toHaveText('Scan 5 packages');
  await page.getByRole('button', { name: 'Show the OSV request' }).click();
  await expect(page.locator('#request-meta')).toContainText(
    'Request 1 of 1 · 5 packages',
  );
  expect(network.external()).toEqual([]);
  const shown = await page.locator('#request-body').textContent();
  await scan(page);
  const sent = network.requests.find((request) => request.url === OSV_BATCH);
  expect(sent?.body).toBe(shown);
  // Nothing identifying goes with them: no cookie, no referrer.
  for (const request of network.external()) {
    expect(request.headers['cookie']).toBeUndefined();
    expect(request.headers['referer']).toBeUndefined();
  }
  const hosts = new Set(
    network.external().map((request) => new URL(request.url).host),
  );
  expect([...hosts].sort()).toEqual(['api.first.org', 'api.osv.dev']);
});

test('scanning shows real counts while requests are in flight', async ({
  page,
  network,
}) => {
  await loadSample(page);
  const release = hold(network, OSV_BATCH);
  await page.locator('#scan-button').click();
  await expect(page.locator('#progress-osv')).toHaveText('0 of 5 packages');
  await expect(page.locator('#progress-advisories')).toHaveText(
    'waiting for OSV',
  );
  await expect(page.locator('#progress-kev')).toHaveText(
    'catalog 2099.01.01, released 1 January 2099',
  );
  await expect(page.locator('#stop')).toBeFocused();
  release();
  await expect(page.locator('#progress-osv')).toHaveText('5 of 5 packages');
  await expect(page.locator('#progress-advisories')).toHaveText('5 of 5');
  await expect(page.locator('#progress-epss')).toHaveText('4 of 4 CVEs');
  await expect(page.locator('#report-title')).toBeFocused();
  await expect(page.locator('#scan-live')).toHaveText(
    'Scan finished: 4 issues, 1 actively exploited.',
  );
});

test('result: the CLI text report, JSON download, table and facts @cross', async ({
  page,
}) => {
  await loadSample(page);
  await scan(page);
  await expect(reportText(page)).toContainText(`Vulnpilot ${version}`);
  await expect(reportText(page)).toContainText('Top 4 of 4 issue(s)');
  await expect(
    reportText(page).locator('.t-r', { hasText: 'KNOWN EXPLOITED' }),
  ).toHaveCount(1);
  await expect(reportText(page)).not.toContainText('Get continuous monitoring');
  await expect(page.locator('.report-waitlist')).toContainText(
    'planned but not available yet',
  );
  await expect(page.locator('#report-facts')).toContainText(
    'CLI exit code for this result: 1 (issues found).',
  );
  await expect(page.locator('#terminal-command')).toHaveText(
    'npx vulnpilot --sbom test/fixtures/sbom/cyclonedx.json --non-interactive',
  );
  await expect(page.locator('#toggle-all')).toBeHidden();

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download JSON' }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(
    /^vulnpilot-report-\d{4}-\d{2}-\d{2}\.json$/,
  );
  const report = JSON.parse(readFileSync((await download.path())!, 'utf8'));
  const validate = new Ajv({ allErrors: true, validateFormats: false }).compile(
    schema,
  );
  expect(validate(report), JSON.stringify(validate.errors)).toBe(true);
  expect(report.mock).toBe(false);

  await page.getByRole('button', { name: 'Show as table' }).click();
  const rows = page.locator('#report-table tbody tr');
  await expect(rows).toHaveCount(4);
  await expect(rows.first()).toContainText('Known exploited');
});

test('partial failure: OSV down is never shown as clean @cross', async ({
  page,
  network,
}) => {
  network.override(OSV_BATCH, (route) =>
    route.fulfill({ status: 503, body: '' }),
  );
  await loadSample(page);
  await scan(page);
  await expect(page.locator('#report-banners')).toContainText(
    'Incomplete data. OSV.dev could not be reached, so no package was checked. This is not a clean result: the CLI would exit 2.',
  );
  await expect(reportText(page)).toContainText(
    'OSV.dev unavailable: HTTP 503 from api.osv.dev',
  );
  await expect(reportText(page)).toContainText(
    'Vulnerability data could not be retrieved; results are incomplete.',
  );
  await expect(reportText(page)).not.toContainText(
    'No known vulnerabilities found.',
  );
  await expect(page.locator('#progress-osv')).toHaveText(
    'failed for 5 of 5 packages (HTTP 503 from api.osv.dev)',
  );
  await expect(page.locator('#report-facts')).toContainText(
    'CLI exit code for this result: 2',
  );
});

test('partial failure: missing advisories, KEV and EPSS are named, issues stay', async ({
  page,
  network,
}) => {
  network.override(
    'https://api.osv.dev/v1/vulns/GHSA-mock-lod2-0002',
    (route) => route.fulfill({ status: 503, body: '' }),
  );
  network.override('http://127.0.0.1:4173/api/kev', (route) =>
    route.fulfill({ status: 502, body: '{}', contentType: 'application/json' }),
  );
  network.override('https://api.first.org/', (route) =>
    route.fulfill({ status: 503, body: '' }),
  );
  await loadSample(page);
  await scan(page);
  const banners = page.locator('#report-banners');
  await expect(banners).toContainText('did not return details for 1 advisory');
  await expect(banners).toContainText('No KEV data.');
  // Three CVEs: the advisory without details has none.
  await expect(banners).toContainText('FIRST EPSS did not score 3 CVEs.');
  await expect(reportText(page)).toContainText(
    'GHSA-mock-lod2-0002 (details unavailable)',
  );
  await expect(reportText(page)).toContainText('Top 4 of 4 issue(s)');
});

test('stop discards the run and keeps the file', async ({ page, network }) => {
  await loadSample(page);
  const release = hold(network, OSV_BATCH);
  await page.locator('#scan-button').click();
  await page.locator('#stop').click();
  await expect(page.locator('#progress-note')).toHaveText(
    'Stopped. Nothing from this run was kept. Press Scan to start again.',
  );
  await expect(page.locator('#scan-button')).toBeFocused();
  release();
  await page.waitForTimeout(500);
  await expect(page.locator('#report')).toBeHidden();
  await scan(page);
});

test.describe('input errors', () => {
  const choose = (page: Page, name: string, content: string | Buffer) =>
    page.locator('#file-input').setInputFiles({
      name,
      mimeType: 'application/octet-stream',
      buffer: Buffer.isBuffer(content) ? content : Buffer.from(content),
    });
  const error = (page: Page) => page.locator('#input-error');

  test('unsupported file @cross', async ({ page }) => {
    await open(page, '/scan');
    await choose(page, 'notes.txt', 'hello');
    await expect(error(page)).toHaveText(
      'Unsupported file notes.txt. Expected one of package-lock.json, pnpm-lock.yaml, yarn.lock, or a CycloneDX JSON SBOM.',
    );
    await expect(error(page)).toBeFocused();
  });

  test('unparseable file, in the CLI’s words', async ({ page }) => {
    await open(page, '/scan');
    await choose(page, 'package-lock.json', '{"lockfileVersion": 7}');
    await expect(error(page)).toHaveText(
      'Could not parse package-lock.json: Expected package-lock.json with lockfileVersion 1, 2 or 3.',
    );
  });

  test('oversize file', async ({ page, network }) => {
    await open(page, '/scan');
    await choose(page, 'package-lock.json', Buffer.alloc(33 * 1024 * 1024, 32));
    await expect(error(page)).toHaveText(
      'package-lock.json is 33.0 MB. The browser scanner reads files up to 32 MB. Scan it with the CLI: npx vulnpilot --path package-lock.json',
    );
    expect(
      network.requests.some((request) => request.url.includes('parse-worker')),
    ).toBe(false);
  });

  test('empty file and unrecognised paste', async ({ page }) => {
    await open(page, '/scan');
    await choose(page, 'yarn.lock', '');
    await expect(error(page)).toHaveText('yarn.lock is empty.');
    await page.getByLabel('Or paste its contents').fill('just some text');
    await page.getByRole('button', { name: 'Read pasted text' }).click();
    await expect(error(page)).toHaveText(
      'The pasted text is not a supported lockfile or SBOM. Expected the contents of package-lock.json, pnpm-lock.yaml, yarn.lock, or a CycloneDX JSON SBOM.',
    );
  });

  test('a parse that takes longer than 20 seconds is stopped', async ({
    page,
    network,
  }) => {
    test.setTimeout(60_000);
    network.override(
      'http://127.0.0.1:4173/assets/scanner/parse-worker-',
      (route) =>
        route.fulfill({
          contentType: 'text/javascript',
          body: 'self.onmessage = () => {};',
        }),
    );
    await open(page, '/scan');
    await choose(
      page,
      'package-lock.json',
      readFileSync(fixture('projects/npm/package-lock.json')),
    );
    await expect(error(page)).toHaveText(
      'Reading package-lock.json took longer than 20 seconds and was stopped. Scan it with the CLI: npx vulnpilot --path package-lock.json',
      { timeout: 30_000 },
    );
  });
});

test('pasting into the drop zone reads the text without a request', async ({
  page,
  network,
}) => {
  await open(page, '/scan');
  const content = readFileSync(fixture('projects/pnpm/pnpm-lock.yaml'), 'utf8');
  await page.locator('#paste-input').focus();
  await page.evaluate((text) => {
    const data = new DataTransfer();
    data.setData('text/plain', text);
    document
      .getElementById('paste-input')!
      .dispatchEvent(
        new ClipboardEvent('paste', { clipboardData: data, bubbles: true }),
      );
  }, content);
  await expect(page.locator('#found-body')).toContainText('pnpm-lock');
  await expect(page.locator('#file-summary')).toContainText('Pasted text');
  await expect(page.locator('#paste-input')).toHaveValue('');
  expect(network.external()).toEqual([]);
});

test('third-party strings are text: no markup from an advisory reaches the DOM', async ({
  page,
  network,
}) => {
  const hostile = '<img src=x onerror="window.__xss=1"><b>bold</b>';
  network.override(
    'https://api.osv.dev/v1/vulns/GHSA-mock-log1-0004',
    async (route) => {
      const record = await (await network.mock(route.request().url())).json();
      await route.fulfill({
        json: { ...record, summary: hostile },
        headers: { 'access-control-allow-origin': 'http://127.0.0.1:4173' },
      });
    },
  );
  await loadSample(page);
  await scan(page);
  await expect(reportText(page)).toContainText(hostile);
  await expect(page.locator('#report img, #report b')).toHaveCount(0);
  expect(
    await page.evaluate(() => (window as { __xss?: number }).__xss),
  ).toBeUndefined();
});

test('Trusted Types are enforced on /scan', async ({ page, violations }) => {
  await open(page, '/scan');
  const result = await page.evaluate(() => {
    try {
      document.body.insertAdjacentHTML('beforeend', '<b>x</b>');
      return 'assigned';
    } catch (error) {
      return (error as Error).name;
    }
  });
  expect(result).toBe('TypeError');
  // That attempt was meant to be refused; nothing else may be.
  violations.length = 0;
});

test('nothing is stored in the browser', async ({ page, context }) => {
  await loadSample(page);
  await scan(page);
  const stored = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    cookie: document.cookie,
    caches: (await caches.keys()).length,
    databases: (await indexedDB.databases()).length,
  }));
  expect(stored).toEqual({
    local: 0,
    session: 0,
    cookie: '',
    caches: 0,
    databases: 0,
  });
  expect(await context.cookies()).toEqual([]);
  expect(page.url()).toBe('http://127.0.0.1:4173/scan');
});

test('the scanner clears files left by the old home-page handoff', async ({
  page,
  network,
}) => {
  await open(page, '/privacy');
  await page.evaluate(
    () =>
      new Promise<void>((resolve, reject) => {
        const request = indexedDB.open('vulnpilot-handoff', 1);
        request.onupgradeneeded = () =>
          request.result.createObjectStore('files');
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const db = request.result;
          const transaction = db.transaction('files', 'readwrite');
          transaction
            .objectStore('files')
            .put(
              { file: new File(['{}'], 'package-lock.json'), at: Date.now() },
              'dropped',
            );
          transaction.oncomplete = () => {
            db.close();
            resolve();
          };
          transaction.onabort = () => reject(transaction.error);
        };
      }),
  );
  await open(page, '/scan?handoff');
  await expect(page).toHaveURL(/\/scan$/);
  await expect(page.locator('#found-title')).toBeHidden();
  await expect
    .poll(() => page.evaluate(() => indexedDB.databases()))
    .toEqual([]);
  expect(network.external()).toEqual([]);
});

test('the CRA screen uses the CLI rules and feeds the report @cross', async ({
  page,
}) => {
  await loadSample(page);
  await scan(page);
  const questions = page.locator('#cra-form fieldset');
  await questions.nth(0).getByLabel('Yes').check();
  await questions.nth(1).getByLabel('Yes').check();
  await questions
    .nth(2)
    .getByLabel('Firmware or a connected hardware device')
    .check();
  await expect(page.locator('.cra-verdict-value')).toHaveText('LIKELY APPLIES');
  await expect(page.locator('.cra-verdict code')).toHaveText(
    'commercial-eu-product',
  );
  await expect(page.locator('[data-cra-flags]')).toHaveText(
    '--eu-distribution yes --commercial yes --product-type firmware',
  );
  await expect(reportText(page)).toContainText(
    'EU Cyber Resilience Act: LIKELY APPLIES',
  );
  await expect(reportText(page)).toContainText(
    '>>> CISA KEV match: check whether your product is affected.',
  );
  await expect(reportText(page)).toContainText(
    'must send an early warning without undue delay and within 24 hours of becoming aware of an actively exploited vulnerability in their product.',
  );
  await expect(page.locator('#terminal-command')).toHaveText(
    'npx vulnpilot --sbom test/fixtures/sbom/cyclonedx.json --non-interactive --eu-distribution yes --commercial yes --product-type firmware',
  );
});

test('keyboard only: sample, consent, scan, result, with visible focus', async ({
  page,
}) => {
  await open(page, '/scan');
  const outline = async () =>
    page.evaluate(() => {
      const style = getComputedStyle(document.activeElement!);
      return style.outlineStyle !== 'none' && style.outlineWidth !== '0px';
    });
  await page.keyboard.press('Tab'); // skip link
  await expect(page.locator('.skip-link')).toBeFocused();
  await page.locator('#sample').focus();
  expect(await outline()).toBe(true);
  await page.keyboard.press('Enter');
  await expect(page.locator('#found-title')).toBeFocused();
  for (let index = 0; index < 10; index += 1) {
    await page.keyboard.press('Tab');
    if (
      await page
        .locator('#scan-button')
        .evaluate((el) => el === document.activeElement)
    )
      break;
  }
  await expect(page.locator('#scan-button')).toBeFocused();
  expect(await outline()).toBe(true);
  await page.keyboard.press('Enter');
  await expect(page.locator('#report-title')).toBeFocused({ timeout: 15_000 });
  await page.keyboard.press('Tab');
  await expect(page.locator('#report-text').locator('..')).toBeFocused();
  expect(await outline()).toBe(true);
});
