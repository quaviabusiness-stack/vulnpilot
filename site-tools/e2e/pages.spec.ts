import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SITE } from '../build/paths.js';
import { expect, open, SUPABASE, test } from './support.js';

const PAGES = [
  { path: '/', canonical: 'https://getvulnpilot.vercel.app/' },
  { path: '/scan', canonical: 'https://getvulnpilot.vercel.app/scan' },
  { path: '/docs', canonical: 'https://getvulnpilot.vercel.app/docs' },
  { path: '/privacy', canonical: 'https://getvulnpilot.vercel.app/privacy' },
];

for (const { path, canonical } of PAGES)
  test(`${path} loads with no outbound request and a canonical URL @cross`, async ({
    page,
    network,
  }) => {
    await open(page, path);
    await page.waitForLoadState('networkidle');
    expect(network.external()).toEqual([]);
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
      'href',
      canonical,
    );
    await expect(page.locator('h1')).toHaveCount(1);
    if (path !== '/scan')
      expect(
        network.requests.some((request) =>
          request.url.includes('/assets/scanner/'),
        ),
      ).toBe(false);
  });

test('unknown paths get the 404 page, not indexed', async ({ page }) => {
  const response = await page.goto('/no-such-page');
  expect(response?.status()).toBe(404);
  await expect(page.locator('h1')).toHaveText('Nothing at this address');
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute(
    'content',
    'noindex',
  );
});

test('the home page states facts only in its JSON-LD', async ({ page }) => {
  await open(page, '/');
  const data = JSON.parse(
    (await page.locator('script[type="application/ld+json"]').textContent()) ??
      '',
  ) as Record<string, unknown>;
  expect(data).toEqual({
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'Vulnpilot',
    description: expect.stringContaining('Free, open-source CLI.') as unknown,
    applicationCategory: 'DeveloperApplication',
    operatingSystem: 'Node.js 26 or later',
    isAccessibleForFree: true,
    license:
      'https://github.com/quaviabusiness-stack/vulnpilot/blob/main/LICENSE',
    url: 'https://getvulnpilot.vercel.app/',
    sameAs: [
      'https://github.com/quaviabusiness-stack/vulnpilot',
      'https://www.npmjs.com/package/vulnpilot',
    ],
  });
});

test('every page CSP in vercel.json upgrades insecure requests', () => {
  const config = JSON.parse(
    readFileSync(join(SITE, 'vercel.json'), 'utf8'),
  ) as {
    headers: { source: string; headers: { key: string; value: string }[] }[];
  };
  const pagePolicies = config.headers
    .filter(
      (rule) =>
        !rule.source.startsWith('/assets') && !rule.source.startsWith('/api'),
    )
    .flatMap((rule) => rule.headers)
    .filter((header) => header.key === 'Content-Security-Policy');
  expect(pagePolicies).toHaveLength(3);
  for (const policy of pagePolicies)
    expect(policy.value).toMatch(/; upgrade-insecure-requests$/);
});

test('the headers are the per-route ones from vercel.json', async ({
  request,
}) => {
  const csp = async (path: string) =>
    (await request.get(path)).headers()['content-security-policy'] ?? '';
  expect(await csp('/')).toContain(
    'connect-src https://xvdwfhadpmsgfpschnbp.supabase.co;',
  );
  expect(await csp('/docs')).toContain("connect-src 'none'");
  expect(await csp('/privacy')).toContain("connect-src 'none'");
  expect(await csp('/no-such-page')).toContain("connect-src 'none'");
  const scan = await csp('/scan');
  expect(scan).toContain(
    "connect-src 'self' https://api.osv.dev https://api.first.org;",
  );
  expect(scan).toContain(
    "require-trusted-types-for 'script'; trusted-types vulnpilot-worker",
  );
  for (const path of ['/', '/scan', '/docs', '/privacy']) {
    const headers = (await request.get(path)).headers();
    expect(headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(headers['cache-control']).toBe('public, max-age=0, must-revalidate');
  }
});

test.describe('waitlist form (unchanged behaviour)', () => {
  async function submit(page: import('@playwright/test').Page, email: string) {
    await page.getByLabel('Work email').fill(email);
    // By keyboard: the sticky header can cover a scrolled-to checkbox for a pointer.
    const consent = page.getByLabel(/I agree to receive emails/);
    await consent.focus();
    if (!(await consent.isChecked())) await page.keyboard.press('Space');
    await expect(consent).toBeChecked();
    await page
      .getByRole('button', { name: 'Join the waitlist' })
      .last()
      .click();
  }
  const posts = (network: import('./support.js').Network) =>
    network.requests.filter((request) => request.url.startsWith(SUPABASE));

  test('posts the four fields to Supabase only on submit @cross', async ({
    page,
    network,
  }) => {
    await open(page, '/');
    await page.getByLabel(/Company size/).selectOption('11-50');
    expect(posts(network)).toEqual([]);
    await submit(page, ' someone@example.com ');
    await expect(
      page.getByRole('heading', { name: 'You’re on the list' }),
    ).toBeVisible();
    const [post] = posts(network).filter(
      (request) => request.method === 'POST',
    );
    expect(post?.url).toBe(`${SUPABASE}/rest/v1/vulnpilot_waitlist`);
    expect(JSON.parse(post!.body ?? '')).toEqual({
      email: 'someone@example.com',
      consent: true,
      source: 'direct',
      company_size: '11-50',
    });
    expect(post!.headers['prefer']).toBe('return=minimal');
    expect(post!.headers['content-type']).toBe('application/json');
    expect(post!.headers['apikey']).toBeTruthy();
    expect(post!.headers['authorization']).toMatch(/^Bearer /);
  });

  test('maps utm_source to source', async ({ page, network }) => {
    await open(page, '/?utm_source=CLI');
    await submit(page, 'a@example.com');
    await expect(
      page.getByRole('heading', { name: 'You’re on the list' }),
    ).toBeVisible();
    await open(page, '/?utm_source=not%20allowed!');
    await submit(page, 'b@example.com');
    await expect(
      page.getByRole('heading', { name: 'You’re on the list' }),
    ).toBeVisible();
    const sources = posts(network)
      .filter((request) => request.method === 'POST')
      .map(
        (request) =>
          (JSON.parse(request.body ?? '') as { source: string }).source,
      );
    expect(sources).toEqual(['cli', 'other']);
  });

  test('shows 409 as success and 400 as an email error', async ({
    page,
    network,
  }) => {
    network.supabaseStatus = 409;
    await open(page, '/');
    await submit(page, 'dup@example.com');
    await expect(
      page.getByRole('heading', { name: 'You’re on the list' }),
    ).toBeVisible();
    network.supabaseStatus = 400;
    await open(page, '/');
    await submit(page, 'bad@example.com');
    await expect(page.locator('#email-error')).toHaveText(
      'Enter a valid email address.',
    );
  });

  test('validates before sending and drops honeypot submissions', async ({
    page,
    network,
  }) => {
    await open(page, '/');
    await page
      .getByRole('button', { name: 'Join the waitlist' })
      .last()
      .click();
    await expect(page.locator('#email-error')).toHaveText(
      'Enter your email address.',
    );
    await expect(page.locator('#consent-error')).toHaveText(
      'Please tick the box so we can email you.',
    );
    // Bots fill every field; people never see this one.
    await page.evaluate(() => {
      (document.getElementById('website') as HTMLInputElement).value = 'bot';
    });
    await submit(page, 'bot@example.com');
    await expect(
      page.getByRole('heading', { name: 'You’re on the list' }),
    ).toBeVisible();
    expect(posts(network)).toEqual([]);
  });
});
