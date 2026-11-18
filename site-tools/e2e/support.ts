// Shared fixtures: every external request is intercepted. OSV.dev and FIRST
// EPSS are answered by the CLI's own mock (src/mock.ts, the fixtures in
// test/fixtures/mock), the Supabase waitlist POST never reaches the real
// table, anything else fails the test, and any CSP or Trusted Types
// violation fails the test.
import {
  test as base,
  expect,
  type Page,
  type Request,
  type Route,
} from '@playwright/test';
import { createMockFetch } from '../../src/mock.js';

export const SUPABASE = 'https://xvdwfhadpmsgfpschnbp.supabase.co';
const LOCAL = /^http:\/\/(127\.0\.0\.1|localhost):4173\//;

export interface Recorded {
  method: string;
  url: string;
  body: string | null;
  headers: Record<string, string>;
}

export interface Network {
  requests: Recorded[];
  external(): Recorded[];
  /**
   * Replace the answer for URLs starting with `prefix`. A handler answers
   * with route.fulfill or hands back to the fixture's mock with
   * `network.answer`; it must never send a request to the real service.
   */
  override(
    prefix: string,
    handler: (route: Route, request: Request) => Promise<void> | void,
  ): void;
  /** The fixture's own answer (the CLI's mock for OSV and EPSS). */
  answer(route: Route, request: Request): Promise<void>;
  /** The CLI's mock fetch, for building modified answers. */
  mock: typeof fetch;
  supabaseStatus: number;
}

const CORS = (origin: string) => ({
  'access-control-allow-origin': origin,
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'access-control-allow-headers': 'Content-Type',
});

export const test = base.extend<{ network: Network; violations: string[] }>({
  network: [
    async ({ context }, use) => {
      const mock = createMockFetch();
      const overrides: [
        string,
        (route: Route, request: Request) => Promise<void> | void,
      ][] = [];
      async function answer(route: Route, request: Request): Promise<void> {
        const url = request.url();
        if (LOCAL.test(url)) return route.continue();
        const origin =
          (await request.headerValue('origin')) ?? 'http://127.0.0.1:4173';
        if (request.method() === 'OPTIONS')
          return route.fulfill({ status: 204, headers: CORS(origin) });
        if (
          url.startsWith('https://api.osv.dev/') ||
          url.startsWith('https://api.first.org/')
        ) {
          const body = request.postData();
          const response = await mock(url, {
            method: request.method(),
            ...(body === null ? {} : { body }),
          });
          return route.fulfill({
            status: response.status,
            headers: { 'content-type': 'application/json', ...CORS(origin) },
            body: await response.text(),
          });
        }
        if (url.startsWith(SUPABASE))
          return route.fulfill({
            status: network.supabaseStatus,
            headers: CORS(origin),
            body: '',
          });
        return route.abort('blockedbyclient');
      }
      const network: Network = {
        requests: [],
        external: () =>
          network.requests.filter((item) => !LOCAL.test(item.url)),
        override: (prefix, handler) => overrides.unshift([prefix, handler]),
        answer,
        mock,
        supabaseStatus: 201,
      };
      await context.route('**/*', async (route, request) => {
        const url = request.url();
        if (!url.startsWith('data:') && !url.startsWith('blob:'))
          network.requests.push({
            method: request.method(),
            url,
            body: request.postData(),
            headers: await request.allHeaders(),
          });
        const override = overrides.find(([prefix]) => url.startsWith(prefix));
        if (override) return override[1](route, request);
        return answer(route, request);
      });
      await use(network);
    },
    { auto: true },
  ],
  violations: [
    async ({ page }, use) => {
      const violations: string[] = [];
      await page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (event) => {
          console.error(
            `CSP violation: ${event.violatedDirective} ${event.blockedURI}`,
          );
        });
      });
      const watch = (text: string) => {
        if (
          /Content Security Policy|CSP violation|Trusted Type|TrustedScriptURL|TrustedHTML/i.test(
            text,
          )
        )
          violations.push(text);
      };
      page.on('console', (message) => watch(message.text()));
      page.on('pageerror', (error) =>
        violations.push(`page error: ${error.message}`),
      );
      page.on('worker', (worker) =>
        worker.on('console', (message) => watch(message.text())),
      );
      await use(violations);
      expect(violations, 'CSP, Trusted Types or script errors').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/** Opens a page with the network fixture and CSP watching in place. */
export async function open(page: Page, path: string): Promise<void> {
  const response = await page.goto(path);
  expect(response?.ok() || response?.status() === 404).toBe(true);
}
