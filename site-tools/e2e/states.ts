// The pages and /scan states that accessibility and visual tests cover.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Page, Route } from '@playwright/test';
import { ROOT } from '../build/paths.js';
import { expect, type Network, open } from './support.js';

export interface State {
  name: string;
  setup: (page: Page, network: Network) => Promise<void>;
}

const sample = async (page: Page) => {
  await open(page, '/scan');
  await page.getByRole('button', { name: 'Try the sample SBOM' }).click();
  await expect(page.locator('#found-title')).toBeFocused();
};

const finish = async (page: Page) => {
  await page.locator('#scan-button').click();
  await expect(page.locator('#report-title')).toBeFocused({ timeout: 15_000 });
};

export const PAGE_STATES: State[] = [
  { name: 'home', setup: (page) => open(page, '/') },
  { name: 'docs', setup: (page) => open(page, '/docs') },
  { name: 'privacy', setup: (page) => open(page, '/privacy') },
  { name: 'not-found', setup: (page) => open(page, '/no-such-page') },
];

export const SCAN_STATES: State[] = [
  { name: 'scan-empty', setup: (page) => open(page, '/scan') },
  {
    name: 'scan-consent',
    setup: async (page) => {
      await sample(page);
      await page.getByRole('button', { name: 'Show the OSV request' }).click();
    },
  },
  {
    name: 'scan-scanning',
    setup: async (page, network) => {
      // Hold the advisory lookups so the counts stop at a known point.
      network.override(
        'https://api.osv.dev/v1/vulns/',
        (route: Route) =>
          new Promise<void>(() => {
            void route;
          }),
      );
      await sample(page);
      await page.locator('#scan-button').click();
      await expect(page.locator('#progress-advisories')).toHaveText('0 of 5');
    },
  },
  {
    name: 'scan-result',
    setup: async (page) => {
      await sample(page);
      await finish(page);
      await page.getByRole('button', { name: 'Show as table' }).click();
    },
  },
  {
    name: 'scan-osv-down',
    setup: async (page, network) => {
      network.override('https://api.osv.dev/v1/querybatch', (route: Route) =>
        route.fulfill({ status: 503, body: '' }),
      );
      await sample(page);
      await finish(page);
    },
  },
  {
    name: 'scan-unsupported',
    setup: async (page) => {
      await open(page, '/scan');
      await page.locator('#file-input').setInputFiles({
        name: 'notes.txt',
        mimeType: 'text/plain',
        buffer: Buffer.from('hello'),
      });
      await expect(page.locator('#input-error')).toBeVisible();
    },
  },
  {
    name: 'scan-oversize',
    setup: async (page) => {
      await open(page, '/scan');
      await page.locator('#file-input').setInputFiles({
        name: 'package-lock.json',
        mimeType: 'application/json',
        buffer: Buffer.alloc(33 * 1024 * 1024, 32),
      });
      await expect(page.locator('#input-error')).toBeVisible();
    },
  },
  {
    name: 'scan-lockfile',
    setup: async (page) => {
      await open(page, '/scan');
      await page
        .locator('#file-input')
        .setInputFiles(
          join(ROOT, 'test/fixtures/projects/npm/package-lock.json'),
        );
      await expect(page.locator('#found-title')).toBeFocused();
      await finish(page);
    },
  },
];

export const fixtureText = (path: string) =>
  readFileSync(join(ROOT, 'test/fixtures', path), 'utf8');
