// Lighthouse CI for the built site, served locally with the deployment's
// headers. "Fast 4G" here means: 60 ms RTT, 9 Mbit/s down, 1.5 Mbit/s up,
// 4x CPU slowdown, mobile emulation (simulated throttling).
const { chromium } = require('@playwright/test');

const BASE = 'http://127.0.0.1:4173';
const strict = {
  'categories:performance': ['error', { minScore: 1 }],
  'categories:accessibility': ['error', { minScore: 1 }],
  'categories:best-practices': ['error', { minScore: 1 }],
  'categories:seo': ['error', { minScore: 1 }],
  'largest-contentful-paint': ['error', { maxNumericValue: 1500 }],
  'cumulative-layout-shift': ['error', { maxNumericValue: 0 }],
};

module.exports = {
  ci: {
    collect: {
      startServerCommand: 'tsx server/serve.ts',
      startServerReadyPattern: 'Serving site',
      url: [`${BASE}/`, `${BASE}/docs`, `${BASE}/scan`, `${BASE}/privacy`],
      numberOfRuns: 3,
      chromePath: chromium.executablePath(),
      settings: {
        formFactor: 'mobile',
        throttlingMethod: 'simulate',
        throttling: {
          rttMs: 60,
          throughputKbps: 9000,
          uploadThroughputKbps: 1500,
          cpuSlowdownMultiplier: 4,
        },
        chromeFlags: '--headless=new --no-sandbox',
        // Lighthouse fetches robots.txt from inside the page, so a strict
        // connect-src blocks it ("Fetch of robots.txt failed: CSP violation").
        // Crawlers do not apply page CSP. The site keeps its CSP and
        // checks/index.ts validates robots.txt and sitemap.xml instead.
        skipAudits: ['robots-txt'],
      },
    },
    assert: {
      assertMatrix: [
        { matchingUrlPattern: '4173/(docs|privacy)?$', assertions: strict },
        {
          // /scan loads its module script and the CRA rules before any input.
          matchingUrlPattern: '4173/scan$',
          assertions: {
            ...strict,
            'categories:performance': ['error', { minScore: 0.95 }],
          },
        },
      ],
    },
    upload: { target: 'filesystem', outputDir: '.lighthouseci' },
  },
};
