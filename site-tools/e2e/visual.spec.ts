// Visual regression: every page and /scan state at 360, 768, 1280 and 1440 px
// in light and dark. Baselines are generated on Linux in CI (see site.yml,
// "update snapshots") and reviewed before they are committed.
import { expect, test } from './support.js';
import { PAGE_STATES, SCAN_STATES } from './states.js';

const WIDTHS = [360, 768, 1280, 1440];
// Time-dependent text is fixed or masked; everything else comes from fixtures.
const FIXED_TIME = new Date('2026-11-18T12:00:00Z');

for (const scheme of ['light', 'dark'] as const)
  for (const width of WIDTHS)
    for (const state of [...PAGE_STATES, ...SCAN_STATES])
      test(`${state.name} ${width} ${scheme} @visual`, async ({
        page,
        network,
      }) => {
        await page.clock.setFixedTime(FIXED_TIME);
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({
          colorScheme: scheme,
          reducedMotion: 'reduce',
        });
        // font-display: optional keeps fallback fonts when a font is slow on a
        // first visit; load both once so every screenshot uses the real fonts.
        await page.goto('/privacy');
        await page.evaluate(() =>
          Promise.all([
            document.fonts.load('400 16px Inter'),
            document.fonts.load('400 16px "JetBrains Mono"'),
          ]),
        );
        await state.setup(page, network);
        await page.evaluate(() => document.fonts.ready);
        // No page-level horizontal scrolling at any width.
        expect(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= window.innerWidth,
          ),
        ).toBe(true);
        // The sticky header would otherwise be drawn where the page was scrolled.
        await page.evaluate(() => window.scrollTo(0, 0));
        await expect(page).toHaveScreenshot(
          `${state.name}-${width}-${scheme}.png`,
          {
            fullPage: true,
          },
        );
      });
