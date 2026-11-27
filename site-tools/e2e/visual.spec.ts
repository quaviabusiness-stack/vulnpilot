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
        // Playwright routing disables HTTP caching, so warming up fonts on a
        // different page cannot prevent `font-display: optional` from falling
        // back. Allow the fonts to swap in before measuring the screenshot.
        await page.route(/\/assets\/styles-[a-f0-9]+\.css$/, async (route) => {
          const response = await route.fetch();
          expect(response.ok()).toBe(true);
          const css = (await response.text()).replaceAll(
            'font-display: optional',
            'font-display: swap',
          );
          await route.fulfill({ contentType: 'text/css', body: css });
        });
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
