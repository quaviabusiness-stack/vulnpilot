// axe-core (WCAG 2.0, 2.1 and 2.2, levels A and AA) on every page and every
// /scan state, in both colour schemes.
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './support.js';
import { PAGE_STATES, SCAN_STATES } from './states.js';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

for (const scheme of ['light', 'dark'] as const)
  for (const state of [...PAGE_STATES, ...SCAN_STATES])
    test(`${state.name} has no axe violations in ${scheme}`, async ({
      page,
      network,
    }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await state.setup(page, network);
      const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
      expect(
        results.violations.map(({ id, nodes }) => ({
          id,
          targets: nodes.map((node) => node.target.join(' ')),
        })),
      ).toEqual([]);
    });
