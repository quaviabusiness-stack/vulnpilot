// The CRA screen's result block. Rendered to HTML by the generator for the
// first paint and to DOM nodes by the page whenever an answer changes.
import type { CraAssessment } from '../../src/cra.js';
import type { CraVerdict } from '../../src/types.js';
import { longDate } from './format.js';
import { h, type VNode } from './view.js';

/** The verdict as the CLI prints it. */
export const VERDICT_TEXT: Readonly<Record<CraVerdict, string>> = {
  likely_applies: 'LIKELY APPLIES',
  likely_out_of_scope: 'LIKELY OUT OF SCOPE',
  unclear: 'UNCLEAR',
};

const FLAGS = {
  euDistribution: '--eu-distribution',
  commercial: '--commercial',
  productType: '--product-type',
} as const;

/** The same answers as CLI flags. */
export function craFlags(assessment: CraAssessment): string {
  return assessment.answers
    .map(({ id, answer }) => `${FLAGS[id]} ${answer}`)
    .join(' ');
}

export function craResultView(assessment: CraAssessment): VNode {
  return h(
    'div',
    { class: 'cra-result-body' },
    h(
      'dl',
      { class: 'cra-verdict' },
      h(
        'div',
        {},
        h('dt', {}, 'Verdict'),
        h(
          'dd',
          { class: 'cra-verdict-value' },
          VERDICT_TEXT[assessment.verdict],
        ),
      ),
      h(
        'div',
        {},
        h('dt', {}, 'Rule'),
        h('dd', {}, h('code', {}, assessment.rule)),
      ),
    ),
    h('p', { class: 'cra-reason' }, assessment.reason),
    h('h3', { class: 'minor-heading' }, 'Key dates'),
    h(
      'ul',
      { class: 'cra-dates' },
      ...assessment.keyDates.map((item) =>
        h(
          'li',
          {},
          h('time', { datetime: item.date }, longDate(item.date)),
          item.inForce ? ' (in force)' : '',
          `: ${item.obligation}`,
        ),
      ),
    ),
    h('p', { class: 'cra-disclaimer' }, h('strong', {}, assessment.disclaimer)),
    h(
      'p',
      { class: 'cra-flags' },
      'As flags: ',
      h('code', { 'data-cra-flags': '' }, craFlags(assessment)),
    ),
  );
}
