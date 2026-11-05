import { confirm, isCancel, select } from '@clack/prompts';
import type { Answers } from './types.js';

export class CancelledError extends Error {
  constructor() {
    super('Questionnaire cancelled.');
  }
}

export async function askQuestions(
  supplied: Partial<Answers>,
  interactive: boolean,
): Promise<Answers> {
  const answers: Answers = {
    euDistribution: supplied.euDistribution ?? 'unknown',
    commercial: supplied.commercial ?? 'unknown',
    productType: supplied.productType ?? 'unknown',
  };
  if (!interactive) return answers;

  for (const [key, message] of [
    ['euDistribution', 'Do you sell or distribute this product in the EU?'],
    ['commercial', 'Is this product part of a commercial activity?'],
  ] as const) {
    if (supplied[key] !== undefined) continue;
    const answer = await confirm({ message });
    if (isCancel(answer)) throw new CancelledError();
    answers[key] = answer ? 'yes' : 'no';
  }
  if (supplied.productType === undefined) {
    const answer = await select({
      message: 'What kind of product is it?',
      options: [
        { value: 'app' as const, label: 'App' },
        { value: 'library' as const, label: 'Library' },
        { value: 'firmware' as const, label: 'Firmware' },
      ],
    });
    if (isCancel(answer)) throw new CancelledError();
    answers.productType = answer;
  }
  return answers;
}
