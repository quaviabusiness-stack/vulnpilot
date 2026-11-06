import { isCancel, select } from '@clack/prompts';
import { PRODUCT_TYPES, QUESTIONS } from './cra.js';
import type { Answer, Answers, ProductType } from './types.js';

export class CancelledError extends Error {
  constructor() {
    super('Questionnaire cancelled.');
  }
}

const YES_NO = [
  { value: 'yes' as const, label: 'Yes' },
  { value: 'no' as const, label: 'No' },
  { value: 'unknown' as const, label: 'Not sure' },
];

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

  for (const { id, question } of QUESTIONS) {
    if (supplied[id] !== undefined) continue;
    if (id === 'productType') {
      const answer = await select<ProductType>({
        message: question,
        options: (Object.keys(PRODUCT_TYPES) as ProductType[]).map((value) => ({
          value,
          label: PRODUCT_TYPES[value],
        })),
      });
      if (isCancel(answer)) throw new CancelledError();
      answers.productType = answer;
    } else {
      const answer = await select<Answer>({
        message: question,
        options: YES_NO,
      });
      if (isCancel(answer)) throw new CancelledError();
      answers[id] = answer;
    }
  }
  return answers;
}
