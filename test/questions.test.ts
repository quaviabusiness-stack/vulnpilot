import { select } from '@clack/prompts';
import { expect, it, vi } from 'vitest';
import { askQuestions, CancelledError } from '../src/questions.js';

vi.mock('@clack/prompts', () => ({
  select: vi.fn(),
  isCancel: (value: unknown) => typeof value === 'symbol',
}));

it('returns unknown answers without prompts in non-interactive mode', async () => {
  expect(await askQuestions({}, false)).toEqual({
    euDistribution: 'unknown',
    commercial: 'unknown',
    productType: 'unknown',
  });
  expect(select).not.toHaveBeenCalled();
});

it('asks all three questions interactively, including "not sure" and SaaS options', async () => {
  vi.mocked(select)
    .mockResolvedValueOnce('yes')
    .mockResolvedValueOnce('unknown')
    .mockResolvedValueOnce('saas-with-client');
  expect(await askQuestions({}, true)).toEqual({
    euDistribution: 'yes',
    commercial: 'unknown',
    productType: 'saas-with-client',
  });
  expect(select).toHaveBeenCalledTimes(3);
  const productOptions = vi.mocked(select).mock.calls[2]![0].options;
  expect(productOptions.map((option) => option.value)).toEqual([
    'app',
    'library',
    'firmware',
    'saas',
    'saas-with-client',
    'unknown',
  ]);
});

it('uses supplied answers without prompting again', async () => {
  const answers = {
    euDistribution: 'yes',
    commercial: 'yes',
    productType: 'firmware',
  } as const;
  expect(await askQuestions(answers, true)).toEqual(answers);
  expect(select).not.toHaveBeenCalled();
});

it('stops on cancellation', async () => {
  vi.mocked(select).mockResolvedValueOnce(Symbol('cancel'));
  await expect(askQuestions({}, true)).rejects.toBeInstanceOf(CancelledError);
  expect(select).toHaveBeenCalledTimes(1);
});
