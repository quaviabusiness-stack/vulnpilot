import { confirm, select } from '@clack/prompts';
import { expect, it, vi } from 'vitest';
import { askQuestions, CancelledError } from '../src/questions.js';

vi.mock('@clack/prompts', () => ({
  confirm: vi.fn(),
  select: vi.fn(),
  isCancel: (value: unknown) => typeof value === 'symbol',
}));

it('returns unknown answers without prompts in non-interactive mode', async () => {
  expect(await askQuestions({}, false)).toEqual({
    euDistribution: 'unknown',
    commercial: 'unknown',
    productType: 'unknown',
  });
  expect(confirm).not.toHaveBeenCalled();
  expect(select).not.toHaveBeenCalled();
});

it('asks all three questions interactively', async () => {
  vi.mocked(confirm).mockResolvedValueOnce(true).mockResolvedValueOnce(false);
  vi.mocked(select).mockResolvedValueOnce('library');
  expect(await askQuestions({}, true)).toEqual({
    euDistribution: 'yes',
    commercial: 'no',
    productType: 'library',
  });
  expect(confirm).toHaveBeenCalledTimes(2);
  expect(select).toHaveBeenCalledTimes(1);
});

it('uses supplied answers without prompting again', async () => {
  const answers = {
    euDistribution: 'yes',
    commercial: 'yes',
    productType: 'firmware',
  } as const;
  expect(await askQuestions(answers, true)).toEqual(answers);
  expect(confirm).not.toHaveBeenCalled();
  expect(select).not.toHaveBeenCalled();
});

it('stops on cancellation', async () => {
  vi.mocked(confirm).mockResolvedValueOnce(
    Symbol('cancel') as Awaited<ReturnType<typeof confirm>>,
  );
  await expect(askQuestions({}, true)).rejects.toBeInstanceOf(CancelledError);
  expect(select).not.toHaveBeenCalled();
});
