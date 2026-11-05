import { expect, it } from 'vitest';
import { assessCra, createReport, formatReport } from '../src/report.js';
import type { Answers } from '../src/types.js';

const answers: Answers = {
  euDistribution: 'yes',
  commercial: 'yes',
  productType: 'app',
};

it('keeps unanswered and noncommercial cases under review', () => {
  expect(assessCra(answers)).toBe('likely-applies');
  expect(assessCra({ ...answers, euDistribution: 'no' })).toBe(
    'likely-out-of-scope',
  );
  expect(assessCra({ ...answers, commercial: 'no' })).toBe('needs-review');
  expect(assessCra({ ...answers, productType: 'unknown' })).toBe(
    'needs-review',
  );
});

it('counts distinct IDs separately from vulnerable dependencies and marks mock data', () => {
  const dependency = {
    name: 'example',
    version: '1.0.0',
    ecosystem: 'npm',
  } as const;
  const report = createReport(
    answers,
    [
      { dependency, vulnerabilityIds: ['A', 'B'] },
      {
        dependency: { ...dependency, version: '2.0.0' },
        vulnerabilityIds: ['A'],
      },
    ],
    true,
  );
  expect(report.vulnerabilityCount).toBe(2);
  expect(report.vulnerableDependencyCount).toBe(2);
  expect(report.dependencyCount).toBe(2);
  expect(JSON.parse(formatReport(report, true))).toEqual(report);
  expect(formatReport(report, false)).toContain('MOCK DATA');
  expect(formatReport(report, false)).toContain('not legal advice');
});
