import { afterEach, expect, it, vi } from 'vitest';
import { runCli } from '../src/main.js';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

it('prints valid fixture-backed JSON without prompting', async () => {
  vi.stubEnv('OSV_MOCK', '1');
  const output = vi.spyOn(console, 'log').mockImplementation(() => {});
  await runCli([
    'node',
    'cli.js',
    '--path',
    'test/fixtures',
    '--json',
    '--no-telemetry',
  ]);
  expect(output).toHaveBeenCalledTimes(1);
  const report = JSON.parse(String(output.mock.calls[0]?.[0]));
  expect(report).toMatchObject({
    dependencyCount: 2,
    vulnerabilityCount: 1,
    dataSource: 'mock-fixture',
    cra: { result: 'needs-review' },
  });
  expect(report.disclaimer).toContain('not legal advice');
  expect(fetch).not.toHaveBeenCalled();
});

it('accepts all three CI answers through flags', async () => {
  vi.stubEnv('OSV_MOCK', '1');
  vi.stubEnv('CI', 'true');
  const output = vi.spyOn(console, 'log').mockImplementation(() => {});
  await runCli([
    'node',
    'cli.js',
    '--path',
    'test/fixtures',
    '--json',
    '--non-interactive',
    '--eu-distribution',
    'yes',
    '--commercial',
    'yes',
    '--product-type',
    'library',
  ]);
  expect(JSON.parse(String(output.mock.calls[0]?.[0])).cra).toEqual({
    result: 'likely-applies',
    answers: {
      euDistribution: 'yes',
      commercial: 'yes',
      productType: 'library',
    },
  });
  expect(fetch).not.toHaveBeenCalled();
});
