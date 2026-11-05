import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CLI_VERSION } from '../src/build-info.js';
import { sendTelemetry } from '../src/telemetry.js';

let stateDirectory: string;
beforeEach(async () => {
  stateDirectory = await mkdtemp(join(tmpdir(), 'vulnpilot-telemetry-test-'));
});
afterEach(async () => {
  await rm(stateDirectory, { recursive: true, force: true });
});

const event = {
  enabled: true,
  dependencyCount: 2,
  resultBucket: 'needs-review',
} as const;

it.each([
  { enabled: false, env: {} },
  { enabled: true, env: { VULNPILOT_TELEMETRY: '0' } },
  { enabled: true, env: { CI: 'true' } },
  { enabled: true, env: { CI: '' } },
])('never sends or shows notices when disabled: %j', async (override) => {
  const request = vi.fn<typeof fetch>();
  const notice = vi.fn();
  await sendTelemetry({
    ...event,
    ...override,
    endpoint: 'https://example.invalid/events',
    stateDirectory,
    fetch: request,
    notice,
  });
  expect(request).not.toHaveBeenCalled();
  expect(notice).not.toHaveBeenCalled();
});

it('does nothing when no endpoint was embedded at build time', async () => {
  await sendTelemetry({
    ...event,
    env: { VULNPILOT_TELEMETRY_ENDPOINT: 'https://example.invalid/runtime' },
    stateDirectory,
  });
  expect(fetch).not.toHaveBeenCalled();
});

it('sends exactly four allowed fields once per run and shows the notice once', async () => {
  const request = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response(null, { status: 204 }));
  const notice = vi.fn();
  const options = {
    ...event,
    env: {},
    endpoint: 'https://example.invalid/events',
    stateDirectory,
    fetch: request,
    notice,
  };
  await sendTelemetry(options);
  await sendTelemetry(options);
  expect(notice).toHaveBeenCalledTimes(1);
  expect(notice).toHaveBeenCalledWith(
    expect.stringContaining('--no-telemetry'),
  );
  expect(request).toHaveBeenCalledTimes(2);
  const [, init] = request.mock.calls[0]!;
  expect(JSON.parse(String(init?.body))).toEqual({
    cliVersion: CLI_VERSION,
    os: process.platform,
    dependencyCount: 2,
    resultBucket: 'needs-review',
  });
  expect(init?.redirect).toBe('error');
  expect(init?.signal).toBeInstanceOf(AbortSignal);
});

it('ignores delivery failures and does not retry', async () => {
  const request = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'));
  await expect(
    sendTelemetry({
      ...event,
      env: {},
      endpoint: 'https://example.invalid/events',
      stateDirectory,
      fetch: request,
      notice: vi.fn(),
    }),
  ).resolves.toBeUndefined();
  expect(request).toHaveBeenCalledTimes(1);
});

it('rejects non-HTTPS telemetry endpoints', async () => {
  const request = vi.fn<typeof fetch>();
  await sendTelemetry({
    ...event,
    env: {},
    endpoint: 'http://example.invalid/events',
    stateDirectory,
    fetch: request,
  });
  expect(request).not.toHaveBeenCalled();
});
