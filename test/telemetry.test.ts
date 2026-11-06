import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CLI_VERSION } from '../src/build-info.js';
import {
  kevCountBucket,
  sendTelemetry,
  telemetryEvent,
} from '../src/telemetry.js';

let stateDirectory: string;
beforeEach(async () => {
  stateDirectory = await mkdtemp(join(tmpdir(), 'vulnpilot-telemetry-test-'));
});
afterEach(async () => {
  await rm(stateDirectory, { recursive: true, force: true });
});

const event = telemetryEvent({
  dependencyCount: 812,
  verdict: 'likely_applies',
  kevCount: 3,
  platform: 'linux',
});
let configured: {
  enabled: boolean;
  event: typeof event;
  supabaseUrl: string;
  anonKey: string;
  stateDirectory: string;
};
beforeEach(() => {
  configured = {
    enabled: true,
    event,
    supabaseUrl: 'https://project.supabase.co',
    anonKey: 'anon-test-key',
    stateDirectory,
  };
});

it('builds exactly the five documented fields', () => {
  expect(event).toEqual({
    cli_version: CLI_VERSION,
    os: 'linux',
    dep_count: 812,
    result_bucket: 'likely_applies',
    kev_count_bucket: '2-5',
  });
  expect(
    telemetryEvent({
      dependencyCount: 0,
      verdict: 'unclear',
      kevCount: 0,
      platform: 'haiku',
    }).os,
  ).toBe('other');
  expect([0, 1, 2, 5, 6, 40].map(kevCountBucket)).toEqual([
    '0',
    '1',
    '2-5',
    '2-5',
    '6+',
    '6+',
  ]);
});

it.each([
  { enabled: false, env: {} },
  { enabled: true, env: { VULNPILOT_TELEMETRY: '0' } },
  { enabled: true, env: { CI: 'true' } },
  { enabled: true, env: { CI: '' } },
])('never sends or shows notices when disabled: %j', async (override) => {
  const request = vi.fn<typeof fetch>();
  const notice = vi.fn();
  await sendTelemetry({ ...configured, ...override, fetch: request, notice });
  expect(request).not.toHaveBeenCalled();
  expect(notice).not.toHaveBeenCalled();
});

it('does nothing when no Supabase project was embedded at build time', async () => {
  await sendTelemetry({
    enabled: true,
    event,
    env: { VULNPILOT_SUPABASE_URL: 'https://runtime.example' },
    stateDirectory,
  });
  expect(fetch).not.toHaveBeenCalled();
});

it('inserts one row into cli_runs with the anon key and shows the notice once', async () => {
  const request = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response(null, { status: 201 }));
  const notice = vi.fn();
  const options = { ...configured, env: {}, fetch: request, notice };
  await sendTelemetry(options);
  await sendTelemetry(options);
  expect(notice).toHaveBeenCalledTimes(1);
  expect(notice).toHaveBeenCalledWith(
    expect.stringContaining('--no-telemetry'),
  );
  expect(request).toHaveBeenCalledTimes(2);
  const [url, init] = request.mock.calls[0]!;
  expect(String(url)).toBe('https://project.supabase.co/rest/v1/cli_runs');
  expect(init?.method).toBe('POST');
  expect(init?.headers).toEqual({
    'Content-Type': 'application/json',
    apikey: 'anon-test-key',
    Authorization: 'Bearer anon-test-key',
    Prefer: 'return=minimal',
  });
  expect(JSON.parse(String(init?.body))).toEqual(event);
  expect(Object.keys(JSON.parse(String(init?.body)))).toEqual([
    'cli_version',
    'os',
    'dep_count',
    'result_bucket',
    'kev_count_bucket',
  ]);
  expect(init?.redirect).toBe('error');
  expect(init?.signal).toBeInstanceOf(AbortSignal);
});

it('drops any field outside the allowlist', async () => {
  const request = vi.fn<typeof fetch>().mockResolvedValue(new Response(null));
  await sendTelemetry({
    ...configured,
    env: {},
    event: { ...event, packages: ['secret-internal-pkg'] } as typeof event,
    fetch: request,
    notice: vi.fn(),
  });
  expect(String(request.mock.calls[0]![1]?.body)).not.toContain('secret');
});

it('ignores delivery failures and does not retry', async () => {
  const request = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'));
  await expect(
    sendTelemetry({ ...configured, env: {}, fetch: request, notice: vi.fn() }),
  ).resolves.toBeUndefined();
  expect(request).toHaveBeenCalledTimes(1);
});

it('rejects non-HTTPS Supabase URLs', async () => {
  const request = vi.fn<typeof fetch>();
  await sendTelemetry({
    ...configured,
    supabaseUrl: 'http://project.supabase.co',
    env: {},
    fetch: request,
  });
  expect(request).not.toHaveBeenCalled();
});
