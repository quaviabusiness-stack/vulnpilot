import { mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { CLI_VERSION, SUPABASE_ANON_KEY, SUPABASE_URL } from './build-info.js';
import type { CraVerdict } from './types.js';

export type KevCountBucket = '0' | '1' | '2-5' | '6+';

/** The complete telemetry payload. Nothing else is ever sent. */
export interface TelemetryEvent {
  cli_version: string;
  os: string;
  dep_count: number;
  result_bucket: CraVerdict;
  kev_count_bucket: KevCountBucket;
}

const KNOWN_PLATFORMS = new Set([
  'aix',
  'android',
  'darwin',
  'freebsd',
  'linux',
  'openbsd',
  'sunos',
  'win32',
]);

export function kevCountBucket(count: number): KevCountBucket {
  if (count <= 0) return '0';
  if (count === 1) return '1';
  if (count <= 5) return '2-5';
  return '6+';
}

export function telemetryEvent(input: {
  dependencyCount: number;
  verdict: CraVerdict;
  kevCount: number;
  platform?: string;
}): TelemetryEvent {
  const platform = input.platform ?? process.platform;
  return {
    cli_version: CLI_VERSION,
    os: KNOWN_PLATFORMS.has(platform) ? platform : 'other',
    dep_count: input.dependencyCount,
    result_bucket: input.verdict,
    kev_count_bucket: kevCountBucket(input.kevCount),
  };
}

interface TelemetryOptions {
  enabled: boolean;
  event: TelemetryEvent;
  env?: NodeJS.ProcessEnv;
  supabaseUrl?: string;
  anonKey?: string;
  fetch?: typeof fetch;
  stateDirectory?: string;
  notice?: (message: string) => void;
}

export function telemetryDisabled(
  enabled: boolean,
  env: NodeJS.ProcessEnv,
): boolean {
  return !enabled || env.VULNPILOT_TELEMETRY === '0' || env.CI !== undefined;
}

export async function sendTelemetry(options: TelemetryOptions): Promise<void> {
  const env = options.env ?? process.env;
  const supabaseUrl = options.supabaseUrl ?? SUPABASE_URL;
  const anonKey = options.anonKey ?? SUPABASE_ANON_KEY;
  if (telemetryDisabled(options.enabled, env) || !supabaseUrl || !anonKey)
    return;

  try {
    const endpoint = new URL('/rest/v1/cli_runs', supabaseUrl);
    if (endpoint.protocol !== 'https:') return;
    const stateDirectory =
      options.stateDirectory ??
      join(
        env.XDG_CONFIG_HOME ??
          (process.platform === 'win32'
            ? (env.APPDATA ?? homedir())
            : join(homedir(), '.config')),
        'vulnpilot',
      );
    const notice =
      options.notice ?? ((message: string) => console.error(message));
    try {
      await mkdir(stateDirectory, { recursive: true });
      await writeFile(join(stateDirectory, 'telemetry-notice'), '1\n', {
        flag: 'wx',
        mode: 0o600,
      });
      notice(
        'Vulnpilot sends anonymous usage counts (version, OS, dependency count, CRA result, KEV count bucket); disable with --no-telemetry or VULNPILOT_TELEMETRY=0.',
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        notice(
          'Vulnpilot telemetry is disabled because its first-run notice could not be saved.',
        );
        return;
      }
    }
    // Explicit allowlist: rebuild the object so no extra field can slip through.
    const { cli_version, os, dep_count, result_bucket, kev_count_bucket } =
      options.event;
    await (options.fetch ?? fetch)(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        Prefer: 'return=minimal',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(1500),
      body: JSON.stringify({
        cli_version,
        os,
        dep_count,
        result_bucket,
        kev_count_bucket,
      }),
    });
  } catch {
    // Telemetry is best-effort and must never fail a scan or retry an event.
  }
}
