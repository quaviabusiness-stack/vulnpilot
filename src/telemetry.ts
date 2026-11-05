import { mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { CLI_VERSION, TELEMETRY_ENDPOINT } from './build-info.js';
import type { ResultBucket } from './types.js';

interface TelemetryOptions {
  enabled: boolean;
  dependencyCount: number;
  resultBucket: ResultBucket;
  env?: NodeJS.ProcessEnv;
  endpoint?: string;
  fetch?: typeof fetch;
  stateDirectory?: string;
  notice?: (message: string) => void;
}

export async function sendTelemetry(options: TelemetryOptions): Promise<void> {
  const env = options.env ?? process.env;
  const endpoint = options.endpoint ?? TELEMETRY_ENDPOINT;
  if (
    !options.enabled ||
    env.VULNPILOT_TELEMETRY === '0' ||
    env.CI !== undefined ||
    !endpoint
  )
    return;

  try {
    if (new URL(endpoint).protocol !== 'https:') return;
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
        'Vulnpilot sends anonymous usage counts (version, OS, dependency count, result bucket); disable with --no-telemetry or VULNPILOT_TELEMETRY=0.',
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        notice(
          'Vulnpilot telemetry is disabled because its first-run notice could not be saved.',
        );
        return;
      }
    }
    // Explicit allowlist: no identifiers, package details, answers, paths or code.
    await (options.fetch ?? fetch)(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(1500),
      body: JSON.stringify({
        cliVersion: CLI_VERSION,
        os: process.platform,
        dependencyCount: options.dependencyCount,
        resultBucket: options.resultBucket,
      }),
    });
  } catch {
    // Telemetry is best-effort and must never fail a scan or retry an event.
  }
}
