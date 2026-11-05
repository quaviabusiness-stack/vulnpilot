export interface HttpClient {
  fetch: typeof fetch;
  /** Injected so tests can skip backoff delays. */
  sleep: (ms: number) => Promise<void>;
  timeoutMs: number;
  retries: number;
}

export function createHttpClient(
  overrides: Partial<HttpClient> = {},
): HttpClient {
  return {
    fetch: overrides.fetch ?? ((...args) => fetch(...args)),
    sleep:
      overrides.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
    timeoutMs: overrides.timeoutMs ?? 10_000,
    retries: overrides.retries ?? 2,
  };
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    url: string,
  ) {
    super(`HTTP ${status} from ${new URL(url).host}`);
  }
}

function retryable(error: unknown): boolean {
  if (error instanceof HttpError)
    return error.status === 429 || error.status >= 500;
  // Network failures, aborts and timeouts are retried; JSON syntax errors are not.
  return !(error instanceof SyntaxError);
}

/** Fetches JSON with a per-attempt timeout and exponential backoff on transient failures. */
export async function getJson(
  client: HttpClient,
  url: string,
  init: RequestInit = {},
  timeoutMs = client.timeoutMs,
): Promise<unknown> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= client.retries; attempt += 1) {
    if (attempt > 0)
      await client.sleep(400 * 2 ** (attempt - 1) + Math.random() * 200);
    try {
      const response = await client.fetch(url, {
        ...init,
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new HttpError(response.status, url);
      return await response.json();
    } catch (error) {
      lastError = error;
      if (!retryable(error)) break;
    }
  }
  throw lastError;
}

/** Runs `task` over `items` with at most `limit` in flight; preserves order. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next++;
      results[index] = await task(items[index]!, index);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
  return results;
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error)
    return error.name === 'TimeoutError' ? 'request timed out' : error.message;
  return String(error);
}
