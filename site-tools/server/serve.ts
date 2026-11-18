// A small local server that behaves like the Vercel deployment of site/ for
// tests and previews: clean URLs, 404.html, the headers from site/vercel.json
// (so CSP violations show up locally), and /api/kev from the generated
// function file. Upstream CISA requests are answered from a fixture when
// KEV_FIXTURE is set; nothing here talks to the network otherwise.
//
//   pnpm --filter site-tools serve            # http://localhost:4173
import { readFileSync, statSync } from 'node:fs';
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { SITE } from '../build/paths.js';

interface HeaderRule {
  source: string;
  headers: { key: string; value: string }[];
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/vnd.microsoft.icon',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
};

/** Vercel `source` patterns used in site/vercel.json are plain regular expressions. */
export function headerRules(): {
  pattern: RegExp;
  headers: HeaderRule['headers'];
}[] {
  const config = JSON.parse(
    readFileSync(join(SITE, 'vercel.json'), 'utf8'),
  ) as {
    headers: HeaderRule[];
  };
  return config.headers.map((rule) => {
    if (!/^[\w/()*.?!$|+-]*$/.test(rule.source))
      throw new Error(`Unsupported source pattern ${rule.source}`);
    return { pattern: new RegExp(`^${rule.source}$`), headers: rule.headers };
  });
}

export function headersFor(path: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const rule of headerRules())
    if (rule.pattern.test(path))
      for (const { key, value } of rule.headers) headers[key] = value;
  return headers;
}

function file(path: string): string | undefined {
  const target = normalize(join(SITE, path));
  if (!target.startsWith(SITE + sep) && target !== SITE) return undefined;
  try {
    return statSync(target).isFile() ? target : undefined;
  } catch {
    return undefined;
  }
}

async function kevFetchOverride(): Promise<void> {
  const fixture = process.env.KEV_FIXTURE;
  if (!fixture) return;
  const { KEV_URL } = await import('../../src/kev.js');
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== KEV_URL) return original(input, init);
    if (process.env.KEV_UPSTREAM_STATUS)
      return new Response('', {
        status: Number(process.env.KEV_UPSTREAM_STATUS),
      });
    return new Response(readFileSync(fixture), {
      headers: { 'Content-Type': 'application/json' },
    });
  };
}

async function api(request: IncomingMessage, url: URL): Promise<Response> {
  const module = (await import(
    pathToFileURL(join(SITE, 'api', 'kev.mjs')).href
  )) as Record<string, (request: Request) => Promise<Response>>;
  const handler = module[request.method ?? 'GET'];
  if (url.pathname !== '/api/kev' || !handler)
    return new Response('Not found', { status: 404 });
  return handler(new Request(url, { method: request.method ?? 'GET' }));
}

async function respond(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const url = new URL(request.url ?? '/', 'http://localhost');
  const path = decodeURIComponent(url.pathname);
  const send = (
    status: number,
    body: Buffer | string | null,
    headers: Record<string, string>,
  ) => {
    // Header names are case-insensitive; the deployment's rules win, as on Vercel.
    const merged: Record<string, string> = {};
    for (const [key, value] of Object.entries({ ...headers }))
      merged[key.toLowerCase()] = value;
    for (const [key, value] of Object.entries(headersFor(path)))
      merged[key.toLowerCase()] = value;
    // This server speaks plain HTTP, and WebKit applies
    // upgrade-insecure-requests even to 127.0.0.1. The deployment is HTTPS
    // only, where the directive changes nothing; tests check it in vercel.json.
    const csp = merged['content-security-policy'];
    if (csp)
      merged['content-security-policy'] = csp.replace(
        /; upgrade-insecure-requests/,
        '',
      );
    response.writeHead(status, merged);
    response.end(request.method === 'HEAD' ? undefined : (body ?? undefined));
  };

  if (path.startsWith('/api/')) {
    const result = await api(request, url);
    const headers: Record<string, string> = {};
    result.headers.forEach((value, key) => {
      headers[key] = value;
    });
    send(result.status, Buffer.from(await result.arrayBuffer()), headers);
    return;
  }
  if (path.endsWith('.html')) {
    const clean = path === '/index.html' ? '/' : path.slice(0, -5);
    send(308, null, { Location: clean + url.search });
    return;
  }
  if (path.length > 1 && path.endsWith('/')) {
    send(308, null, { Location: path.slice(0, -1) + url.search });
    return;
  }
  const target =
    path === '/' ? file('index.html') : (file(path) ?? file(`${path}.html`));
  if (!target) {
    send(404, readFileSync(join(SITE, '404.html')), {
      'Content-Type': TYPES['.html']!,
    });
    return;
  }
  send(200, readFileSync(target), {
    'Content-Type': TYPES[extname(target)] ?? 'application/octet-stream',
  });
}

export async function startServer(port: number): Promise<() => Promise<void>> {
  await kevFetchOverride();
  const server = createServer((request, response) => {
    respond(request, response).catch((error: unknown) => {
      console.error(error);
      response.writeHead(500).end('Internal error');
    });
  });
  await new Promise<void>((resolve) =>
    server.listen(port, '127.0.0.1', resolve),
  );
  return () => new Promise((resolve) => server.close(() => resolve()));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const port = Number(process.env.PORT ?? 4173);
  await startServer(port);
  console.log(`Serving site/ on http://localhost:${port}`);
}
