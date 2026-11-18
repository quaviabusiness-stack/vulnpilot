// The /scan parse worker: reads one file or pasted text, detects the format
// and parses it with the CLI's own parsers. It cannot make network requests.
import { detectInput, parseDetected } from '../../src/lockfiles/detect.js';
import type { ParseRequest, ParseResponse } from './protocol.js';

declare const self: DedicatedWorkerGlobalScope;

// Node's readFile(…, 'utf8') keeps a byte order mark; so does this, so a file
// parses (or fails) here exactly as it does in the CLI.
const decoder = new TextDecoder('utf-8', { ignoreBOM: true });

self.addEventListener('message', (event: MessageEvent<ParseRequest>) => {
  const { id, source, label } = event.data;
  const started = performance.now();
  const reply = (response: ParseResponse) => self.postMessage(response);
  try {
    let content: string;
    let bytes: number;
    let name: string | undefined;
    if (source.kind === 'bytes') {
      bytes = source.buffer.byteLength;
      content = decoder.decode(source.buffer);
      name = source.name;
    } else {
      content = source.text;
      bytes = new TextEncoder().encode(content).byteLength;
      name = source.name;
    }
    if (content.trim() === '') {
      reply({ id, ok: false, reason: 'empty', message: `${label} is empty.` });
      return;
    }
    const detected = detectInput(content, name);
    if (!detected) {
      reply({ id, ok: false, reason: 'unsupported', message: '' });
      return;
    }
    const inventory = parseDetected(label, detected, content);
    reply({
      id,
      ok: true,
      inventory,
      detected,
      bytes,
      ms: performance.now() - started,
    });
  } catch (error) {
    reply({
      id,
      ok: false,
      reason: 'parse',
      message: error instanceof Error ? error.message : String(error),
    });
  }
});
