// Messages between the /scan page and its parse worker. The worker reads the
// file, detects the format and parses it with the CLI's parsers; it has no
// network access (its CSP is connect-src 'none').
import type { DetectedInput } from '../../src/lockfiles/detect.js';
import type { Inventory } from '../../src/types.js';

export type ParseSource =
  | { kind: 'bytes'; buffer: ArrayBuffer; name: string }
  | { kind: 'text'; text: string; name?: string };

export interface ParseRequest {
  id: number;
  source: ParseSource;
  /** Shown in errors and in the report as `input.file`. */
  label: string;
}

export type ParseResponse =
  | {
      id: number;
      ok: true;
      inventory: Inventory;
      detected: DetectedInput;
      bytes: number;
      ms: number;
    }
  | {
      id: number;
      ok: false;
      reason: 'empty' | 'unsupported' | 'parse';
      message: string;
    };
