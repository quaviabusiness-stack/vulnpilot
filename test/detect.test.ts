import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  detectInput,
  parseDetected,
  type DetectedInput,
} from '../src/lockfiles/detect.js';
import { readLockfile, readSbom } from '../src/lockfiles/index.js';

const FIXTURES: [string, DetectedInput][] = [
  ['projects/npm/package-lock.json', 'package-lock.json'],
  ['projects/pnpm/pnpm-lock.yaml', 'pnpm-lock.yaml'],
  ['projects/yarn-v1/yarn.lock', 'yarn.lock'],
  ['projects/yarn-berry/yarn.lock', 'yarn.lock'],
  ['sbom/cyclonedx.json', 'cyclonedx'],
];
const path = (fixture: string) => join('test/fixtures', fixture);
const read = (fixture: string) => readFile(path(fixture), 'utf8');
const cli = (fixture: string, detected: DetectedInput) =>
  detected === 'cyclonedx'
    ? readSbom(path(fixture))
    : readLockfile(path(fixture));

describe('browser input detection', () => {
  it.each(FIXTURES)(
    'reads %s by name and by content exactly as the CLI does',
    async (fixture, expected) => {
      const content = await read(fixture);
      const fromCli = await cli(fixture, expected);
      const name = fixture.split('/').pop()!;
      for (const detected of [
        detectInput(content, name),
        detectInput(content),
        detectInput(content, 'download (1).txt'),
      ]) {
        expect(detected).toBe(expected);
        const inventory = parseDetected(fromCli.file, detected!, content);
        expect(inventory).toEqual(fromCli);
      }
    },
  );

  it('lets a canonical lockfile name win, as the CLI does', async () => {
    const sbom = await read('sbom/cyclonedx.json');
    const detected = detectInput(sbom, 'package-lock.json');
    expect(detected).toBe('package-lock.json');
    expect(() => parseDetected('package-lock.json', detected!, sbom)).toThrow(
      'Could not parse package-lock.json: Expected package-lock.json with lockfileVersion 1, 2 or 3.',
    );
  });

  it('returns nothing for unsupported content', () => {
    expect(detectInput('hello world')).toBeUndefined();
    expect(detectInput('{"name":"app","version":"1.0.0"}')).toBeUndefined();
    expect(detectInput('[1, 2, 3]')).toBeUndefined();
    expect(detectInput('{ broken json')).toBeUndefined();
    expect(detectInput('', 'notes.txt')).toBeUndefined();
  });

  it('detects input with a byte order mark but parses it like the CLI', async () => {
    const content = `\uFEFF${await read('projects/npm/package-lock.json')}`;
    expect(detectInput(content)).toBe('package-lock.json');
    expect(() =>
      parseDetected('package-lock.json', 'package-lock.json', content),
    ).toThrow(/^Could not parse package-lock\.json: /);
  });
});
