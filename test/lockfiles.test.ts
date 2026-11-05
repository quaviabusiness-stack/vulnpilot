import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import fixture from './fixtures/package-lock.json' with { type: 'json' };
import { readDependencies } from '../src/lockfiles/index.js';
import { parsePackageLock } from '../src/lockfiles/package-lock.js';

const directories: string[] = [];
async function directory() {
  const path = await mkdtemp(join(tmpdir(), 'vulnpilot-lock-test-'));
  directories.push(path);
  return path;
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe('package-lock parser', () => {
  it('reads the fixture without treating the root project as a dependency', () => {
    expect(parsePackageLock(JSON.stringify(fixture))).toEqual([
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      { name: 'picocolors', version: '1.1.1', ecosystem: 'npm' },
    ]);
  });

  it.each([2, 3])(
    'handles nested versions, scoped names, aliases and links in v%i',
    (lockfileVersion) => {
      const result = parsePackageLock(
        JSON.stringify({
          lockfileVersion,
          packages: {
            '': { name: 'root', version: '1.0.0' },
            'node_modules/a': { version: '1.0.0' },
            'node_modules/b/node_modules/a': { version: '1.0.0' },
            'node_modules/c/node_modules/a': { version: '2.0.0' },
            'node_modules/@scope/name': { version: '3.0.0-beta.1+build.2' },
            'node_modules/alias': { name: 'actual', version: '1.2.3' },
            'node_modules/local': {
              version: '1.0.0',
              resolved: 'file:../local',
            },
            'node_modules/workspace': {
              link: true,
              resolved: 'packages/workspace',
            },
            'packages/workspace': { name: 'workspace', version: '1.0.0' },
            'node_modules/git': { version: 'git+https://example.invalid/repo' },
          },
        }),
      );
      expect(result.map(({ name, version }) => `${name}@${version}`)).toEqual([
        'a@1.0.0',
        'a@2.0.0',
        '@scope/name@3.0.0-beta.1+build.2',
        'actual@1.2.3',
      ]);
    },
  );

  it('supports v1 transitive dependencies and scoped npm aliases', () => {
    const result = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          outer: {
            version: '1.0.0',
            dependencies: { inner: { version: '2.0.0' } },
          },
          alias: { version: 'npm:@scope/actual@3.0.0' },
        },
      }),
    );
    expect(result.map((item) => item.name)).toEqual([
      'outer',
      'inner',
      '@scope/actual',
    ]);
  });

  it.each([
    'null',
    '{}',
    '{',
    '{"lockfileVersion":4}',
    '{"lockfileVersion":3}',
  ])('rejects malformed or unsupported input: %s', (content) => {
    expect(() => parsePackageLock(content)).toThrow();
  });
});

describe('lockfile selection', () => {
  it('reads only the selected lockfile in a directory', async () => {
    expect(await readDependencies('test/fixtures')).toHaveLength(2);
    expect(
      await readDependencies('test/fixtures/package-lock.json'),
    ).toHaveLength(2);
  });

  it('rejects source files and unsupported filenames before reading', async () => {
    const path = await directory();
    const source = join(path, 'source.ts');
    await writeFile(source, 'not a lockfile');
    await expect(readDependencies(source)).rejects.toThrow(
      'Only supported dependency lockfiles',
    );
  });

  it('rejects missing and ambiguous lockfiles', async () => {
    const path = await directory();
    await expect(readDependencies(path)).rejects.toThrow(
      'No supported lockfile',
    );
    await writeFile(join(path, 'package-lock.json'), JSON.stringify(fixture));
    await writeFile(join(path, 'yarn.lock'), '');
    await expect(readDependencies(path)).rejects.toThrow('Multiple lockfiles');
  });

  it.each(['pnpm-lock.yaml', 'yarn.lock'])(
    'fails explicitly for the %s stub',
    async (name) => {
      const path = await directory();
      await writeFile(join(path, name), '');
      await expect(readDependencies(path)).rejects.toThrow(
        'not implemented yet',
      );
    },
  );

  it.skip('TODO: parse pnpm-lock.yaml snapshots and aliases', () => {});
  it.skip('TODO: parse Yarn Classic and Berry yarn.lock files', () => {});
});
