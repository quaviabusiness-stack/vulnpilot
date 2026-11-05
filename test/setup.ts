import { beforeEach, vi } from 'vitest';

// All tests must inject a fixture-backed fetch; accidental requests fail closed.
beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error(
        'Network calls are forbidden in tests. Inject a mock fetch.',
      );
    }),
  );
});
