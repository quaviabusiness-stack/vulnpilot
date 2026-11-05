import { describe, expect, it } from 'vitest';
import { assessCra } from '../src/cra.js';
import type { Answers } from '../src/types.js';

const base: Answers = {
  euDistribution: 'yes',
  commercial: 'yes',
  productType: 'app',
};
const verdict = (overrides: Partial<Answers>) =>
  assessCra({ ...base, ...overrides });

describe('CRA decision rules (draft, pending legal review)', () => {
  it.each(['app', 'library', 'firmware'] as const)(
    'commercial %s on the EU market -> likely_applies',
    (productType) => {
      expect(verdict({ productType })).toMatchObject({
        verdict: 'likely_applies',
        rule: 'commercial-eu-product',
      });
    },
  );

  it('non-commercial open source -> likely_out_of_scope and mentions stewards', () => {
    const result = verdict({ commercial: 'no' });
    expect(result).toMatchObject({
      verdict: 'likely_out_of_scope',
      rule: 'non-commercial-open-source',
    });
    expect(result.reason).toContain('open-source software stewards');
  });

  it('pure SaaS -> likely_out_of_scope; SaaS with a client -> unclear', () => {
    expect(verdict({ productType: 'saas' })).toMatchObject({
      verdict: 'likely_out_of_scope',
      rule: 'pure-saas',
    });
    expect(verdict({ productType: 'saas-with-client' })).toMatchObject({
      verdict: 'unclear',
      rule: 'saas-with-client',
    });
  });

  it('not on the EU market -> likely_out_of_scope, whatever else is true', () => {
    expect(
      verdict({ euDistribution: 'no', productType: 'firmware' }),
    ).toMatchObject({
      verdict: 'likely_out_of_scope',
      rule: 'not-on-eu-market',
    });
  });

  it.each<Partial<Answers>>([
    { euDistribution: 'unknown' },
    { commercial: 'unknown' },
    { productType: 'unknown' },
    {
      euDistribution: 'unknown',
      commercial: 'unknown',
      productType: 'unknown',
    },
  ])('anything else -> unclear: %j', (overrides) => {
    const result = verdict(overrides);
    expect(result.verdict).toBe('unclear');
    expect(result.reason).toMatch(/unknown/);
  });

  it('returns the answers to all three questions with the verdict', () => {
    expect(assessCra(base).answers).toEqual([
      {
        id: 'euDistribution',
        question: expect.stringContaining('EU market'),
        answer: 'yes',
      },
      {
        id: 'commercial',
        question: expect.stringContaining('commercial'),
        answer: 'yes',
      },
      { id: 'productType', question: expect.any(String), answer: 'app' },
    ]);
  });

  it('always includes the key dates and the not-legal-advice disclaimer', () => {
    const before = assessCra(base, new Date('2026-01-01T00:00:00Z'));
    expect(before.keyDates).toEqual([
      {
        date: '2026-09-11',
        obligation: expect.stringContaining('24 hours'),
        inForce: false,
      },
      {
        date: '2027-12-11',
        obligation: expect.stringContaining('CE marking'),
        inForce: false,
      },
    ]);
    const after = assessCra(
      { ...base, commercial: 'no' },
      new Date('2026-11-05T00:00:00Z'),
    );
    expect(after.keyDates.map((item) => item.inForce)).toEqual([true, false]);
    expect(after.disclaimer).toMatch(/^Not legal advice/);
  });
});
