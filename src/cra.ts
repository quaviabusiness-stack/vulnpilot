import type { Answer, Answers, CraVerdict, ProductType } from './types.js';

// ---------------------------------------------------------------------------
// EU Cyber Resilience Act (Regulation (EU) 2024/2847) applicability screen.
//
// LEGAL REVIEW NEEDED: every rule below is a simplified DRAFT written by
// engineers, not lawyers. It deliberately errs towards "unclear" and must be
// reviewed by qualified counsel before anyone relies on it. It is not legal
// advice. Notable simplifications: no treatment of the sectoral exclusions
// (medical devices, motor vehicles, aviation, marine equipment, defence),
// importers/distributors, spare parts, or the important/critical product
// categories that change the conformity-assessment route.
// ---------------------------------------------------------------------------

export const DISCLAIMER =
  'Not legal advice. This is an automated preliminary screen based on three answers.';

export interface CraQuestion {
  id: keyof Answers;
  question: string;
}

export const QUESTIONS: readonly CraQuestion[] = [
  {
    id: 'euDistribution',
    question:
      'Is the product made available on the EU market (sold, distributed or offered to users in the EU)?',
  },
  {
    id: 'commercial',
    question:
      'Is it supplied as part of a commercial activity (sold, licensed, monetised, or with paid support/services)?',
  },
  { id: 'productType', question: 'What kind of product is it?' },
];

export const PRODUCT_TYPES: Record<ProductType, string> = {
  app: 'Installable software (desktop, mobile, CLI, on-prem server)',
  library: 'Library or component that others integrate',
  firmware: 'Firmware or a connected hardware device',
  saas: 'Pure SaaS / hosted service with nothing downloadable',
  'saas-with-client': 'SaaS with an app, desktop client, agent or firmware',
  unknown: 'Not sure',
};

export interface KeyDate {
  date: string;
  obligation: string;
  inForce: boolean;
}

export interface CraAssessment {
  verdict: CraVerdict;
  /** Identifier of the rule that produced the verdict, for transparency. */
  rule: string;
  reason: string;
  answers: {
    id: keyof Answers;
    question: string;
    answer: Answer | ProductType;
  }[];
  keyDates: KeyDate[];
  disclaimer: string;
}

const KEY_DATES = [
  {
    date: '2026-09-11',
    obligation:
      'Vulnerability and incident reporting obligations apply: early warning within 24 hours of becoming aware of an actively exploited vulnerability or severe incident.',
  },
  {
    date: '2027-12-11',
    obligation:
      'Full obligations apply, including essential cybersecurity requirements, conformity assessment and CE marking.',
  },
] as const;

const DOWNLOADABLE: ProductType[] = ['app', 'library', 'firmware'];

interface Rule {
  id: string;
  matches: (answers: Answers) => boolean;
  verdict: CraVerdict;
  reason: (answers: Answers) => string;
}

// Rules are evaluated in order; the first match wins.
const RULES: Rule[] = [
  {
    // LEGAL REVIEW NEEDED: the CRA only covers products made available on the Union market.
    id: 'not-on-eu-market',
    matches: (a) => a.euDistribution === 'no',
    verdict: 'likely_out_of_scope',
    reason: () =>
      'CRA obligations attach to products with digital elements that are made available on the EU market. You said the product is not offered to users in the EU, so the CRA likely does not apply today. Re-assess as soon as you sell, distribute or offer downloads to EU users, including through app stores or resellers.',
  },
  {
    // LEGAL REVIEW NEEDED: remote data processing is only in scope when it is
    // part of a product with digital elements.
    id: 'pure-saas',
    matches: (a) => a.productType === 'saas',
    verdict: 'likely_out_of_scope',
    reason: () =>
      'Pure SaaS with no downloadable product is often outside the CRA: the regulation covers products with digital elements, and hosted services fall under it mainly as the remote data processing of such a product (they may instead fall under NIS2). If you ship any app, desktop client, agent, SDK or firmware, re-run and choose "SaaS with an app/client".',
  },
  {
    // LEGAL REVIEW NEEDED: FOSS outside a commercial activity is excluded
    // (open-source stewards have a lighter regime (Art. 24)).
    id: 'non-commercial-open-source',
    matches: (a) => a.commercial === 'no',
    verdict: 'likely_out_of_scope',
    reason: () =>
      'Free and open-source software that is not monetised and not supplied as part of a commercial activity is outside the manufacturer obligations. Note the lighter regime for "open-source software stewards" (Art. 24): an organisation that systematically supports open source intended for commercial use must have a cybersecurity policy, cooperate with authorities, and report actively exploited vulnerabilities to the extent it is involved in development. Monetisation (paid support, paid features, donations conditioned on services) can change the answer.',
  },
  {
    // LEGAL REVIEW NEEDED: placing on the market in the course of a commercial
    // activity makes the supplier a "manufacturer".
    id: 'commercial-eu-product',
    matches: (a) =>
      a.euDistribution === 'yes' &&
      a.commercial === 'yes' &&
      DOWNLOADABLE.includes(a.productType),
    verdict: 'likely_applies',
    reason: (a) =>
      `You make a ${a.productType === 'library' ? 'software component' : a.productType === 'firmware' ? 'firmware/hardware product' : 'software product'} available on the EU market as part of a commercial activity, so you are likely a "manufacturer" under the CRA. That means vulnerability handling, an SBOM, security updates for the support period, and reporting actively exploited vulnerabilities to ENISA/your CSIRT${a.productType === 'library' ? '. Components integrated by others are in scope when placed on the market on their own' : ''}.`,
  },
  {
    // LEGAL REVIEW NEEDED: a downloadable client is a product with digital
    // elements; whether the backend is its remote data processing depends on design.
    id: 'saas-with-client',
    matches: (a) => a.productType === 'saas-with-client',
    verdict: 'unclear',
    reason: () =>
      'Your service includes something users download or run (an app, desktop client, agent or firmware). That component is likely a product with digital elements, and the backend may count as its remote data processing solution. Whether and how the CRA applies depends on how the parts are offered and monetised in the EU; get a scoping review.',
  },
];

function fallbackReason(answers: Answers): string {
  const open = QUESTIONS.filter(({ id }) => answers[id] === 'unknown').map(
    ({ id }) =>
      ({
        euDistribution: 'whether you offer the product in the EU',
        commercial: 'whether it is part of a commercial activity',
        productType: 'what kind of product it is',
      })[id],
  );
  return open.length > 0
    ? `The answers do not settle it yet: unknown ${open.join(', ')}. If you sell or distribute downloadable software or firmware to EU users as part of a business, the CRA most likely applies.`
    : 'This combination of answers does not match a clear rule. If you sell or distribute downloadable software or firmware to EU users as part of a business, the CRA most likely applies.';
}

export function assessCra(answers: Answers, now = new Date()): CraAssessment {
  const rule = RULES.find((candidate) => candidate.matches(answers));
  const today = now.toISOString().slice(0, 10);
  return {
    verdict: rule?.verdict ?? 'unclear',
    rule: rule?.id ?? 'insufficient-information',
    reason: rule ? rule.reason(answers) : fallbackReason(answers),
    answers: QUESTIONS.map(({ id, question }) => ({
      id,
      question,
      answer: answers[id],
    })),
    keyDates: KEY_DATES.map((item) => ({
      ...item,
      inForce: today >= item.date,
    })),
    disclaimer: DISCLAIMER,
  };
}
