export interface Dependency {
  name: string;
  version: string;
  ecosystem: 'npm';
}

export type Answer = 'yes' | 'no' | 'unknown';
export type ProductType = 'app' | 'library' | 'firmware' | 'unknown';

export interface Answers {
  euDistribution: Answer;
  commercial: Answer;
  productType: ProductType;
}

export type ResultBucket =
  'likely-applies' | 'likely-out-of-scope' | 'needs-review';

export interface Finding {
  dependency: Dependency;
  vulnerabilityIds: string[];
}
