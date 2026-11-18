// Replaced at build time (see build/scanner.ts).
declare const __WORKER_URL__: string;
declare const __CLI_VERSION__: string;

// Trusted Types, as far as /scan uses them (not yet in TypeScript's DOM lib).
interface TrustedScriptURLPolicy {
  createScriptURL(input: string): unknown;
}
interface TrustedTypesFactory {
  createPolicy(
    name: string,
    rules: { createScriptURL(input: string): string },
  ): TrustedScriptURLPolicy;
}
interface Window {
  trustedTypes?: TrustedTypesFactory;
}
