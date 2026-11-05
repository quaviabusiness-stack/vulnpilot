import packageJson from '../package.json' with { type: 'json' };

declare const __CLI_VERSION__: string;
declare const __SUPABASE_URL__: string;
declare const __SUPABASE_ANON_KEY__: string;
declare const __WAITLIST_URL__: string;

export const CLI_VERSION =
  typeof __CLI_VERSION__ === 'undefined'
    ? packageJson.version
    : __CLI_VERSION__;

// These are embedded at build time only (see tsup.config.ts). Runtime
// environment variables cannot enable telemetry in a published build.
export const SUPABASE_URL =
  typeof __SUPABASE_URL__ === 'undefined' ? '' : __SUPABASE_URL__;
export const SUPABASE_ANON_KEY =
  typeof __SUPABASE_ANON_KEY__ === 'undefined' ? '' : __SUPABASE_ANON_KEY__;
export const WAITLIST_URL =
  typeof __WAITLIST_URL__ === 'undefined' ? '' : __WAITLIST_URL__;
