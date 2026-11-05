import packageJson from '../package.json' with { type: 'json' };

declare const __CLI_VERSION__: string;
declare const __TELEMETRY_ENDPOINT__: string;

export const CLI_VERSION =
  typeof __CLI_VERSION__ === 'undefined'
    ? packageJson.version
    : __CLI_VERSION__;

// Runtime environment variables cannot enable an endpoint in a published build.
export const TELEMETRY_ENDPOINT =
  typeof __TELEMETRY_ENDPOINT__ === 'undefined' ? '' : __TELEMETRY_ENDPOINT__;
