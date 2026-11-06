#!/usr/bin/env node
import { EXIT, runCli } from './main.js';

runCli().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    const message =
      error instanceof Error ? error.message : 'Unexpected error.';
    // Diagnostics stay off stdout so --json output remains machine-readable.
    console.error(`Vulnpilot: ${message}`);
    process.exitCode = EXIT.error;
  },
);
