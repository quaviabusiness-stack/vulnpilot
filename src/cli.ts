#!/usr/bin/env node
import { runCli } from './main.js';

runCli().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unexpected error.';
  // Diagnostics stay off stdout so successful --json output is machine-readable.
  console.error(`Vulnpilot: ${message}`);
  process.exitCode = 1;
});
