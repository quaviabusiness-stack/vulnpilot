import { defineConfig } from 'tsup';
import packageJson from './package.json' with { type: 'json' };

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  target: 'node26',
  platform: 'node',
  clean: true,
  splitting: false,
  sourcemap: false,
  // Bundle the two CLI dependencies so the packed entry is self-contained.
  noExternal: ['commander', '@clack/prompts'],
  define: {
    __CLI_VERSION__: JSON.stringify(packageJson.version),
    __SUPABASE_URL__: JSON.stringify(process.env.VULNPILOT_SUPABASE_URL ?? ''),
    __SUPABASE_ANON_KEY__: JSON.stringify(
      process.env.VULNPILOT_SUPABASE_ANON_KEY ?? '',
    ),
    __WAITLIST_URL__: JSON.stringify(process.env.VULNPILOT_WAITLIST_URL ?? ''),
  },
});
