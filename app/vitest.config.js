import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: '../wrangler.toml' },
      miniflare: {
        bindings: {
          PROXY_SECRET: '000102030405060708090a0b0c0d0e0f',
          RELAY_DEBUG: '0',
        },
      },
    }),
  ],
  test: {
    include: ['runtime-test/**/*.worker.js'],
    testTimeout: 15_000,
  },
});
