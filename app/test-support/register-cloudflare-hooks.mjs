import { register } from 'node:module';

register('./cloudflare-workers-loader.mjs', import.meta.url);
