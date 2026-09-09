import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';

function javascriptFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return javascriptFiles(path);
    return /\.(?:js|mjs)$/.test(entry.name) ? [path] : [];
  });
}

const files = [
  'src', 'test', 'runtime-test', 'scripts', 'test-support', '../shared',
  '../validation/src', '../validation/test', '../validation/scripts',
  '../validation/cloudflare-probe/src', '../validation/cloudflare-probe/test',
].flatMap(javascriptFiles);
for (const file of files) execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
console.log(`syntax ok: ${files.length} files`);
