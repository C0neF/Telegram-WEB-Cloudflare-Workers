import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const rootConfigUrl = new URL('../../wrangler.toml', import.meta.url);
const appConfigUrl = new URL('../../app/wrangler.toml', import.meta.url);

test('the root Wrangler config is the only deployment contract', () => {
  assert.equal(existsSync(rootConfigUrl), true);
  assert.equal(existsSync(appConfigUrl), false);

  const root = readFileSync(rootConfigUrl, 'utf8');
  assert.match(root, /^main\s*=\s*"app\/src\/index\.js"/m);
  assert.match(root, /^name\s*=\s*"telegram-web-cloudflare-workers"/m);
  assert.match(root, /^compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"/m);
  assert.match(root, /^new_sqlite_classes\s*=\s*\["RelayDO"\]/m);
});

test('app tooling explicitly consumes the root Wrangler config', () => {
  const packageJson = JSON.parse(readFileSync(
    new URL('../../app/package.json', import.meta.url),
    'utf8',
  ));
  for (const scriptName of ['dev', 'deploy', 'deploy:dry']) {
    assert.match(packageJson.scripts[scriptName], /(?:^|\s)wrangler(?:\s|$)/);
    assert.match(packageJson.scripts[scriptName], /--config \.\.\/wrangler\.toml(?:\s|$)/);
    assert.doesNotMatch(packageJson.scripts[scriptName], /wrangler@/);
  }
  assert.equal(packageJson.devDependencies.wrangler, '4.127.0');

  const vitestConfig = readFileSync(
    new URL('../../app/vitest.config.js', import.meta.url),
    'utf8',
  );
  assert.match(vitestConfig, /configPath:\s*['"]\.\.\/wrangler\.toml['"]/);
});

test('CI dry-runs the deployable validation probe', () => {
  const workflow = readFileSync(
    new URL('../../.github/workflows/ci.yml', import.meta.url),
    'utf8',
  );
  assert.match(
    workflow,
    /- name: Wrangler dry-run — validation probe\s+working-directory: validation\/cloudflare-probe\s+run: node \.\.\/\.\.\/app\/node_modules\/wrangler\/bin\/wrangler\.js deploy --dry-run --config wrangler\.toml/,
  );
});
