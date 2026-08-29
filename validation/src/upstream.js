import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url));

export const PINNED_UPSTREAM = Object.freeze({
  server: '52a5feb7fac38f68da5afef9cedd9b3bfc8473ca',
  desktop: '3772337dd3e435b6269297f9db8f65959f8abe89',
});

const REPOSITORIES = Object.freeze({
  server: join(workspaceRoot, '.research-cache', 'tproxy-server'),
  desktop: join(workspaceRoot, '.research-cache', 'tdesktop'),
});

export async function readPinnedSource(repository, sourcePath) {
  const repoPath = REPOSITORIES[repository];
  const commit = PINNED_UPSTREAM[repository];
  if (!repoPath || !commit) {
    throw new Error(`Unknown pinned repository: ${repository}`);
  }

  if (existsSync(join(repoPath, '.git'))) {
    return execFileSync(
      'git',
      ['-C', repoPath, 'show', `${commit}:${sourcePath}`],
      { encoding: 'utf8' },
    );
  }
  const owner = repository === 'server' ? 'telegramdesktop/tproxy-server' : 'telegramdesktop/tdesktop';
  const url = `https://raw.githubusercontent.com/${owner}/${commit}/${sourcePath}`;
  const response = await fetch(url, {
    headers: { 'User-Agent': 'Telegram-WEB-Proxy-validation/1.0' },
  });
  if (!response.ok) throw new Error(`Unable to fetch pinned source: ${response.status} ${url}`);
  return response.text();
}
