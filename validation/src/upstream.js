import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url));

export const PINNED_UPSTREAM = Object.freeze({
  server: '52a5feb7fac38f68da5afef9cedd9b3bfc8473ca',
  desktop: '3772337dd3e435b6269297f9db8f65959f8abe89',
});

const REPOSITORIES = Object.freeze({
  server: `${workspaceRoot}/.research-cache/tproxy-server`,
  desktop: `${workspaceRoot}/.research-cache/tdesktop`,
});

export function readPinnedSource(repository, sourcePath) {
  const repoPath = REPOSITORIES[repository];
  const commit = PINNED_UPSTREAM[repository];
  if (!repoPath || !commit) {
    throw new Error(`Unknown pinned repository: ${repository}`);
  }

  return execFileSync(
    'git',
    ['-C', repoPath, 'show', `${commit}:${sourcePath}`],
    { encoding: 'utf8' },
  );
}
