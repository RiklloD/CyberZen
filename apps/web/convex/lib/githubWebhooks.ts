export type GithubPushPayload = {
  after?: string
  deleted?: boolean
  ref?: string
  repository?: {
    full_name?: string
  }
  head_commit?: {
    message?: string
  }
  commits?: Array<{
    added?: string[]
    modified?: string[]
    removed?: string[]
    message?: string
  }>
}

export type NormalizedGithubPushPayload =
  | {
      status: 'processed'
      repositoryFullName: string
      branch: string
      commitSha: string
      changedFiles: string[]
    }
  | {
      status: 'ignored'
      reason: string
    }
  | {
      status: 'rejected'
      reason: string
    }

function normalizeRefBranch(ref: string | undefined) {
  if (!ref) {
    return null
  }

  if (!ref.startsWith('refs/heads/')) {
    return null
  }

  return ref.slice('refs/heads/'.length)
}

/**
 * Collect all unique commit messages from a push payload.
 * head_commit.message is preferred as the canonical lead message; per-commit
 * messages are appended de-duplicated. Returns an empty string when no
 * messages are present (caller should skip the scan in that case).
 */
export function collectCommitMessages(
  commits: GithubPushPayload['commits'] = [],
  headCommit?: GithubPushPayload['head_commit'],
): string {
  const seen = new Set<string>()
  const messages: string[] = []

  const push = (msg: string | null | undefined) => {
    const trimmed = msg?.trim()
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed)
      messages.push(trimmed)
    }
  }

  push(headCommit?.message)
  for (const commit of commits) {
    push(commit?.message)
  }

  return messages.join('\n\n')
}

export function collectChangedFiles(
  commits: GithubPushPayload['commits'] = [],
): string[] {
  const changedFiles = new Set<string>()

  for (const commit of commits) {
    for (const path of commit?.added ?? []) {
      changedFiles.add(path)
    }
    for (const path of commit?.modified ?? []) {
      changedFiles.add(path)
    }
    for (const path of commit?.removed ?? []) {
      changedFiles.add(path)
    }
  }

  return [...changedFiles]
}

export function normalizeGithubPushPayload(
  payload: GithubPushPayload,
): NormalizedGithubPushPayload {
  const repositoryFullName = payload.repository?.full_name?.trim()

  if (!repositoryFullName) {
    return {
      status: 'rejected',
      reason: 'GitHub push payload is missing repository.full_name.',
    }
  }

  const branch = normalizeRefBranch(payload.ref)

  if (!branch) {
    return {
      status: 'ignored',
      reason: 'Only branch push events are routed into workflow ingestion.',
    }
  }

  if (payload.deleted) {
    return {
      status: 'ignored',
      reason: `Branch ${branch} was deleted, so no workflow run was created.`,
    }
  }

  const commitSha = payload.after?.trim()

  if (!commitSha || /^0+$/.test(commitSha)) {
    return {
      status: 'ignored',
      reason: `Branch ${branch} does not point at a new commit SHA.`,
    }
  }

  return {
    status: 'processed',
    repositoryFullName,
    branch,
    commitSha,
    changedFiles: collectChangedFiles(payload.commits),
  }
}
