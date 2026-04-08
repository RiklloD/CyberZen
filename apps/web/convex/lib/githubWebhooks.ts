export type GithubPushPayload = {
  after?: string
  deleted?: boolean
  ref?: string
  repository?: {
    full_name?: string
  }
  commits?: Array<{
    added?: string[]
    modified?: string[]
    removed?: string[]
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
