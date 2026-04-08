import { describe, expect, it } from 'vitest'
import {
  collectChangedFiles,
  normalizeGithubPushPayload,
  type GithubPushPayload,
} from './githubWebhooks'

describe('collectChangedFiles', () => {
  it('deduplicates added, modified, and removed paths in commit order', () => {
    expect(
      collectChangedFiles([
        {
          added: ['package.json', 'README.md'],
          modified: ['src/index.ts'],
        },
        {
          modified: ['README.md', 'src/index.ts'],
          removed: ['docs/old.md'],
        },
      ]),
    ).toEqual(['package.json', 'README.md', 'src/index.ts', 'docs/old.md'])
  })
})

describe('normalizeGithubPushPayload', () => {
  it('normalizes a branch push into ingestion args', () => {
    const payload: GithubPushPayload = {
      ref: 'refs/heads/main',
      after: 'abc123def456',
      repository: {
        full_name: 'atlas-fintech/payments-api',
      },
      commits: [
        {
          added: ['requirements.txt'],
          modified: ['services/auth/jwt.py'],
          removed: ['docs/legacy.md'],
        },
      ],
    }

    expect(normalizeGithubPushPayload(payload)).toEqual({
      status: 'processed',
      repositoryFullName: 'atlas-fintech/payments-api',
      branch: 'main',
      commitSha: 'abc123def456',
      changedFiles: [
        'requirements.txt',
        'services/auth/jwt.py',
        'docs/legacy.md',
      ],
    })
  })

  it('ignores branch deletions', () => {
    expect(
      normalizeGithubPushPayload({
        ref: 'refs/heads/main',
        after: '0000000000000000000000000000000000000000',
        deleted: true,
        repository: {
          full_name: 'atlas-fintech/payments-api',
        },
      }),
    ).toEqual({
      status: 'ignored',
      reason: 'Branch main was deleted, so no workflow run was created.',
    })
  })

  it('ignores non-branch refs such as tags', () => {
    expect(
      normalizeGithubPushPayload({
        ref: 'refs/tags/v1.0.0',
        after: 'abc123def456',
        repository: {
          full_name: 'atlas-fintech/payments-api',
        },
      }),
    ).toEqual({
      status: 'ignored',
      reason: 'Only branch push events are routed into workflow ingestion.',
    })
  })

  it('rejects payloads missing repository identity', () => {
    expect(
      normalizeGithubPushPayload({
        ref: 'refs/heads/main',
        after: 'abc123def456',
      }),
    ).toEqual({
      status: 'rejected',
      reason: 'GitHub push payload is missing repository.full_name.',
    })
  })
})
