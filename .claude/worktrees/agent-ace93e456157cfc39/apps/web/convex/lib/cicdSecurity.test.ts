/// <reference types="vite/client" />
// WS-35 — CI/CD Pipeline Security Scanner: unit tests.

import { describe, expect, test } from 'vitest'
import {
  combineCicdResults,
  detectCicdFileType,
  scanCicdFile,
} from './cicdSecurity'

// ---------------------------------------------------------------------------
// detectCicdFileType
// ---------------------------------------------------------------------------

describe('detectCicdFileType', () => {
  test('identifies GitHub Actions workflow by path', () => {
    expect(detectCicdFileType('.github/workflows/ci.yml')).toBe('github_actions')
  })

  test('identifies GitHub Actions workflow with .yaml extension', () => {
    expect(detectCicdFileType('.github/workflows/release.yaml')).toBe('github_actions')
  })

  test('identifies GitHub Actions in nested path', () => {
    expect(detectCicdFileType('repo/.github/workflows/deploy.yml')).toBe('github_actions')
  })

  test('identifies GitLab CI', () => {
    expect(detectCicdFileType('.gitlab-ci.yml')).toBe('gitlab_ci')
  })

  test('identifies GitLab CI with .yaml extension', () => {
    expect(detectCicdFileType('.gitlab-ci.yaml')).toBe('gitlab_ci')
  })

  test('identifies CircleCI config', () => {
    expect(detectCicdFileType('.circleci/config.yml')).toBe('circleci')
  })

  test('identifies CircleCI config with .yaml extension', () => {
    expect(detectCicdFileType('.circleci/config.yaml')).toBe('circleci')
  })

  test('identifies Bitbucket Pipelines', () => {
    expect(detectCicdFileType('bitbucket-pipelines.yml')).toBe('bitbucket_pipelines')
  })

  test('identifies Bitbucket Pipelines with .yaml extension', () => {
    expect(detectCicdFileType('bitbucket-pipelines.yaml')).toBe('bitbucket_pipelines')
  })

  test('returns unknown for a plain YAML file', () => {
    expect(detectCicdFileType('config/app.yml')).toBe('unknown')
  })

  test('returns unknown for a Terraform file', () => {
    expect(detectCicdFileType('main.tf')).toBe('unknown')
  })

  test('handles Windows-style path separators', () => {
    expect(detectCicdFileType('.github\\workflows\\ci.yml')).toBe('github_actions')
  })
})

// ---------------------------------------------------------------------------
// GitHub Actions rules
// ---------------------------------------------------------------------------

// Helper: \x24 = '$' — avoids esbuild choking on ${{ inside template literals
const GH_EXPR = (expr: string) => `\x24{{ ${expr} }}`

describe('GHACTIONS_SCRIPT_INJECTION', () => {
  test('detects event payload in run step', () => {
    const content = `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${GH_EXPR('github.event.issue.title')}"
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_SCRIPT_INJECTION')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects head_ref injection', () => {
    const content = `steps:\n  - run: git checkout ${GH_EXPR('github.head_ref')}`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_SCRIPT_INJECTION')).toBe(true)
  })

  test('does not trigger on safe env-var indirection', () => {
    const content = `
steps:
  - env:
      TITLE: ${GH_EXPR('github.event.pull_request.title')}
    run: echo "$TITLE"
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_SCRIPT_INJECTION')).toBe(false)
  })
})

describe('GHACTIONS_PULL_REQUEST_TARGET', () => {
  test('detects pull_request_target trigger', () => {
    const content = `
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_PULL_REQUEST_TARGET')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('does not trigger on plain pull_request', () => {
    const content = `on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_PULL_REQUEST_TARGET')).toBe(false)
  })
})

describe('GHACTIONS_UNPINNED_ACTION', () => {
  test('detects tag-pinned action', () => {
    const content = `steps:\n  - uses: actions/checkout@v4`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_UNPINNED_ACTION')).toBe(true)
    expect(result.mediumCount).toBeGreaterThan(0)
  })

  test('does not trigger on SHA-pinned action', () => {
    const content = `steps:\n  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_UNPINNED_ACTION')).toBe(false)
  })

  test('detects branch-pinned action', () => {
    const content = `steps:\n  - uses: actions/checkout@main`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_UNPINNED_ACTION')).toBe(true)
  })
})

describe('GHACTIONS_EXCESSIVE_PERMISSIONS', () => {
  test('detects write-all permissions', () => {
    const content = `permissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_EXCESSIVE_PERMISSIONS')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('does not trigger on restricted permissions', () => {
    const content = `permissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_EXCESSIVE_PERMISSIONS')).toBe(false)
  })
})

describe('GHACTIONS_SECRETS_IN_LOGGING', () => {
  test('detects echo of secret', () => {
    const content = `steps:\n  - run: echo ${GH_EXPR('secrets.MY_TOKEN')}`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_SECRETS_IN_LOGGING')).toBe(true)
  })
})

describe('GHACTIONS_SELF_HOSTED_RUNNER', () => {
  test('detects self-hosted runner', () => {
    const content = `jobs:\n  build:\n    runs-on: self-hosted`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_SELF_HOSTED_RUNNER')).toBe(true)
    expect(result.mediumCount).toBeGreaterThan(0)
  })

  test('does not trigger on ubuntu-latest runner', () => {
    const content = `jobs:\n  build:\n    runs-on: ubuntu-latest`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GHACTIONS_SELF_HOSTED_RUNNER')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// GitLab CI rules
// ---------------------------------------------------------------------------

describe('GITLAB_DIND_PRIVILEGED', () => {
  test('detects privileged: true in GitLab CI', () => {
    const content = `
build:
  image: docker:24
  services:
    - name: docker:dind
      privileged: true
  script:
    - docker build .
`
    const result = scanCicdFile('.gitlab-ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GITLAB_DIND_PRIVILEGED')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })
})

describe('GITLAB_CURL_BASH_PIPE', () => {
  test('detects curl | bash in GitLab script', () => {
    const content = `
install:
  script:
    - curl -s https://example.com/install.sh | bash
`
    const result = scanCicdFile('.gitlab-ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GITLAB_CURL_BASH_PIPE')).toBe(true)
  })

  test('detects wget | sh variant', () => {
    const content = `
setup:
  script:
    - wget -qO- https://example.com/setup.sh | sh
`
    const result = scanCicdFile('.gitlab-ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GITLAB_CURL_BASH_PIPE')).toBe(true)
  })
})

describe('GITLAB_UNVERIFIED_IMAGE', () => {
  test('detects tag-based image reference', () => {
    const content = `image: node:18\njob:\n  script:\n    - npm test`
    const result = scanCicdFile('.gitlab-ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GITLAB_UNVERIFIED_IMAGE')).toBe(true)
  })

  test('does not trigger on digest-pinned image', () => {
    const content = `image: node@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\njob:\n  script:\n    - npm test`
    const result = scanCicdFile('.gitlab-ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'GITLAB_UNVERIFIED_IMAGE')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// CircleCI rules
// ---------------------------------------------------------------------------

describe('CIRCLE_CURL_BASH_PIPE', () => {
  test('detects curl | bash in CircleCI run step', () => {
    const content = `
jobs:
  build:
    steps:
      - run: curl -sSL https://install.python-poetry.org | bash
`
    const result = scanCicdFile('.circleci/config.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CIRCLE_CURL_BASH_PIPE')).toBe(true)
  })
})

describe('CIRCLE_MACHINE_LATEST_IMAGE', () => {
  test('detects machine executor with :latest image', () => {
    const content = `
jobs:
  build:
    machine:
      image: cimg/base:latest
    steps:
      - run: echo hello
`
    const result = scanCicdFile('.circleci/config.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CIRCLE_MACHINE_LATEST_IMAGE')).toBe(true)
  })

  test('does not trigger on versioned machine image', () => {
    const content = `
jobs:
  build:
    machine:
      image: ubuntu-2204:2023.10.1
    steps:
      - run: echo hello
`
    const result = scanCicdFile('.circleci/config.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CIRCLE_MACHINE_LATEST_IMAGE')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Bitbucket Pipelines rules
// ---------------------------------------------------------------------------

describe('BB_PRIVILEGED_PIPELINE', () => {
  test('detects privileged: true in Bitbucket step', () => {
    const content = `
pipelines:
  default:
    - step:
        privileged: true
        script:
          - docker build .
`
    const result = scanCicdFile('bitbucket-pipelines.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'BB_PRIVILEGED_PIPELINE')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })
})

describe('BB_CURL_BASH_PIPE', () => {
  test('detects curl | bash in Bitbucket script', () => {
    const content = `
pipelines:
  default:
    - step:
        script:
          - curl https://example.com/setup.sh | bash
`
    const result = scanCicdFile('bitbucket-pipelines.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'BB_CURL_BASH_PIPE')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Cross-platform rules
// ---------------------------------------------------------------------------

describe('CI_INLINE_SECRET', () => {
  test('detects hardcoded API_KEY in GitHub Actions env', () => {
    const content = `
jobs:
  build:
    env:
      API_KEY: s3cr3tv4luehere
    runs-on: ubuntu-latest
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CI_INLINE_SECRET')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('does not trigger on variable reference', () => {
    const content = `
jobs:
  build:
    env:
      API_KEY: ${GH_EXPR('secrets.MY_API_KEY')}
    runs-on: ubuntu-latest
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CI_INLINE_SECRET')).toBe(false)
  })

  test('detects hardcoded PASSWORD in GitLab CI', () => {
    const content = `
variables:
  PASSWORD: mysupersecretpass
build:
  script:
    - echo deploy
`
    const result = scanCicdFile('.gitlab-ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CI_INLINE_SECRET')).toBe(true)
  })
})

describe('CI_MISSING_TIMEOUT', () => {
  test('fires when no timeout is configured in GitHub Actions', () => {
    const content = `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CI_MISSING_TIMEOUT')).toBe(true)
    expect(result.lowCount).toBeGreaterThan(0)
  })

  test('does not fire when timeout-minutes is set', () => {
    const content = `
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - run: npm test
`
    const result = scanCicdFile('.github/workflows/ci.yml', content)
    expect(result.findings.some((f) => f.ruleId === 'CI_MISSING_TIMEOUT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// unknown file type
// ---------------------------------------------------------------------------

describe('unknown file type', () => {
  test('returns no findings for an unrecognised file', () => {
    const content = `curl https://example.com | bash`
    const result = scanCicdFile('random-file.yml', content)
    expect(result.fileType).toBe('unknown')
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// combineCicdResults
// ---------------------------------------------------------------------------

describe('combineCicdResults', () => {
  test('returns none risk for empty array', () => {
    const summary = combineCicdResults([])
    expect(summary.overallRisk).toBe('none')
    expect(summary.totalFiles).toBe(0)
    expect(summary.totalFindings).toBe(0)
  })

  test('returns none risk when no findings', () => {
    const result = scanCicdFile('.github/workflows/ci.yml', `
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`)
    const summary = combineCicdResults([result])
    expect(summary.overallRisk).toBe('none')
    expect(summary.totalFindings).toBe(0)
  })

  test('promotes risk to critical when any critical finding exists', () => {
    const r1 = scanCicdFile('.github/workflows/ci.yml', `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${GH_EXPR('github.event.issue.title')}"
`)
    const summary = combineCicdResults([r1])
    expect(summary.overallRisk).toBe('critical')
  })

  test('aggregates counts across multiple files', () => {
    const r1 = scanCicdFile('.github/workflows/ci.yml', `
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
`)
    const r2 = scanCicdFile('.gitlab-ci.yml', `
variables:
  PASSWORD: hardcoded
build:
  script:
    - npm test
`)
    const summary = combineCicdResults([r1, r2])
    expect(summary.totalFiles).toBe(2)
    expect(summary.totalFindings).toBeGreaterThan(2)
  })

  test('summary string mentions critical count', () => {
    const r1 = scanCicdFile('bitbucket-pipelines.yml', `
pipelines:
  default:
    - step:
        privileged: true
        script:
          - echo hi
`)
    const summary = combineCicdResults([r1])
    expect(summary.summary).toMatch(/critical/)
  })

  test('summary string is clean for zero findings', () => {
    const summary = combineCicdResults([])
    expect(summary.summary).toMatch(/No CI\/CD/)
  })

  test('summary mentions file count when findings exist', () => {
    const r1 = scanCicdFile('.github/workflows/ci.yml', `permissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest`)
    const summary = combineCicdResults([r1])
    expect(summary.summary).toMatch(/1 CI\/CD file/)
  })
})
