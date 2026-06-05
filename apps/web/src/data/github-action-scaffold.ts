// GitHub Actions marketplace scaffold content for CyberZen security scanning.

export const ACTION_YML = `name: 'CyberZen Security Scan'
description: 'Run CyberZen security scanning on your repository and gate CI on findings severity.'
author: 'CyberZen'

branding:
  icon: 'shield'
  color: 'blue'

inputs:
  api-key:
    description: 'CyberZen API key (store as a repository secret: CYBERZEN_API_KEY)'
    required: true

  workspace:
    description: 'CyberZen workspace slug (found in Settings > General)'
    required: true

  fail-on-severity:
    description: 'Minimum severity that causes the action to fail. One of: critical, high, medium, low, informational, none'
    required: false
    default: 'critical'

  repo:
    description: 'Repository full name to scan (defaults to the current repo)'
    required: false
    default: '\${{ github.repository }}'

  branch:
    description: 'Branch to scan (defaults to the triggering ref)'
    required: false
    default: '\${{ github.ref_name }}'

  timeout-minutes:
    description: 'Maximum minutes to wait for scan results before timing out'
    required: false
    default: '10'

outputs:
  findings-count:
    description: 'Total number of new findings detected in this scan'

  critical-count:
    description: 'Number of critical-severity findings'

  high-count:
    description: 'Number of high-severity findings'

  scan-url:
    description: 'URL to view full scan results in the CyberZen dashboard'

runs:
  using: 'composite'
  steps:
    - name: Run CyberZen scan
      shell: bash
      env:
        CYBERZEN_API_KEY: \${{ inputs.api-key }}
        CYBERZEN_WORKSPACE: \${{ inputs.workspace }}
        CYBERZEN_REPO: \${{ inputs.repo }}
        CYBERZEN_BRANCH: \${{ inputs.branch }}
        FAIL_ON_SEVERITY: \${{ inputs.fail-on-severity }}
        TIMEOUT_MINUTES: \${{ inputs.timeout-minutes }}
      run: \${{ github.action_path }}/entrypoint.sh
`

export const ENTRYPOINT_SH = `#!/usr/bin/env bash
set -euo pipefail

API_BASE="\${CYBERZEN_API_URL:-https://animated-viper-811.eu-west-1.convex.site}"
POLL_INTERVAL=15

echo "CyberZen Security Scan"
echo "Workspace: \${CYBERZEN_WORKSPACE}"
echo "Repository: \${CYBERZEN_REPO}"
echo "Branch: \${CYBERZEN_BRANCH}"
echo "Fail on severity: \${FAIL_ON_SEVERITY}"

# Trigger scan
RESPONSE=$(curl -sf -X POST "\${API_BASE}/api/repositories/scan" \\
  -H "X-Sentinel-Api-Key: \${CYBERZEN_API_KEY}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "workspace": "'"'\${CYBERZEN_WORKSPACE}'"'",
    "repository": "'"'\${CYBERZEN_REPO}'"'",
    "branch": "'"'\${CYBERZEN_BRANCH}'"'"
  }')

SCAN_ID=$(echo "\${RESPONSE}" | jq -r '.scanId')
SCAN_URL=$(echo "\${RESPONSE}" | jq -r '.url')

echo "Scan queued: \${SCAN_ID}"
echo "scan-url=\${SCAN_URL}" >> "\${GITHUB_OUTPUT}"

# Poll for results
ELAPSED=0
MAX_SECONDS=\$((TIMEOUT_MINUTES * 60))

while [ "\${ELAPSED}" -lt "\${MAX_SECONDS}" ]; do
  sleep "\${POLL_INTERVAL}"
  ELAPSED=\$((ELAPSED + POLL_INTERVAL))

  STATUS_RESP=$(curl -sf "\${API_BASE}/api/scans/\${SCAN_ID}" \\
    -H "X-Sentinel-Api-Key: \${CYBERZEN_API_KEY}")

  STATUS=$(echo "\${STATUS_RESP}" | jq -r '.status')

  if [ "\${STATUS}" = "completed" ]; then
    FINDINGS=$(echo "\${STATUS_RESP}" | jq -r '.findingsCount')
    CRITICAL=$(echo "\${STATUS_RESP}" | jq -r '.criticalCount')
    HIGH=$(echo "\${STATUS_RESP}" | jq -r '.highCount')

    echo "findings-count=\${FINDINGS}" >> "\${GITHUB_OUTPUT}"
    echo "critical-count=\${CRITICAL}" >> "\${GITHUB_OUTPUT}"
    echo "high-count=\${HIGH}" >> "\${GITHUB_OUTPUT}"

    echo ""
    echo "Scan complete: \${FINDINGS} findings (\${CRITICAL} critical, \${HIGH} high)"
    echo "View results: \${SCAN_URL}"

    # Gate on severity
    case "\${FAIL_ON_SEVERITY}" in
      critical) [ "\${CRITICAL}" -eq 0 ] || { echo "FAILED: \${CRITICAL} critical findings detected."; exit 1; } ;;
      high)     [ "\$((\${CRITICAL} + \${HIGH}))" -eq 0 ] || { echo "FAILED: critical or high findings detected."; exit 1; } ;;
      none)     ;;
    esac

    exit 0
  fi

  echo "[\${ELAPSED}s] Scan status: \${STATUS}..."
done

echo "Timed out waiting for scan results after \${TIMEOUT_MINUTES} minutes."
exit 1
`

export const README_MD = `# CyberZen Security Scan — GitHub Action

[![CyberZen](https://img.shields.io/badge/security-CyberZen-blue)](https://cyberzen.dev)

Integrate CyberZen's AI-powered security scanning directly into your GitHub Actions CI/CD pipeline. Gate pull requests on security findings, track vulnerability trends, and get developer education inline.

## Quick Start

\`\`\`yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: CyberZen Security Scan
        uses: cyberzen/scan-action@v1
        with:
          api-key: \${{ secrets.CYBERZEN_API_KEY }}
          workspace: my-workspace
          fail-on-severity: high
\`\`\`

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| \`api-key\` | Yes | — | CyberZen API key (store as \`CYBERZEN_API_KEY\` secret) |
| \`workspace\` | Yes | — | CyberZen workspace slug |
| \`fail-on-severity\` | No | \`critical\` | Minimum severity to fail CI (\`critical\`, \`high\`, \`medium\`, \`low\`, \`none\`) |
| \`repo\` | No | current repo | Repository full name to scan |
| \`branch\` | No | current branch | Branch to scan |
| \`timeout-minutes\` | No | \`10\` | Minutes to wait for results |

## Outputs

| Output | Description |
|--------|-------------|
| \`findings-count\` | Total new findings detected |
| \`critical-count\` | Number of critical-severity findings |
| \`high-count\` | Number of high-severity findings |
| \`scan-url\` | Link to full results in CyberZen dashboard |

## Status Badge

Add to your README to show real-time security posture:

\`\`\`markdown
[![Security](https://api.cyberzen.dev/badge/{workspace}/{repo})](https://app.cyberzen.dev/{workspace})
\`\`\`

## Setup Guide

1. Go to **Settings > API Keys** in CyberZen and create a new key with \`repositories:write\` and \`findings:read\` scopes.
2. Add the key as a GitHub Actions secret named \`CYBERZEN_API_KEY\`.
3. Find your workspace slug in **Settings > General**.
4. Add the workflow YAML shown above to \`.github/workflows/security.yml\`.

## License

MIT
`
