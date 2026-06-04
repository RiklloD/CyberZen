import { describe, expect, it } from 'vitest'
import { type SensitiveFileRuleId, detectSensitiveFiles } from './sensitiveFileDetector'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ruleIds(paths: string[]): SensitiveFileRuleId[] {
  return detectSensitiveFiles(paths).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// PRIVATE_KEY_FILE rule
// ---------------------------------------------------------------------------

describe('PRIVATE_KEY_FILE rule', () => {
  it('fires on id_rsa', () => {
    expect(ruleIds(['id_rsa'])).toContain('PRIVATE_KEY_FILE')
  })

  it('fires on id_ed25519 in a directory', () => {
    expect(ruleIds(['.ssh/id_ed25519'])).toContain('PRIVATE_KEY_FILE')
  })

  it('fires on id_dsa', () => {
    expect(ruleIds(['keys/id_dsa'])).toContain('PRIVATE_KEY_FILE')
  })

  it('does not fire on id_rsa.pub (public key)', () => {
    // Public keys do not match because the pattern anchors to end-of-string
    expect(ruleIds(['id_rsa.pub'])).not.toContain('PRIVATE_KEY_FILE')
  })

  it('fires on Windows-style path with backslash', () => {
    expect(ruleIds(['.ssh\\id_ed25519'])).toContain('PRIVATE_KEY_FILE')
  })
})

// ---------------------------------------------------------------------------
// CERTIFICATE_FILE rule
// ---------------------------------------------------------------------------

describe('CERTIFICATE_FILE rule', () => {
  it('fires on *.pem', () => {
    expect(ruleIds(['certs/server.pem'])).toContain('CERTIFICATE_FILE')
  })

  it('fires on *.p12', () => {
    expect(ruleIds(['keychain.p12'])).toContain('CERTIFICATE_FILE')
  })

  it('fires on *.pfx', () => {
    expect(ruleIds(['export.pfx'])).toContain('CERTIFICATE_FILE')
  })

  it('fires on *.der and *.p8', () => {
    expect(ruleIds(['cert.der'])).toContain('CERTIFICATE_FILE')
    expect(ruleIds(['apns.p8'])).toContain('CERTIFICATE_FILE')
  })
})

// ---------------------------------------------------------------------------
// KEYSTORE_FILE rule
// ---------------------------------------------------------------------------

describe('KEYSTORE_FILE rule', () => {
  it('fires on *.jks', () => {
    expect(ruleIds(['android.jks'])).toContain('KEYSTORE_FILE')
  })

  it('fires on *.keystore', () => {
    expect(ruleIds(['release.keystore'])).toContain('KEYSTORE_FILE')
  })

  it('does not fire on random .txt file', () => {
    expect(ruleIds(['readme.txt'])).not.toContain('KEYSTORE_FILE')
  })
})

// ---------------------------------------------------------------------------
// AWS_CREDENTIALS rule
// ---------------------------------------------------------------------------

describe('AWS_CREDENTIALS rule', () => {
  it('fires on .aws/credentials', () => {
    expect(ruleIds(['.aws/credentials'])).toContain('AWS_CREDENTIALS')
  })

  it('fires on .aws/config', () => {
    expect(ruleIds(['.aws/config'])).toContain('AWS_CREDENTIALS')
  })

  it('does not fire on aws-sdk.js', () => {
    expect(ruleIds(['src/aws-sdk.js'])).not.toContain('AWS_CREDENTIALS')
  })
})

// ---------------------------------------------------------------------------
// CREDENTIAL_FILE rule
// ---------------------------------------------------------------------------

describe('CREDENTIAL_FILE rule', () => {
  it('fires on credentials.json', () => {
    expect(ruleIds(['credentials.json'])).toContain('CREDENTIAL_FILE')
  })

  it('fires on credentials.yml', () => {
    expect(ruleIds(['config/credentials.yml'])).toContain('CREDENTIAL_FILE')
  })

  it('fires on credential.toml (singular)', () => {
    expect(ruleIds(['credential.toml'])).toContain('CREDENTIAL_FILE')
  })

  it('does not fire on source-credentials-provider.ts', () => {
    expect(ruleIds(['src/source-credentials-provider.ts'])).not.toContain('CREDENTIAL_FILE')
  })
})

// ---------------------------------------------------------------------------
// WP_CONFIG rule
// ---------------------------------------------------------------------------

describe('WP_CONFIG rule', () => {
  it('fires on wp-config.php', () => {
    expect(ruleIds(['wp-config.php'])).toContain('WP_CONFIG')
  })

  it('fires on subdirectory', () => {
    expect(ruleIds(['wordpress/wp-config.php'])).toContain('WP_CONFIG')
  })

  it('does not fire on wp-config-sample.php', () => {
    // The pattern requires exact filename wp-config.php
    expect(ruleIds(['wp-config-sample.php'])).not.toContain('WP_CONFIG')
  })
})

// ---------------------------------------------------------------------------
// ENV_FILE rule
// ---------------------------------------------------------------------------

describe('ENV_FILE rule', () => {
  it('fires on bare .env', () => {
    expect(ruleIds(['.env'])).toContain('ENV_FILE')
  })

  it('fires on .env.local', () => {
    expect(ruleIds(['.env.local'])).toContain('ENV_FILE')
  })

  it('fires on .env.production', () => {
    expect(ruleIds(['apps/web/.env.production'])).toContain('ENV_FILE')
  })

  it('fires on .env.staging', () => {
    expect(ruleIds(['.env.staging'])).toContain('ENV_FILE')
  })

  it('does NOT fire on .env.example', () => {
    // .env.example is not matched by the pattern (only local/dev/development/etc)
    expect(ruleIds(['.env.example'])).not.toContain('ENV_FILE')
  })

  it('does NOT fire on .envrc (used by direnv)', () => {
    // .envrc is not in the suffix list
    expect(ruleIds(['.envrc'])).not.toContain('ENV_FILE')
  })
})

// ---------------------------------------------------------------------------
// SECRET_FILE rule
// ---------------------------------------------------------------------------

describe('SECRET_FILE rule', () => {
  it('fires on secrets.json', () => {
    expect(ruleIds(['secrets.json'])).toContain('SECRET_FILE')
  })

  it('fires on secret.yml', () => {
    expect(ruleIds(['config/secret.yml'])).toContain('SECRET_FILE')
  })
})

// ---------------------------------------------------------------------------
// DOCKER_CONFIG rule
// ---------------------------------------------------------------------------

describe('DOCKER_CONFIG rule', () => {
  it('fires on .docker/config.json', () => {
    expect(ruleIds(['.docker/config.json'])).toContain('DOCKER_CONFIG')
  })

  it('does not fire on docker-compose.yml', () => {
    expect(ruleIds(['docker-compose.yml'])).not.toContain('DOCKER_CONFIG')
  })
})

// ---------------------------------------------------------------------------
// NETRC_FILE rule
// ---------------------------------------------------------------------------

describe('NETRC_FILE rule', () => {
  it('fires on .netrc', () => {
    expect(ruleIds(['.netrc'])).toContain('NETRC_FILE')
  })

  it('fires on _netrc (Windows variant)', () => {
    expect(ruleIds(['_netrc'])).toContain('NETRC_FILE')
  })
})

// ---------------------------------------------------------------------------
// DATABASE_CONFIG rule
// ---------------------------------------------------------------------------

describe('DATABASE_CONFIG rule', () => {
  it('fires on database.yml', () => {
    expect(ruleIds(['config/database.yml'])).toContain('DATABASE_CONFIG')
  })

  it('fires on bare database.json', () => {
    expect(ruleIds(['database.json'])).toContain('DATABASE_CONFIG')
  })

  it('does not fire on database.ts (code file)', () => {
    expect(ruleIds(['src/database.ts'])).not.toContain('DATABASE_CONFIG')
  })
})

// ---------------------------------------------------------------------------
// SERVICE_ACCOUNT_KEY rule
// ---------------------------------------------------------------------------

describe('SERVICE_ACCOUNT_KEY rule', () => {
  it('fires on service_account_key.json', () => {
    expect(ruleIds(['service_account_key.json'])).toContain('SERVICE_ACCOUNT_KEY')
  })

  it('fires on gcp-key.json', () => {
    expect(ruleIds(['gcp-key.json'])).toContain('SERVICE_ACCOUNT_KEY')
  })

  it('fires on google-credentials.json', () => {
    expect(ruleIds(['google-credentials.json'])).toContain('SERVICE_ACCOUNT_KEY')
  })
})

// ---------------------------------------------------------------------------
// FIREBASE_CONFIG rule
// ---------------------------------------------------------------------------

describe('FIREBASE_CONFIG rule', () => {
  it('fires on google-services.json', () => {
    expect(ruleIds(['android/app/google-services.json'])).toContain('FIREBASE_CONFIG')
  })

  it('fires on GoogleService-Info.plist (iOS)', () => {
    expect(ruleIds(['ios/GoogleService-Info.plist'])).toContain('FIREBASE_CONFIG')
  })
})

// ---------------------------------------------------------------------------
// NPMRC_FILE rule
// ---------------------------------------------------------------------------

describe('NPMRC_FILE rule', () => {
  it('fires on .npmrc', () => {
    expect(ruleIds(['.npmrc'])).toContain('NPMRC_FILE')
  })

  it('fires on nested .npmrc', () => {
    expect(ruleIds(['packages/ui/.npmrc'])).toContain('NPMRC_FILE')
  })

  it('has severity=medium', () => {
    const result = detectSensitiveFiles(['.npmrc'])
    const finding = result.findings.find((f) => f.ruleId === 'NPMRC_FILE')
    expect(finding?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// DEBUG_ARTIFACT rule
// ---------------------------------------------------------------------------

describe('DEBUG_ARTIFACT rule', () => {
  it('fires on npm-debug.log', () => {
    expect(ruleIds(['npm-debug.log'])).toContain('DEBUG_ARTIFACT')
  })

  it('fires on .DS_Store', () => {
    expect(ruleIds(['.DS_Store'])).toContain('DEBUG_ARTIFACT')
  })

  it('fires on Thumbs.db', () => {
    expect(ruleIds(['Thumbs.db'])).toContain('DEBUG_ARTIFACT')
  })

  it('fires on yarn-error.log', () => {
    expect(ruleIds(['yarn-error.log'])).toContain('DEBUG_ARTIFACT')
  })

  it('has severity=low', () => {
    const result = detectSensitiveFiles(['.DS_Store'])
    const finding = result.findings.find((f) => f.ruleId === 'DEBUG_ARTIFACT')
    expect(finding?.severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Clean input
// ---------------------------------------------------------------------------

describe('clean file list', () => {
  it('returns riskScore=0 and riskLevel=none', () => {
    const result = detectSensitiveFiles(['src/index.ts', 'README.md', 'package.json'])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
    expect(result.totalFindings).toBe(0)
  })

  it('summary says no sensitive files', () => {
    const result = detectSensitiveFiles([])
    expect(result.summary).toMatch(/no sensitive files/i)
  })
})

// ---------------------------------------------------------------------------
// Scoring and riskLevel
// ---------------------------------------------------------------------------

describe('scoring and riskLevel', () => {
  it('single debug finding → riskScore=3, riskLevel=low', () => {
    const result = detectSensitiveFiles(['.DS_Store'])
    expect(result.riskScore).toBe(3)
    expect(result.riskLevel).toBe('low')
  })

  it('single .npmrc finding → riskScore=8, riskLevel=low', () => {
    const result = detectSensitiveFiles(['.npmrc'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })

  it('single .env finding → riskScore=15, riskLevel=low', () => {
    const result = detectSensitiveFiles(['.env'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('single critical finding → riskScore=30, riskLevel=medium', () => {
    const result = detectSensitiveFiles(['.aws/credentials'])
    expect(result.riskScore).toBe(30)
    expect(result.riskLevel).toBe('medium')
  })

  it('two critical findings → riskScore=60, riskLevel=high', () => {
    const result = detectSensitiveFiles(['.aws/credentials', 'credentials.json'])
    // 2 × 30 = 60, cap is 75 → 60, riskLevel: ≥50 = high
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })

  it('three critical findings → riskScore=75 (cap), riskLevel=critical', () => {
    const result = detectSensitiveFiles([
      '.aws/credentials',
      'credentials.json',
      'android.jks',
    ])
    // 3 × 30 = 90, capped at 75
    expect(result.riskScore).toBe(75)
    expect(result.riskLevel).toBe('critical')
  })

  it('compound: critical + high + medium + low sums correctly', () => {
    const result = detectSensitiveFiles([
      '.aws/credentials', // critical +30
      '.env', // high +15
      '.npmrc', // medium +8
      '.DS_Store', // low +3
    ])
    expect(result.riskScore).toBe(56)
    expect(result.riskLevel).toBe('high')
    expect(result.criticalCount).toBe(1)
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
  })

  it('totalFindings includes all per-rule matches', () => {
    const result = detectSensitiveFiles(['id_rsa', '.env', '.DS_Store'])
    expect(result.totalFindings).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('critical summary mentions "rotate credentials"', () => {
    const result = detectSensitiveFiles(['.aws/credentials'])
    expect(result.summary).toMatch(/rotate credentials/i)
  })

  it('high summary mentions risk level', () => {
    const result = detectSensitiveFiles(['.env', '.docker/config.json'])
    expect(result.summary).toMatch(/high-risk/i)
  })

  it('medium-only summary includes finding count', () => {
    const result = detectSensitiveFiles(['.npmrc'])
    expect(result.summary).toMatch(/1 sensitive file/i)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('path normalisation', () => {
  it('handles Windows backslash paths', () => {
    const result = detectSensitiveFiles(['.aws\\credentials'])
    expect(result.findings.map((f) => f.ruleId)).toContain('AWS_CREDENTIALS')
  })

  it('handles deeply nested paths', () => {
    const result = detectSensitiveFiles(['a/b/c/d/e/.env'])
    expect(result.findings.map((f) => f.ruleId)).toContain('ENV_FILE')
  })

  it('preserves original path in matchedPath', () => {
    const result = detectSensitiveFiles(['.aws\\credentials'])
    expect(result.findings[0].matchedPath).toBe('.aws\\credentials')
  })
})
