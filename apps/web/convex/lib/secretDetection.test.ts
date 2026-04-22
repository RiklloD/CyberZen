// WS-30 — Hardcoded Credential & Secret Detection Engine: unit tests
/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  combineResults,
  isLikelyPlaceholder,
  isTestFile,
  redactMatch,
  scanForSecrets,
  shannonEntropy,
} from './secretDetection'

// ---------------------------------------------------------------------------
// isLikelyPlaceholder
// ---------------------------------------------------------------------------

describe('isLikelyPlaceholder', () => {
  it('returns true for template variable ${...}', () => {
    expect(isLikelyPlaceholder('${OPENAI_API_KEY}')).toBe(true)
  })

  it('returns true for YOUR_ prefixed strings', () => {
    expect(isLikelyPlaceholder('YOUR_API_KEY')).toBe(true)
  })

  it('returns true for <...> placeholder', () => {
    expect(isLikelyPlaceholder('<MY_SECRET>')).toBe(true)
  })

  it('returns true for changeme', () => {
    expect(isLikelyPlaceholder('changeme')).toBe(true)
  })

  it('returns true for all-same-character strings', () => {
    expect(isLikelyPlaceholder('xxxxxxxxxxxxxxxxxxxxxxxx')).toBe(true)
    expect(isLikelyPlaceholder('aaaaaaaaaaaaaaaa')).toBe(true)
  })

  it('returns true for EXAMPLE_ prefixed strings', () => {
    expect(isLikelyPlaceholder('EXAMPLE_SECRET_TOKEN')).toBe(true)
  })

  it('returns false for real-looking keys', () => {
    expect(isLikelyPlaceholder('sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx')).toBe(false)
  })

  it('returns false for real GitHub token format', () => {
    expect(isLikelyPlaceholder('ghp_abcdefghijklmnopqrstuvwxyz123456ABCD')).toBe(false)
  })

  it('returns true for empty string', () => {
    expect(isLikelyPlaceholder('')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// redactMatch
// ---------------------------------------------------------------------------

describe('redactMatch', () => {
  it('redacts long strings: first 4 + *** + last 4', () => {
    const result = redactMatch('AKIAIOSFODNN7EXAMPLE')
    expect(result).toBe('AKIA***MPLE')
  })

  it('returns partial redaction for short strings (≤ 12 chars)', () => {
    const result = redactMatch('sk-ab12ef')
    expect(result).toContain('***')
    expect(result.length).toBeLessThan(10)
  })

  it('trims whitespace before redacting', () => {
    const result = redactMatch('  AKIAIOSFODNN7EXAMPLE  ')
    expect(result).toBe('AKIA***MPLE')
  })

  it('handles exactly-12-char string as short', () => {
    const result = redactMatch('abcdefghijkl')
    expect(result).toBe('abcd***')
  })
})

// ---------------------------------------------------------------------------
// shannonEntropy
// ---------------------------------------------------------------------------

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0)
  })

  it('returns 0 for all-same-character string', () => {
    expect(shannonEntropy('aaaaaaaaaa')).toBe(0)
  })

  it('returns ~1 for two perfectly alternating chars', () => {
    const e = shannonEntropy('ababababababab')
    expect(e).toBeCloseTo(1.0, 1)
  })

  it('returns entropy < 3 for dictionary word', () => {
    expect(shannonEntropy('password')).toBeLessThan(3)
  })

  it('returns entropy > 4 for random-looking key-like string', () => {
    // Simulated random API key with mixed chars
    const key = 'A3bF9kQpZ7mR2xW0cY6vN1hJ8oL4uI5sT'
    expect(shannonEntropy(key)).toBeGreaterThan(4.0)
  })
})

// ---------------------------------------------------------------------------
// isTestFile
// ---------------------------------------------------------------------------

describe('isTestFile', () => {
  it('detects .test.ts files', () => {
    expect(isTestFile('src/auth/auth.test.ts')).toBe(true)
  })

  it('detects .spec.ts files', () => {
    expect(isTestFile('auth.spec.ts')).toBe(true)
  })

  it('detects __tests__ directories', () => {
    expect(isTestFile('src/__tests__/api.ts')).toBe(true)
  })

  it('detects fixture paths', () => {
    expect(isTestFile('tests/fixtures/sample.ts')).toBe(true)
  })

  it('returns false for regular source files', () => {
    expect(isTestFile('src/api/auth.ts')).toBe(false)
  })

  it('returns false for files that happen to contain "test" in their name', () => {
    expect(isTestFile('src/attest.ts')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Pattern-based detectors
// ---------------------------------------------------------------------------

describe('AWS credential detection', () => {
  it('detects AWS Access Key ID', () => {
    const result = scanForSecrets('const key = "AKIAIOSFODNN7EXAMPLE"')
    const finding = result.findings.find((f) => f.category === 'aws_credential')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('critical')
  })

  it('detects AWS secret access key assignment', () => {
    const result = scanForSecrets(
      'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    )
    const finding = result.findings.find((f) => f.category === 'aws_credential')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('critical')
  })

  it('does NOT flag AKIA placeholder', () => {
    const result = scanForSecrets('const key = "AKIAYOURKEYGOESHERE"')
    // All-same-char check won't fire here; let's check a real placeholder
    expect(result.findings.filter((f) => f.category === 'aws_credential')).toHaveLength(0)
  })
})

describe('GitHub token detection', () => {
  it('detects classic GitHub PAT (ghp_)', () => {
    const token = 'ghp_' + 'A'.repeat(36)
    const result = scanForSecrets(`const token = "${token}"`)
    const finding = result.findings.find((f) => f.category === 'github_token')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('critical')
  })

  it('detects GitHub OAuth token (gho_)', () => {
    const token = 'gho_' + 'B'.repeat(36)
    const result = scanForSecrets(`token: "${token}"`)
    const finding = result.findings.find((f) => f.category === 'github_token')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('critical')
  })

  it('detects GitHub Actions token (ghs_) as high severity', () => {
    const token = 'ghs_' + 'C'.repeat(36)
    const result = scanForSecrets(token)
    const finding = result.findings.find((f) => f.category === 'github_token')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('high')
  })
})

describe('Private key detection', () => {
  it('detects RSA PRIVATE KEY header', () => {
    const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...'
    const result = scanForSecrets(content)
    const finding = result.findings.find((f) => f.category === 'private_key')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('critical')
  })

  it('detects OPENSSH PRIVATE KEY header', () => {
    const content = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...'
    const result = scanForSecrets(content)
    expect(result.findings.some((f) => f.category === 'private_key')).toBe(true)
  })
})

describe('OpenAI key detection', () => {
  it('detects OpenAI API key format', () => {
    const key = 'sk-' + 'a'.repeat(48)
    const result = scanForSecrets(`OPENAI_API_KEY="${key}"`)
    expect(result.findings.some((f) => f.category === 'openai_key')).toBe(true)
  })

  it('does NOT flag Stripe key as OpenAI (different prefix)', () => {
    const result = scanForSecrets('const key = "FAKE_STRIPE_LIVE"')
    // Stripe key should be caught by stripe_key, not openai_key
    expect(result.findings.some((f) => f.category === 'stripe_key')).toBe(true)
    expect(result.findings.some((f) => f.category === 'openai_key')).toBe(false)
  })
})

describe('Stripe key detection', () => {
  it('detects Stripe live secret key as critical', () => {
    const result = scanForSecrets('stripeKey = "FAKE_STRIPE_LIVE_LONG"')
    const finding = result.findings.find((f) => f.category === 'stripe_key')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('critical')
  })

  it('detects Stripe test secret key as high', () => {
    const result = scanForSecrets('stripeKey = "FAKE_STRIPE_TEST_LONG"')
    const finding = result.findings.find((f) => f.category === 'stripe_key')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('high')
  })
})

describe('Database URL detection', () => {
  it('detects PostgreSQL URL with credentials', () => {
    const result = scanForSecrets(
      'DATABASE_URL="postgresql://admin:sup3rs3cret@prod-db.company.com:5432/app"',
    )
    const finding = result.findings.find((f) => f.category === 'database_url')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('high')
  })

  it('detects MongoDB connection string with credentials', () => {
    const result = scanForSecrets(
      'MONGO_URI="mongodb+srv://user:passw0rd@cluster.mongodb.net/db"',
    )
    const finding = result.findings.find((f) => f.category === 'database_url')
    expect(finding).toBeDefined()
  })

  it('does NOT flag DB URLs without a password (no colon-at pattern)', () => {
    // URL without credentials section
    const result = scanForSecrets('pg_url = "postgresql://localhost:5432/mydb"')
    expect(result.findings.filter((f) => f.category === 'database_url')).toHaveLength(0)
  })
})

describe('Hardcoded password detection', () => {
  it('detects password = "..." assignment', () => {
    const result = scanForSecrets('const password = "superS3cret!"')
    expect(result.findings.some((f) => f.category === 'hardcoded_password')).toBe(true)
  })

  it('does NOT flag short or obviously placeholder passwords', () => {
    const result = scanForSecrets('password = "${DB_PASSWORD}"')
    expect(result.findings.some((f) => f.category === 'hardcoded_password')).toBe(false)
  })
})

describe('Slack token detection', () => {
  it('detects Slack bot token', () => {
    const token = 'FAKE_SLACK_BOT'
    const result = scanForSecrets(`SLACK_TOKEN = "${token}"`)
    expect(result.findings.some((f) => f.category === 'communication_key')).toBe(true)
  })
})

describe('SendGrid key detection', () => {
  it('detects SendGrid API key', () => {
    const key = 'SG.' + 'a'.repeat(22) + '.' + 'b'.repeat(43)
    const result = scanForSecrets(`SENDGRID_API_KEY="${key}"`)
    expect(result.findings.some((f) => f.category === 'sendgrid_key')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Test-file hint
// ---------------------------------------------------------------------------

describe('test-file hint', () => {
  it('marks findings from test files with isTestFileHint=true', () => {
    const token = 'ghp_' + 'X'.repeat(36)
    const result = scanForSecrets(`const token = "${token}"`, 'auth.test.ts')
    const finding = result.findings[0]
    expect(finding).toBeDefined()
    expect(finding.isTestFileHint).toBe(true)
  })

  it('marks findings from production files with isTestFileHint=false', () => {
    const token = 'ghp_' + 'Y'.repeat(36)
    const result = scanForSecrets(`const token = "${token}"`, 'src/auth.ts')
    expect(result.findings[0]?.isTestFileHint).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Placeholder exclusion
// ---------------------------------------------------------------------------

describe('placeholder exclusion', () => {
  it('does not flag ${GITHUB_TOKEN} template variable', () => {
    const result = scanForSecrets('const t = "${GITHUB_TOKEN}"')
    expect(result.findings.length).toBe(0)
  })

  it('does not flag YOUR_API_KEY placeholder', () => {
    const result = scanForSecrets('api_key = "YOUR_API_KEY_HERE"')
    expect(result.findings.length).toBe(0)
  })

  it('does not flag changeme password', () => {
    const result = scanForSecrets('password: "changeme"')
    expect(result.findings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Entropy-based detection
// ---------------------------------------------------------------------------

describe('entropy-based detection', () => {
  it('detects high-entropy quoted string', () => {
    // Simulated random-looking API key not matching any known pattern
    const randomKey = '"Xk9qLmNpRsT3vWuYjZa0BcDe1FgHhIiJk"'
    const result = scanForSecrets(`unknown_credential = ${randomKey}`)
    // Should detect via entropy
    expect(result.findings.length).toBeGreaterThan(0)
  })

  it('does NOT flag a UUID as high-entropy (benign)', () => {
    const result = scanForSecrets('"550e8400-e29b-41d4-a716-446655440000"')
    const entropyFindings = result.findings.filter((f) => f.category === 'high_entropy_string')
    expect(entropyFindings).toHaveLength(0)
  })

  it('does NOT flag a SHA-256 hex hash', () => {
    const hash = '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'
    const result = scanForSecrets(hash)
    const entropyFindings = result.findings.filter((f) => f.category === 'high_entropy_string')
    expect(entropyFindings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Redacted match content
// ---------------------------------------------------------------------------

describe('redacted match in findings', () => {
  it('AWS key finding has redactedMatch showing prefix', () => {
    const result = scanForSecrets('"AKIAIOSFODNN7EXAMPLE"')
    const finding = result.findings.find((f) => f.category === 'aws_credential')
    expect(finding?.redactedMatch).toMatch(/^AKIA/)
  })
})

// ---------------------------------------------------------------------------
// Clean content
// ---------------------------------------------------------------------------

describe('clean content', () => {
  it('returns isClean=true and empty findings for safe content', () => {
    const result = scanForSecrets('const foo = "hello world"')
    expect(result.isClean).toBe(true)
    expect(result.findings).toHaveLength(0)
  })

  it('summary says no secrets detected for clean content', () => {
    const result = scanForSecrets('const x = 42')
    expect(result.summary).toMatch(/no secrets/i)
  })
})

// ---------------------------------------------------------------------------
// Summary generation
// ---------------------------------------------------------------------------

describe('summary generation', () => {
  it('includes filename in summary when provided', () => {
    const result = scanForSecrets('const x = "AKIAIOSFODNN7EXAMPLE"', 'config.ts')
    expect(result.summary).toMatch(/config\.ts/)
  })

  it('lists severity breakdown in summary', () => {
    const token = 'ghp_' + 'A'.repeat(36) // critical
    const result = scanForSecrets(token)
    expect(result.summary).toMatch(/critical/)
  })
})

// ---------------------------------------------------------------------------
// combineResults
// ---------------------------------------------------------------------------

describe('combineResults', () => {
  it('returns clean combined result when all inputs are clean', () => {
    const r1 = scanForSecrets('const a = "hello"')
    const r2 = scanForSecrets('const b = 42')
    const combined = combineResults([r1, r2])
    expect(combined.isClean).toBe(true)
    expect(combined.totalFound).toBe(0)
  })

  it('aggregates findings from multiple results', () => {
    const token = 'ghp_' + 'C'.repeat(36)
    const r1 = scanForSecrets(token) // 1 finding
    const r2 = scanForSecrets('"AKIAIOSFODNN7EXAMPLE"') // 1 finding
    const combined = combineResults([r1, r2])
    expect(combined.totalFound).toBeGreaterThanOrEqual(2)
    expect(combined.isClean).toBe(false)
  })

  it('counts severities correctly across results', () => {
    const critical = scanForSecrets('ghp_' + 'D'.repeat(36))
    const medium = scanForSecrets('password = "mysuperpassword123"')
    const combined = combineResults([critical, medium])
    expect(combined.criticalCount).toBeGreaterThan(0)
    expect(combined.mediumCount).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// Integration: mixed content
// ---------------------------------------------------------------------------

describe('scanForSecrets integration', () => {
  it('detects multiple secrets in a single content string', () => {
    const content = [
      'OPENAI_API_KEY = "sk-' + 'a'.repeat(48) + '"',
      'GITHUB_TOKEN = "ghp_' + 'b'.repeat(36) + '"',
    ].join('\n')
    const result = scanForSecrets(content)
    expect(result.totalFound).toBeGreaterThanOrEqual(2)
    expect(result.criticalCount).toBeGreaterThanOrEqual(2)
  })

  it('clean file with .env extension returns no findings', () => {
    const result = scanForSecrets(
      'DATABASE_URL="${DB_URL}"\nAPP_SECRET="${APP_SECRET}"',
      '.env.example',
    )
    expect(result.isClean).toBe(true)
  })
})
