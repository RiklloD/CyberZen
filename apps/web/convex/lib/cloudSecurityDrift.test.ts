import { describe, expect, it } from 'vitest'
import {
  CLOUD_SECURITY_RULES,
  isAuditLoggingConfig,
  scanCloudSecurityDrift,
  type CloudSecurityDriftResult,
} from './cloudSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): CloudSecurityDriftResult {
  return scanCloudSecurityDrift(paths)
}

function expectClean(result: CloudSecurityDriftResult) {
  expect(result.riskScore).toBe(0)
  expect(result.riskLevel).toBe('none')
  expect(result.totalFindings).toBe(0)
  expect(result.findings).toHaveLength(0)
}

function hasRule(result: CloudSecurityDriftResult, ruleId: string) {
  return result.findings.some((f) => f.ruleId === ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('scanCloudSecurityDrift — trivial inputs', () => {
  it('returns clean result for empty array', () => {
    expectClean(scan([]))
  })

  it('returns clean result for whitespace-only paths', () => {
    expectClean(scan(['', '   ', '\t']))
  })

  it('returns clean result for non-cloud-security files', () => {
    expectClean(scan(['src/index.ts', 'README.md', 'package.json']))
  })

  it('summary mentions scanned file count for clean result', () => {
    const result = scan(['src/index.ts', 'README.md'])
    expect(result.summary).toMatch(/2 changed file/)
    expect(result.summary).toMatch(/no cloud security/)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('scanCloudSecurityDrift — vendor path exclusion', () => {
  it('ignores iam.json inside node_modules', () => {
    expectClean(scan(['node_modules/aws-sdk/iam.json']))
  })

  it('ignores iam.tf inside .terraform directory', () => {
    expectClean(scan(['.terraform/modules/iam.tf']))
  })

  it('ignores firewall.json inside dist', () => {
    expectClean(scan(['dist/infra/firewall.json']))
  })

  it('flags iam.json in non-vendor path', () => {
    const result = scan(['infra/iam.json'])
    expect(result.totalFindings).toBeGreaterThanOrEqual(1)
  })

  it('flags iam.json outside vendor but not inside .terraform', () => {
    const result = scan([
      '.terraform/iam.json',  // excluded — .terraform is a vendor dir
      'infra/role.json',      // included — role.json is in IAM_EXACT
    ])
    const f = result.findings.find((f) => f.ruleId === 'IAM_POLICY_DRIFT')!
    expect(f).toBeDefined()
    expect(f.matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// IAM_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('IAM_POLICY_DRIFT rule', () => {
  it('fires for iam.json', () => {
    expect(hasRule(scan(['infra/iam.json']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('fires for role.json', () => {
    expect(hasRule(scan(['aws/role.json']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('fires for policy.json', () => {
    expect(hasRule(scan(['policies/policy.json']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('fires for trust-policy.json', () => {
    expect(hasRule(scan(['infra/trust-policy.json']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('fires for service-account.json', () => {
    expect(hasRule(scan(['gcp/service-account.json']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('fires for iam.tf Terraform file', () => {
    expect(hasRule(scan(['infra/iam.tf']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('fires for roles.yaml', () => {
    expect(hasRule(scan(['infra/roles.yaml']), 'IAM_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT fire for iam.ts source file (non-config extension)', () => {
    expectClean(scan(['src/iam.ts']))
  })

  it('severity is critical', () => {
    const result = scan(['infra/iam.json'])
    const f = result.findings.find((f) => f.ruleId === 'IAM_POLICY_DRIFT')!
    expect(f.severity).toBe('critical')
  })

  it('records matchCount for multiple IAM files', () => {
    const result = scan(['infra/iam.json', 'aws/roles.yaml', 'gcp/policy.json'])
    const f = result.findings.find((f) => f.ruleId === 'IAM_POLICY_DRIFT')!
    expect(f.matchCount).toBe(3)
  })

  it('records matchedPath as first matched file', () => {
    const result = scan(['infra/role.json', 'aws/policy.json'])
    const f = result.findings.find((f) => f.ruleId === 'IAM_POLICY_DRIFT')!
    expect(f.matchedPath).toBe('infra/role.json')
  })
})

// ---------------------------------------------------------------------------
// KMS_KEY_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('KMS_KEY_POLICY_DRIFT rule', () => {
  it('fires for kms.json', () => {
    expect(hasRule(scan(['infra/kms.json']), 'KMS_KEY_POLICY_DRIFT')).toBe(true)
  })

  it('fires for kms.tf', () => {
    expect(hasRule(scan(['infra/kms.tf']), 'KMS_KEY_POLICY_DRIFT')).toBe(true)
  })

  it('fires for key-policy.json', () => {
    expect(hasRule(scan(['aws/key-policy.json']), 'KMS_KEY_POLICY_DRIFT')).toBe(true)
  })

  it('fires for customer-managed-key.json', () => {
    expect(hasRule(scan(['infra/customer-managed-key.json']), 'KMS_KEY_POLICY_DRIFT')).toBe(true)
  })

  it('fires for files under kms/ directory', () => {
    expect(hasRule(scan(['infra/kms/rotation.yaml']), 'KMS_KEY_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT fire for kms.ts source file', () => {
    expectClean(scan(['src/kms.ts']))
  })

  it('severity is critical', () => {
    const result = scan(['infra/kms.json'])
    const f = result.findings.find((f) => f.ruleId === 'KMS_KEY_POLICY_DRIFT')!
    expect(f.severity).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// NETWORK_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('NETWORK_SECURITY_DRIFT rule', () => {
  it('fires for security-group.json', () => {
    expect(hasRule(scan(['aws/security-group.json']), 'NETWORK_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for firewall.tf', () => {
    expect(hasRule(scan(['infra/firewall.tf']), 'NETWORK_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for nacl.yaml', () => {
    expect(hasRule(scan(['vpc/nacl.yaml']), 'NETWORK_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for nsg.json (Azure Network Security Group)', () => {
    expect(hasRule(scan(['azure/nsg.json']), 'NETWORK_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for ingress-rules.yaml', () => {
    expect(hasRule(scan(['infra/ingress-rules.yaml']), 'NETWORK_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT fire for network.ts source file', () => {
    expectClean(scan(['src/network.ts']))
  })

  it('severity is high', () => {
    const result = scan(['aws/firewall.json'])
    const f = result.findings.find((f) => f.ruleId === 'NETWORK_SECURITY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// STORAGE_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('STORAGE_POLICY_DRIFT rule', () => {
  it('fires for bucket-policy.json', () => {
    expect(hasRule(scan(['aws/bucket-policy.json']), 'STORAGE_POLICY_DRIFT')).toBe(true)
  })

  it('fires for s3-policy.yaml', () => {
    expect(hasRule(scan(['infra/s3-policy.yaml']), 'STORAGE_POLICY_DRIFT')).toBe(true)
  })

  it('fires for storage-policy.json', () => {
    expect(hasRule(scan(['gcp/storage-policy.json']), 'STORAGE_POLICY_DRIFT')).toBe(true)
  })

  it('fires for public-access-block.json', () => {
    expect(hasRule(scan(['aws/public-access-block.json']), 'STORAGE_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT fire for storage.ts source file', () => {
    expectClean(scan(['src/storage.ts']))
  })

  it('severity is high', () => {
    const result = scan(['aws/bucket-policy.json'])
    const f = result.findings.find((f) => f.ruleId === 'STORAGE_POLICY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// API_GATEWAY_AUTH_DRIFT
// ---------------------------------------------------------------------------

describe('API_GATEWAY_AUTH_DRIFT rule', () => {
  it('fires for authorizer.json', () => {
    expect(hasRule(scan(['aws/authorizer.json']), 'API_GATEWAY_AUTH_DRIFT')).toBe(true)
  })

  it('fires for lambda-authorizer.yaml', () => {
    expect(hasRule(scan(['infra/lambda-authorizer.yaml']), 'API_GATEWAY_AUTH_DRIFT')).toBe(true)
  })

  it('fires for api-auth.yaml', () => {
    expect(hasRule(scan(['gateway/api-auth.yaml']), 'API_GATEWAY_AUTH_DRIFT')).toBe(true)
  })

  it('fires for gateway-security.json', () => {
    expect(hasRule(scan(['infra/gateway-security.json']), 'API_GATEWAY_AUTH_DRIFT')).toBe(true)
  })

  it('does NOT fire for api.ts source file', () => {
    expectClean(scan(['src/api.ts']))
  })

  it('severity is high', () => {
    const result = scan(['aws/authorizer.json'])
    const f = result.findings.find((f) => f.ruleId === 'API_GATEWAY_AUTH_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// SECRETS_BACKEND_DRIFT
// ---------------------------------------------------------------------------

describe('SECRETS_BACKEND_DRIFT rule', () => {
  it('fires for secrets-manager.json', () => {
    expect(hasRule(scan(['aws/secrets-manager.json']), 'SECRETS_BACKEND_DRIFT')).toBe(true)
  })

  it('fires for vault.hcl', () => {
    expect(hasRule(scan(['infra/vault.hcl']), 'SECRETS_BACKEND_DRIFT')).toBe(true)
  })

  it('fires for parameter-store.yaml', () => {
    expect(hasRule(scan(['aws/parameter-store.yaml']), 'SECRETS_BACKEND_DRIFT')).toBe(true)
  })

  it('fires for vault-config.json', () => {
    expect(hasRule(scan(['infra/vault-config.json']), 'SECRETS_BACKEND_DRIFT')).toBe(true)
  })

  it('does NOT fire for secrets.ts source file', () => {
    expectClean(scan(['src/secrets.ts']))
  })

  it('severity is high', () => {
    const result = scan(['aws/secrets-manager.json'])
    const f = result.findings.find((f) => f.ruleId === 'SECRETS_BACKEND_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// AUDIT_LOGGING_DRIFT — isAuditLoggingConfig helper
// ---------------------------------------------------------------------------

describe('isAuditLoggingConfig', () => {
  it('detects cloudtrail.json', () => {
    expect(isAuditLoggingConfig('aws/cloudtrail.json')).toBe(true)
  })

  it('detects cloudtrail.tf', () => {
    expect(isAuditLoggingConfig('infra/cloudtrail.tf')).toBe(true)
  })

  it('detects cloudtrail-config.yaml', () => {
    expect(isAuditLoggingConfig('infra/cloudtrail-config.yaml')).toBe(true)
  })

  it('detects stackdriver.json', () => {
    expect(isAuditLoggingConfig('gcp/stackdriver.json')).toBe(true)
  })

  it('detects audit-log.yaml', () => {
    expect(isAuditLoggingConfig('infra/audit-log.yaml')).toBe(true)
  })

  it('detects diagnostic-settings.json (Azure)', () => {
    expect(isAuditLoggingConfig('azure/diagnostic-settings.json')).toBe(true)
  })

  it('detects activity-log.json (Azure)', () => {
    expect(isAuditLoggingConfig('azure/activity-log.json')).toBe(true)
  })

  it('detects siem-config.yaml', () => {
    expect(isAuditLoggingConfig('infra/siem-config.yaml')).toBe(true)
  })

  it('detects log-analytics.json', () => {
    expect(isAuditLoggingConfig('azure/log-analytics.json')).toBe(true)
  })

  it('does NOT detect plain log.json (too generic)', () => {
    expect(isAuditLoggingConfig('config/log.json')).toBe(false)
  })

  it('does NOT detect logging.ts source file', () => {
    expect(isAuditLoggingConfig('src/logging.ts')).toBe(false)
  })

  it('does NOT detect README.md', () => {
    expect(isAuditLoggingConfig('docs/audit/README.md')).toBe(false)
  })
})

describe('AUDIT_LOGGING_DRIFT rule (via scanner)', () => {
  it('fires for cloudtrail.json', () => {
    expect(hasRule(scan(['aws/cloudtrail.json']), 'AUDIT_LOGGING_DRIFT')).toBe(true)
  })

  it('fires for audit-log.yaml', () => {
    expect(hasRule(scan(['infra/audit-log.yaml']), 'AUDIT_LOGGING_DRIFT')).toBe(true)
  })

  it('does NOT fire for plain src/log.ts', () => {
    expect(hasRule(scan(['src/log.ts']), 'AUDIT_LOGGING_DRIFT')).toBe(false)
  })

  it('severity is medium', () => {
    const result = scan(['aws/cloudtrail.json'])
    const f = result.findings.find((f) => f.ruleId === 'AUDIT_LOGGING_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// CDN_WAF_DRIFT
// ---------------------------------------------------------------------------

describe('CDN_WAF_DRIFT rule', () => {
  it('fires for cloudfront.json', () => {
    expect(hasRule(scan(['aws/cloudfront.json']), 'CDN_WAF_DRIFT')).toBe(true)
  })

  it('fires for waf.tf', () => {
    expect(hasRule(scan(['infra/waf.tf']), 'CDN_WAF_DRIFT')).toBe(true)
  })

  it('fires for cloudflare.json', () => {
    expect(hasRule(scan(['infra/cloudflare.json']), 'CDN_WAF_DRIFT')).toBe(true)
  })

  it('fires for ddos-protection.json', () => {
    expect(hasRule(scan(['azure/ddos-protection.json']), 'CDN_WAF_DRIFT')).toBe(true)
  })

  it('fires for waf-rule.yaml', () => {
    expect(hasRule(scan(['infra/waf-rule.yaml']), 'CDN_WAF_DRIFT')).toBe(true)
  })

  it('does NOT fire for cdn.ts source file', () => {
    expectClean(scan(['src/cdn.ts']))
  })

  it('severity is medium', () => {
    const result = scan(['aws/waf.json'])
    const f = result.findings.find((f) => f.ruleId === 'CDN_WAF_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanCloudSecurityDrift — scoring', () => {
  it('riskScore is 0 for clean result', () => {
    expect(scan([]).riskScore).toBe(0)
  })

  it('riskLevel is none for zero findings', () => {
    expect(scan([]).riskLevel).toBe('none')
  })

  it('riskScore is positive when a critical rule fires', () => {
    const result = scan(['infra/iam.json'])
    expect(result.riskScore).toBeGreaterThan(0)
  })

  it('riskLevel is elevated (medium or above) when critical rule fires', () => {
    // A single critical finding scores 30 pts → falls in the 'medium' band (25–49).
    // Two critical findings score 60 pts → 'high' band (50–74).
    const result = scan(['infra/iam.json'])
    expect(['medium', 'high', 'critical']).toContain(result.riskLevel)
  })

  it('riskScore increases with more rules firing', () => {
    const single = scan(['infra/iam.json'])
    const multi  = scan(['infra/iam.json', 'infra/kms.json'])
    expect(multi.riskScore).toBeGreaterThan(single.riskScore)
  })

  it('riskScore is capped at 100', () => {
    const result = scan([
      'infra/iam.json', 'infra/kms.json',
      'aws/security-group.json', 'aws/bucket-policy.json',
      'aws/authorizer.json', 'aws/secrets-manager.json',
      'aws/cloudtrail.json', 'aws/waf.json',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })

  it('criticalCount and highCount are populated correctly', () => {
    const result = scan([
      'infra/iam.json',
      'infra/kms.json',
      'aws/security-group.json',
    ])
    expect(result.criticalCount).toBe(2)
    expect(result.highCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('scanCloudSecurityDrift — summary', () => {
  it('mentions "cloud security" in findings summary', () => {
    const result = scan(['infra/iam.json'])
    expect(result.summary).toMatch(/cloud security/)
  })

  it('mentions "mandatory" for critical/high findings', () => {
    const result = scan(['infra/iam.json'])
    expect(result.summary).toMatch(/mandatory/)
  })

  it('mentions "no cloud security" for clean result', () => {
    const result = scan(['src/index.ts'])
    expect(result.summary).toMatch(/no cloud security/)
  })

  it('includes rule count in multi-finding summary', () => {
    const result = scan(['infra/iam.json', 'aws/cloudtrail.json'])
    expect(result.summary).toMatch(/2 cloud security/)
  })
})

// ---------------------------------------------------------------------------
// CLOUD_SECURITY_RULES constant integrity
// ---------------------------------------------------------------------------

describe('CLOUD_SECURITY_RULES constants', () => {
  it('contains 8 rules', () => {
    expect(CLOUD_SECURITY_RULES).toHaveLength(8)
  })

  it('all rules have non-empty descriptions', () => {
    for (const rule of CLOUD_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
    }
  })

  it('all rules have non-empty recommendations', () => {
    for (const rule of CLOUD_SECURITY_RULES) {
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })

  it('critical rules come before high and medium', () => {
    const severities = CLOUD_SECURITY_RULES.map((r) => r.severity)
    const criticalIdx = severities.findIndex((s) => s === 'critical')
    const mediumIdx   = severities.findIndex((s) => s === 'medium')
    expect(criticalIdx).toBeLessThan(mediumIdx)
  })
})
