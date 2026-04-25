/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  isSecretProviderIntegrationConfig,
  scanSecretMgmtDrift,
} from './secretMgmtDrift'

// ---------------------------------------------------------------------------
// Rule 1: VAULT_SERVER_DRIFT
// ---------------------------------------------------------------------------

describe('VAULT_SERVER_DRIFT', () => {
  it('detects vault.hcl at repo root', () => {
    const r = scanSecretMgmtDrift(['vault.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('detects vault-config.hcl', () => {
    const r = scanSecretMgmtDrift(['vault-config.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('detects vault-agent.hcl', () => {
    const r = scanSecretMgmtDrift(['vault-agent.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('detects vault.json', () => {
    const r = scanSecretMgmtDrift(['vault.json'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('detects vault-server.hcl', () => {
    const r = scanSecretMgmtDrift(['vault-server.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('detects vault-* prefixed .yaml', () => {
    const r = scanSecretMgmtDrift(['vault-config-production.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('detects .hcl file in vault/ dir', () => {
    const r = scanSecretMgmtDrift(['vault/config.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(true)
  })

  it('does NOT match app.hcl outside vault dirs', () => {
    const r = scanSecretMgmtDrift(['terraform/app.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_SERVER_DRIFT')).toBe(false)
  })

  it('severity is high', () => {
    const r = scanSecretMgmtDrift(['vault.hcl'])
    const f = r.findings.find((x) => x.ruleId === 'VAULT_SERVER_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: VAULT_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('VAULT_POLICY_DRIFT', () => {
  it('detects .hcl in vault/policies/ dir', () => {
    const r = scanSecretMgmtDrift(['vault/policies/app-read.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_POLICY_DRIFT')).toBe(true)
  })

  it('detects .hcl in vault-policies/ dir', () => {
    const r = scanSecretMgmtDrift(['vault-policies/admin.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_POLICY_DRIFT')).toBe(true)
  })

  it('detects vault-policy- prefixed file', () => {
    const r = scanSecretMgmtDrift(['vault-policy-ci.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_POLICY_DRIFT')).toBe(true)
  })

  it('detects .json in vault/policy/ dir', () => {
    const r = scanSecretMgmtDrift(['vault/policy/default.json'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT match generic policy.hcl outside vault dirs', () => {
    const r = scanSecretMgmtDrift(['config/policy.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_POLICY_DRIFT')).toBe(false)
  })

  it('severity is high', () => {
    const r = scanSecretMgmtDrift(['vault/policies/admin.hcl'])
    const f = r.findings.find((x) => x.ruleId === 'VAULT_POLICY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: AWS_SECRETS_MANAGER_DRIFT
// ---------------------------------------------------------------------------

describe('AWS_SECRETS_MANAGER_DRIFT', () => {
  it('detects secrets-manager.json ungated', () => {
    const r = scanSecretMgmtDrift(['secrets-manager.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_SECRETS_MANAGER_DRIFT')).toBe(true)
  })

  it('detects aws-secrets-manager.yaml', () => {
    const r = scanSecretMgmtDrift(['aws-secrets-manager.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_SECRETS_MANAGER_DRIFT')).toBe(true)
  })

  it('detects secret-rotation- prefixed file', () => {
    const r = scanSecretMgmtDrift(['secret-rotation-lambda.py'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_SECRETS_MANAGER_DRIFT')).toBe(true)
  })

  it('detects .yaml in secrets-manager/ dir', () => {
    const r = scanSecretMgmtDrift(['secrets-manager/policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_SECRETS_MANAGER_DRIFT')).toBe(true)
  })

  it('severity is high', () => {
    const r = scanSecretMgmtDrift(['secrets-manager.json'])
    const f = r.findings.find((x) => x.ruleId === 'AWS_SECRETS_MANAGER_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: AZURE_KEY_VAULT_DRIFT
// ---------------------------------------------------------------------------

describe('AZURE_KEY_VAULT_DRIFT', () => {
  it('detects azure-key-vault.json ungated', () => {
    const r = scanSecretMgmtDrift(['azure-key-vault.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_KEY_VAULT_DRIFT')).toBe(true)
  })

  it('detects keyvault.yaml', () => {
    const r = scanSecretMgmtDrift(['keyvault.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_KEY_VAULT_DRIFT')).toBe(true)
  })

  it('detects keyvault- prefixed file', () => {
    const r = scanSecretMgmtDrift(['keyvault-policy-staging.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_KEY_VAULT_DRIFT')).toBe(true)
  })

  it('detects .bicep in azure-key-vault/ dir', () => {
    const r = scanSecretMgmtDrift(['azure-key-vault/access.bicep'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_KEY_VAULT_DRIFT')).toBe(true)
  })

  it('severity is high', () => {
    const r = scanSecretMgmtDrift(['azure-key-vault.json'])
    const f = r.findings.find((x) => x.ruleId === 'AZURE_KEY_VAULT_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 5: SOPS_ENCRYPTION_DRIFT
// ---------------------------------------------------------------------------

describe('SOPS_ENCRYPTION_DRIFT', () => {
  it('detects .sops.yaml at root', () => {
    const r = scanSecretMgmtDrift(['.sops.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })

  it('detects .sops.yml', () => {
    const r = scanSecretMgmtDrift(['.sops.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })

  it('detects .sops.json', () => {
    const r = scanSecretMgmtDrift(['.sops.json'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })

  it('detects sops.yaml (no dot)', () => {
    const r = scanSecretMgmtDrift(['sops.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })

  it('detects sops- prefixed config', () => {
    const r = scanSecretMgmtDrift(['sops-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })

  it('detects .yaml in sops/ dir', () => {
    const r = scanSecretMgmtDrift(['sops/rules.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })

  it('severity is medium', () => {
    const r = scanSecretMgmtDrift(['.sops.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'SOPS_ENCRYPTION_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: SEALED_SECRETS_DRIFT
// ---------------------------------------------------------------------------

describe('SEALED_SECRETS_DRIFT', () => {
  it('detects sealed-secrets.yaml ungated', () => {
    const r = scanSecretMgmtDrift(['sealed-secrets.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SEALED_SECRETS_DRIFT')).toBe(true)
  })

  it('detects sealed-secrets-controller.yaml', () => {
    const r = scanSecretMgmtDrift(['sealed-secrets-controller.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SEALED_SECRETS_DRIFT')).toBe(true)
  })

  it('detects sealed-secrets- prefixed file', () => {
    const r = scanSecretMgmtDrift(['sealed-secrets-config-prod.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SEALED_SECRETS_DRIFT')).toBe(true)
  })

  it('detects .yaml in sealed-secrets/ dir', () => {
    const r = scanSecretMgmtDrift(['sealed-secrets/controller.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SEALED_SECRETS_DRIFT')).toBe(true)
  })

  it('severity is medium', () => {
    const r = scanSecretMgmtDrift(['sealed-secrets.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'SEALED_SECRETS_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: EXTERNAL_SECRET_OPERATOR_DRIFT
// ---------------------------------------------------------------------------

describe('EXTERNAL_SECRET_OPERATOR_DRIFT', () => {
  it('detects external-secrets.yaml ungated', () => {
    const r = scanSecretMgmtDrift(['external-secrets.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EXTERNAL_SECRET_OPERATOR_DRIFT')).toBe(true)
  })

  it('detects secret-store.yaml', () => {
    const r = scanSecretMgmtDrift(['secret-store.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EXTERNAL_SECRET_OPERATOR_DRIFT')).toBe(true)
  })

  it('detects cluster-secret-store.yaml', () => {
    const r = scanSecretMgmtDrift(['cluster-secret-store.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EXTERNAL_SECRET_OPERATOR_DRIFT')).toBe(true)
  })

  it('detects eso- prefixed file', () => {
    const r = scanSecretMgmtDrift(['eso-store-aws.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EXTERNAL_SECRET_OPERATOR_DRIFT')).toBe(true)
  })

  it('detects .yaml in external-secrets/ dir', () => {
    const r = scanSecretMgmtDrift(['external-secrets/aws-store.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EXTERNAL_SECRET_OPERATOR_DRIFT')).toBe(true)
  })

  it('severity is medium', () => {
    const r = scanSecretMgmtDrift(['external-secrets.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'EXTERNAL_SECRET_OPERATOR_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: SECRET_PROVIDER_INTEGRATION_DRIFT (exported)
// ---------------------------------------------------------------------------

describe('SECRET_PROVIDER_INTEGRATION_DRIFT — isSecretProviderIntegrationConfig', () => {
  it('matches doppler.yaml ungated', () => {
    expect(isSecretProviderIntegrationConfig('doppler.yaml', 'doppler.yaml')).toBe(true)
  })

  it('matches .doppler.yaml', () => {
    expect(isSecretProviderIntegrationConfig('.doppler.yaml', '.doppler.yaml')).toBe(true)
  })

  it('matches .infisical.json', () => {
    expect(isSecretProviderIntegrationConfig('.infisical.json', '.infisical.json')).toBe(true)
  })

  it('matches 1password-credentials.json', () => {
    expect(isSecretProviderIntegrationConfig('1password-credentials.json', '1password-credentials.json')).toBe(true)
  })

  it('matches onepassword-connect.yaml', () => {
    expect(isSecretProviderIntegrationConfig('onepassword-connect.yaml', 'onepassword-connect.yaml')).toBe(true)
  })

  it('matches doppler- prefixed file', () => {
    expect(isSecretProviderIntegrationConfig('doppler-config.yaml', 'doppler-config.yaml')).toBe(true)
  })

  it('matches .yaml in infisical/ dir', () => {
    expect(isSecretProviderIntegrationConfig('infisical/config.yaml', 'config.yaml')).toBe(true)
  })

  it('does NOT match generic config.yaml at root', () => {
    expect(isSecretProviderIntegrationConfig('config.yaml', 'config.yaml')).toBe(false)
  })
})

describe('SECRET_PROVIDER_INTEGRATION_DRIFT — scanSecretMgmtDrift', () => {
  it('detects doppler.yaml', () => {
    const r = scanSecretMgmtDrift(['doppler.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SECRET_PROVIDER_INTEGRATION_DRIFT')).toBe(true)
  })

  it('severity is low', () => {
    const r = scanSecretMgmtDrift(['doppler.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'SECRET_PROVIDER_INTEGRATION_DRIFT')!
    expect(f.severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanSecretMgmtDrift — scoring model', () => {
  it('empty file list returns riskScore 0 and riskLevel none', () => {
    const r = scanSecretMgmtDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('single high rule → 15 → riskLevel medium', () => {
    const r = scanSecretMgmtDrift(['vault.hcl'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('three high rules → 45 → riskLevel high (45 is not < 45)', () => {
    const r = scanSecretMgmtDrift(['vault.hcl', 'vault/policies/admin.hcl', 'secrets-manager.json'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('all four high rules → 60 → riskLevel high', () => {
    const r = scanSecretMgmtDrift([
      'vault.hcl', 'vault/policies/admin.hcl',
      'secrets-manager.json', 'azure-key-vault.json',
    ])
    expect(r.riskScore).toBe(60)
    expect(r.riskLevel).toBe('high')
  })

  it('single medium rule → 8 → riskLevel low', () => {
    const r = scanSecretMgmtDrift(['.sops.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('all 8 rules → score 88 → riskLevel critical', () => {
    const r = scanSecretMgmtDrift([
      'vault.hcl',
      'vault/policies/admin.hcl',
      'secrets-manager.json',
      'azure-key-vault.json',
      '.sops.yaml',
      'sealed-secrets.yaml',
      'external-secrets.yaml',
      'doppler.yaml',
    ])
    // 4×15 + 3×8 + 1×4 = 88
    expect(r.riskScore).toBe(88)
    expect(r.riskLevel).toBe('critical')
  })

  it('score is capped at 100', () => {
    const files = [
      'vault.hcl', 'vault-config.hcl', 'vault-agent.hcl',
      'vault/policies/admin.hcl', 'vault-policy-ci.hcl',
      'secrets-manager.json', 'aws-secrets-manager.yaml',
      'azure-key-vault.json', 'keyvault.yaml',
    ]
    const r = scanSecretMgmtDrift(files)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Per-rule dedup
// ---------------------------------------------------------------------------

describe('scanSecretMgmtDrift — per-rule dedup', () => {
  it('multiple vault server config files count as one VAULT_SERVER_DRIFT finding', () => {
    const r = scanSecretMgmtDrift(['vault.hcl', 'vault-config.hcl', 'vault-agent.hcl'])
    const findings = r.findings.filter((f) => f.ruleId === 'VAULT_SERVER_DRIFT')
    expect(findings).toHaveLength(1)
  })

  it('matchCount reflects actual number of matched vault server files', () => {
    const r = scanSecretMgmtDrift(['vault.hcl', 'vault-config.hcl', 'vault-agent.hcl'])
    const f = r.findings.find((x) => x.ruleId === 'VAULT_SERVER_DRIFT')!
    expect(f.matchCount).toBe(3)
  })

  it('dedup keeps score at 15 for multiple VAULT_SERVER_DRIFT files', () => {
    const r = scanSecretMgmtDrift(['vault.hcl', 'vault-config.hcl', 'vault.json'])
    expect(r.riskScore).toBe(15)
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('scanSecretMgmtDrift — vendor exclusion', () => {
  it('ignores vault.hcl inside vendor/', () => {
    const r = scanSecretMgmtDrift(['vendor/vault.hcl'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores .sops.yaml inside node_modules/', () => {
    const r = scanSecretMgmtDrift(['node_modules/sops/.sops.yaml'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('scanSecretMgmtDrift — path normalisation', () => {
  it('handles Windows backslash paths', () => {
    const r = scanSecretMgmtDrift(['vault\\policies\\admin.hcl'])
    expect(r.findings.some((f) => f.ruleId === 'VAULT_POLICY_DRIFT')).toBe(true)
  })

  it('handles ./ prefix', () => {
    const r = scanSecretMgmtDrift(['./.sops.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SOPS_ENCRYPTION_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

describe('scanSecretMgmtDrift — summary', () => {
  it('returns clean summary when no findings', () => {
    const r = scanSecretMgmtDrift([])
    expect(r.summary).toBe('No secret management configuration drift detected.')
  })

  it('summary includes riskLevel and score', () => {
    const r = scanSecretMgmtDrift(['vault.hcl'])
    expect(r.summary).toContain('medium')
    expect(r.summary).toContain('15/100')
  })

  it('highCount / mediumCount / lowCount are accurate', () => {
    const r = scanSecretMgmtDrift([
      'vault.hcl', 'secrets-manager.json', '.sops.yaml', 'doppler.yaml',
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
  })
})
