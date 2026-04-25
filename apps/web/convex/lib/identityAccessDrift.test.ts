import { describe, expect, it } from 'vitest'
import {
  isServiceAccountFile,
  IDENTITY_ACCESS_RULES,
  scanIdentityAccessDrift,
} from './identityAccessDrift'

const scan = scanIdentityAccessDrift

function ruleIds(r: ReturnType<typeof scan>) {
  return r.findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('trivial inputs', () => {
  it('returns none for empty array', () => {
    const r = scan([])
    expect(r.riskLevel).toBe('none')
    expect(r.riskScore).toBe(0)
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
  })

  it('returns none for vendor-only paths', () => {
    const r = scan([
      'node_modules/some-pkg/vault-policy.hcl',
      '.git/config',
      'vendor/lib/sssd.conf',
      'dist/ldap.conf',
    ])
    expect(r.riskLevel).toBe('none')
    expect(r.findings).toHaveLength(0)
  })

  it('normalises Windows backslash paths', () => {
    const r = scan(['vault\\vault-policy.hcl'])
    expect(ruleIds(r)).toContain('VAULT_POLICY_DRIFT')
  })

  it('returns none for unrelated files', () => {
    const r = scan(['src/index.ts', 'README.md', 'package.json', 'docker-compose.yml'])
    expect(r.riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('excludes node_modules/ paths', () => {
    expect(ruleIds(scan(['node_modules/vault-config.hcl']))).not.toContain('VAULT_POLICY_DRIFT')
  })

  it('excludes .git/ paths', () => {
    expect(ruleIds(scan(['.git/sssd.conf']))).not.toContain('LDAP_CONFIG_DRIFT')
  })

  it('excludes dist/ paths', () => {
    expect(ruleIds(scan(['dist/sudoers']))).not.toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('excludes .terraform/ paths', () => {
    expect(ruleIds(scan(['.terraform/vault-policy.hcl']))).not.toContain('VAULT_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// VAULT_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('VAULT_POLICY_DRIFT', () => {
  it('detects vault-policy.hcl', () => {
    expect(ruleIds(scan(['vault-policy.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects vault-agent.hcl', () => {
    expect(ruleIds(scan(['vault-agent.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects vault-config.hcl', () => {
    expect(ruleIds(scan(['vault-config.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects vault.hcl', () => {
    expect(ruleIds(scan(['vault.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects vault-server.hcl', () => {
    expect(ruleIds(scan(['vault-server.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects files inside vault/ directory', () => {
    expect(ruleIds(scan(['config/vault/app-policy.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects files inside .vault/ directory', () => {
    expect(ruleIds(scan(['.vault/token-policy.json']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects vault- prefixed HCL files', () => {
    expect(ruleIds(scan(['vault-kv-policy.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('detects vault- prefixed YAML files', () => {
    expect(ruleIds(scan(['vault-agent-config.yaml']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('does not flag generic Terraform HCL', () => {
    expect(ruleIds(scan(['main.tf', 'variables.tf', 'outputs.tf']))).not.toContain('VAULT_POLICY_DRIFT')
  })

  it('does not flag random YAML files', () => {
    expect(ruleIds(scan(['config.yaml', 'deployment.yaml']))).not.toContain('VAULT_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// LDAP_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('LDAP_CONFIG_DRIFT', () => {
  it('detects ldap.conf', () => {
    expect(ruleIds(scan(['ldap.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects openldap.conf', () => {
    expect(ruleIds(scan(['openldap.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects slapd.conf', () => {
    expect(ruleIds(scan(['slapd.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects sssd.conf', () => {
    expect(ruleIds(scan(['sssd.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects nslcd.conf', () => {
    expect(ruleIds(scan(['nslcd.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects realmd.conf', () => {
    expect(ruleIds(scan(['realmd.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects ldap-config.yaml', () => {
    expect(ruleIds(scan(['ldap-config.yaml']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects ad-config.yaml', () => {
    expect(ruleIds(scan(['ad-config.yaml']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects files inside ldap/ directory', () => {
    expect(ruleIds(scan(['config/ldap/client.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects files inside sssd/ directory', () => {
    expect(ruleIds(scan(['etc/sssd/sssd.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('detects ldap- prefixed config files', () => {
    expect(ruleIds(scan(['ldap-server.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })

  it('does not flag generic .conf files', () => {
    expect(ruleIds(scan(['nginx.conf', 'app.conf']))).not.toContain('LDAP_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// PRIVILEGED_ACCESS_DRIFT
// ---------------------------------------------------------------------------

describe('PRIVILEGED_ACCESS_DRIFT', () => {
  it('detects sudoers', () => {
    expect(ruleIds(scan(['sudoers']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects sudo.conf', () => {
    expect(ruleIds(scan(['sudo.conf']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects pam.conf', () => {
    expect(ruleIds(scan(['pam.conf']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects pam-config.yaml', () => {
    expect(ruleIds(scan(['pam-config.yaml']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects access.conf', () => {
    expect(ruleIds(scan(['access.conf']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects limits.conf', () => {
    expect(ruleIds(scan(['limits.conf']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects files in pam.d/ directory', () => {
    expect(ruleIds(scan(['etc/pam.d/sshd']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects files in sudoers.d/ directory', () => {
    expect(ruleIds(scan(['etc/sudoers.d/devops']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects files in /etc/security/ directory', () => {
    expect(ruleIds(scan(['etc/security/access.conf']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('detects sudo- prefixed config files', () => {
    expect(ruleIds(scan(['sudo-ldap.conf']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('does not flag random .conf files', () => {
    expect(ruleIds(scan(['httpd.conf', 'mysql.conf']))).not.toContain('PRIVILEGED_ACCESS_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// MFA_ENFORCEMENT_DRIFT
// ---------------------------------------------------------------------------

describe('MFA_ENFORCEMENT_DRIFT', () => {
  it('detects duo.conf', () => {
    expect(ruleIds(scan(['duo.conf']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects duo.ini', () => {
    expect(ruleIds(scan(['duo.ini']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects google-authenticator.conf', () => {
    expect(ruleIds(scan(['google-authenticator.conf']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects yubikey-policy.yaml', () => {
    expect(ruleIds(scan(['yubikey-policy.yaml']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects mfa-policy.yaml', () => {
    expect(ruleIds(scan(['mfa-policy.yaml']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects totp-policy.yml', () => {
    expect(ruleIds(scan(['totp-policy.yml']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects fido2-policy.yaml', () => {
    expect(ruleIds(scan(['fido2-policy.yaml']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects files inside duo/ directory', () => {
    expect(ruleIds(scan(['etc/duo/pam_duo.conf']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects duo- prefixed files', () => {
    expect(ruleIds(scan(['duo-unix.conf']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('detects mfa- prefixed files', () => {
    expect(ruleIds(scan(['mfa-config.yaml']))).toContain('MFA_ENFORCEMENT_DRIFT')
  })

  it('does not flag random .ini files', () => {
    expect(ruleIds(scan(['app.ini', 'pytest.ini']))).not.toContain('MFA_ENFORCEMENT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// IDENTITY_FEDERATION_DRIFT
// ---------------------------------------------------------------------------

describe('IDENTITY_FEDERATION_DRIFT', () => {
  it('detects sp-metadata.xml', () => {
    expect(ruleIds(scan(['sp-metadata.xml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects idp-metadata.xml', () => {
    expect(ruleIds(scan(['idp-metadata.xml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects federation.xml', () => {
    expect(ruleIds(scan(['federation.xml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects saml-metadata.xml', () => {
    expect(ruleIds(scan(['saml-metadata.xml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects scim-config.yaml', () => {
    expect(ruleIds(scan(['scim-config.yaml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects oidc-provider.yaml', () => {
    expect(ruleIds(scan(['oidc-provider.yaml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects XML files inside saml/ directory', () => {
    expect(ruleIds(scan(['config/saml/metadata.xml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects YAML files inside federation/ directory', () => {
    expect(ruleIds(scan(['config/federation/providers.yaml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects sp- prefixed XML files', () => {
    expect(ruleIds(scan(['sp-config.xml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('detects idp- prefixed YAML files', () => {
    expect(ruleIds(scan(['idp-config.yaml']))).toContain('IDENTITY_FEDERATION_DRIFT')
  })

  it('does not flag generic XML files', () => {
    expect(ruleIds(scan(['pom.xml', 'build.xml', 'app-config.xml']))).not.toContain('IDENTITY_FEDERATION_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SERVICE_ACCOUNT_DRIFT — isServiceAccountFile (user contribution)
// ---------------------------------------------------------------------------

describe('isServiceAccountFile', () => {
  // Canonical exact filenames — always match
  it('matches service-account.json', () => {
    expect(isServiceAccountFile('config/service-account.json')).toBe(true)
  })

  it('matches gcp-service-account.json', () => {
    expect(isServiceAccountFile('gcp-service-account.json')).toBe(true)
  })

  it('matches workload-identity.yaml', () => {
    expect(isServiceAccountFile('workload-identity.yaml')).toBe(true)
  })

  it('matches github-actions-wif.yaml', () => {
    expect(isServiceAccountFile('github-actions-wif.yaml')).toBe(true)
  })

  it('matches aws-credentials.json', () => {
    expect(isServiceAccountFile('aws-credentials.json')).toBe(true)
  })

  // GCP-style key file patterns
  it('matches *-sa.json suffix pattern', () => {
    expect(isServiceAccountFile('my-app-sa.json')).toBe(true)
  })

  it('matches *-service-account.json suffix', () => {
    expect(isServiceAccountFile('billing-service-account.json')).toBe(true)
  })

  // k8s directory exclusion
  it('excludes files in k8s/ directory', () => {
    expect(isServiceAccountFile('k8s/service-account.yaml')).toBe(false)
  })

  it('excludes files in kubernetes/ directory', () => {
    expect(isServiceAccountFile('kubernetes/manifests/serviceaccount.yaml')).toBe(false)
  })

  it('excludes files in helm/ directory', () => {
    expect(isServiceAccountFile('helm/templates/service-account.json')).toBe(false)
  })

  // Terraform/IaC exclusion
  it('excludes files in terraform/ directory', () => {
    expect(isServiceAccountFile('terraform/iam/service-account.json')).toBe(false)
  })

  // IAM directory matching
  it('matches JSON in iam/ directory', () => {
    expect(isServiceAccountFile('config/iam/app-credentials.json')).toBe(true)
  })

  it('matches YAML in credentials/ directory', () => {
    expect(isServiceAccountFile('credentials/app-identity.yaml')).toBe(true)
  })

  // Workload identity federation patterns
  it('matches workload-identity-pool.yaml', () => {
    expect(isServiceAccountFile('workload-identity-pool.yaml')).toBe(true)
  })

  it('matches wif-config.json anywhere', () => {
    expect(isServiceAccountFile('ci/wif-config.json')).toBe(true)
  })

  // Negative cases
  it('does not match generic JSON files', () => {
    expect(isServiceAccountFile('package.json')).toBe(false)
  })

  it('does not match tsconfig.json', () => {
    expect(isServiceAccountFile('tsconfig.json')).toBe(false)
  })
})

describe('SERVICE_ACCOUNT_DRIFT (via scan)', () => {
  it('detects service-account.json outside vendor dirs', () => {
    expect(ruleIds(scan(['config/service-account.json']))).toContain('SERVICE_ACCOUNT_DRIFT')
  })

  it('detects workload-identity.yaml', () => {
    expect(ruleIds(scan(['workload-identity.yaml']))).toContain('SERVICE_ACCOUNT_DRIFT')
  })

  it('does not flag service-account.json inside k8s/ directory', () => {
    expect(ruleIds(scan(['k8s/service-account.json']))).not.toContain('SERVICE_ACCOUNT_DRIFT')
  })

  it('does not flag files in terraform/ directory', () => {
    expect(ruleIds(scan(['terraform/iam/service-account.json']))).not.toContain('SERVICE_ACCOUNT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// PASSWORD_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('PASSWORD_POLICY_DRIFT', () => {
  it('detects password-policy.yaml', () => {
    expect(ruleIds(scan(['password-policy.yaml']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects password-policy.json', () => {
    expect(ruleIds(scan(['password-policy.json']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects pwquality.conf', () => {
    expect(ruleIds(scan(['pwquality.conf']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects pam_pwquality.conf', () => {
    expect(ruleIds(scan(['pam_pwquality.conf']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects passwdqc.conf', () => {
    expect(ruleIds(scan(['passwdqc.conf']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects cracklib.conf', () => {
    expect(ruleIds(scan(['cracklib.conf']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects login.defs', () => {
    expect(ruleIds(scan(['login.defs']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('detects password-policy files in /etc/security/', () => {
    expect(ruleIds(scan(['etc/security/pwquality.conf']))).toContain('PASSWORD_POLICY_DRIFT')
  })

  it('does not flag random .conf files', () => {
    expect(ruleIds(scan(['nginx.conf', 'redis.conf']))).not.toContain('PASSWORD_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// APPLICATION_RBAC_DRIFT
// ---------------------------------------------------------------------------

describe('APPLICATION_RBAC_DRIFT', () => {
  it('detects casbin.conf', () => {
    expect(ruleIds(scan(['casbin.conf']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects casbin.yaml', () => {
    expect(ruleIds(scan(['casbin.yaml']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects model.conf (Casbin model)', () => {
    expect(ruleIds(scan(['model.conf']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects policy.csv (Casbin policy)', () => {
    expect(ruleIds(scan(['policy.csv']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects oso-policy.polar', () => {
    expect(ruleIds(scan(['oso-policy.polar']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects authorization.polar', () => {
    expect(ruleIds(scan(['authorization.polar']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects permissions.yaml', () => {
    expect(ruleIds(scan(['permissions.yaml']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects fga-model.json (OpenFGA)', () => {
    expect(ruleIds(scan(['fga-model.json']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects zanzibar.yaml', () => {
    expect(ruleIds(scan(['zanzibar.yaml']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects files inside casbin/ directory', () => {
    expect(ruleIds(scan(['config/casbin/rules.csv']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects files inside authz/ directory', () => {
    expect(ruleIds(scan(['src/authz/policy.yaml']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects casbin-containing basenames', () => {
    expect(ruleIds(scan(['casbin-rbac.conf']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('detects .polar extension files', () => {
    expect(ruleIds(scan(['src/auth/rules.polar']))).toContain('APPLICATION_RBAC_DRIFT')
  })

  it('does not flag generic YAML in src/', () => {
    expect(ruleIds(scan(['src/config.yaml', 'src/routes.yml']))).not.toContain('APPLICATION_RBAC_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 high file → score 15, risk low', () => {
    const r = scan(['vault-policy.hcl'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('3 high files for same rule → score 45 (cap), risk high', () => {
    const r = scan(['vault-policy.hcl', 'vault-agent.hcl', 'vault-config.hcl'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('4 high files for same rule → still capped at 45', () => {
    const r = scan(['vault-policy.hcl', 'vault-agent.hcl', 'vault-config.hcl', 'vault.hcl'])
    expect(r.riskScore).toBe(45)
  })

  it('1 medium file → score 8, risk low', () => {
    const r = scan(['duo.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('4 medium files for same rule → capped at 25', () => {
    const r = scan(['duo.conf', 'duo.ini', 'duo-config.yaml', 'mfa-policy.yaml'])
    expect(r.riskScore).toBe(25)
  })

  it('1 low file → score 4, risk low', () => {
    const r = scan(['casbin.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('score 19 → low (boundary: < 20 = low)', () => {
    // 1 high (15) + 1 low (4) = 19
    const r = scan(['vault-policy.hcl', 'casbin.conf'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })

  it('score 23 → medium (1 high + 1 medium)', () => {
    const r = scan(['vault-policy.hcl', 'duo.conf'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high', () => {
    // 3 high rules × 15 = 45 → high (not medium: < 45 is medium, 45 is high)
    const r = scan(['vault-policy.hcl', 'sssd.conf', 'sudoers'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('3 high rules + 4 medium rules → critical (score 77)', () => {
    // 3 × 15 = 45, 4 × 8 = 32 → total 77
    const r = scan([
      'vault-policy.hcl',    // VAULT_POLICY_DRIFT (high)
      'sssd.conf',           // LDAP_CONFIG_DRIFT (high)
      'sudoers',             // PRIVILEGED_ACCESS_DRIFT (high)
      'duo.conf',            // MFA_ENFORCEMENT_DRIFT (medium)
      'sp-metadata.xml',     // IDENTITY_FEDERATION_DRIFT (medium)
      'password-policy.yaml', // PASSWORD_POLICY_DRIFT (medium)
      'workload-identity.yaml', // SERVICE_ACCOUNT_DRIFT (medium)
    ])
    expect(r.riskScore).toBe(77)
    expect(r.riskLevel).toBe('critical')
  })

  it('score clamped at 100', () => {
    const paths: string[] = []
    for (let i = 0; i < 10; i++) {
      paths.push('vault-policy.hcl', 'sssd.conf', 'sudoers')
    }
    const r = scan(paths)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })

  it('score 4 → low', () => {
    expect(scan(['casbin.conf']).riskLevel).toBe('low')
  })

  it('score 15 → low', () => {
    expect(scan(['vault-policy.hcl']).riskLevel).toBe('low')
  })

  it('score 20 → medium (1 high + 1 medium = 23)', () => {
    const r = scan(['vault-policy.hcl', 'duo.conf'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })

  it('score ≥70 → critical', () => {
    const r = scan([
      'vault-policy.hcl', 'vault-agent.hcl', 'vault-config.hcl', // VAULT ×3 → cap 45
      'sssd.conf', 'ldap.conf', 'slapd.conf',                     // LDAP ×3 → cap 45
    ])
    expect(r.riskScore).toBe(90)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('deduplication (one finding per rule)', () => {
  it('multiple Vault files produce one VAULT_POLICY_DRIFT finding', () => {
    const r = scan(['vault-policy.hcl', 'vault-agent.hcl', 'vault.hcl'])
    expect(ruleIds(r).filter((id) => id === 'VAULT_POLICY_DRIFT')).toHaveLength(1)
  })

  it('matchCount reflects number of matched paths', () => {
    const r = scan(['vault-policy.hcl', 'vault-agent.hcl', 'vault-config.hcl'])
    const finding = r.findings.find((f) => f.ruleId === 'VAULT_POLICY_DRIFT')
    expect(finding?.matchCount).toBe(3)
  })

  it('matchedPath is the first matched path', () => {
    const r = scan(['vault-policy.hcl', 'vault-agent.hcl'])
    const finding = r.findings.find((f) => f.ruleId === 'VAULT_POLICY_DRIFT')
    expect(finding?.matchedPath).toBe('vault-policy.hcl')
  })

  it('duplicate identical paths each count separately', () => {
    const r = scan(['sudoers', 'sudoers', 'sudoers'])
    const finding = r.findings.find((f) => f.ruleId === 'PRIVILEGED_ACCESS_DRIFT')
    expect(finding?.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Finding ordering
// ---------------------------------------------------------------------------

describe('finding ordering (high before medium before low)', () => {
  it('returns high findings before medium and low', () => {
    const r = scan(['casbin.conf', 'duo.conf', 'vault-policy.hcl'])
    const severities = r.findings.map((f) => f.severity)
    const highIdx  = severities.indexOf('high')
    const medIdx   = severities.indexOf('medium')
    const lowIdx   = severities.indexOf('low')
    if (highIdx !== -1 && medIdx !== -1) expect(highIdx).toBeLessThan(medIdx)
    if (medIdx  !== -1 && lowIdx  !== -1) expect(medIdx).toBeLessThan(lowIdx)
    if (highIdx !== -1 && lowIdx  !== -1) expect(highIdx).toBeLessThan(lowIdx)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('contains "none" message for empty result', () => {
    expect(scan([]).summary).toContain('No identity and access management')
  })

  it('mentions "high" count when high findings exist', () => {
    const r = scan(['vault-policy.hcl'])
    expect(r.summary).toContain('1 high')
  })

  it('mentions the top rule label (vault policy drift)', () => {
    const r = scan(['vault-policy.hcl'])
    expect(r.summary.toLowerCase()).toContain('vault policy drift')
  })

  it('uses plural "findings" for multiple', () => {
    const r = scan(['vault-policy.hcl', 'duo.conf'])
    expect(r.summary).toContain('findings')
  })

  it('uses singular "finding" for one', () => {
    const r = scan(['vault-policy.hcl'])
    expect(r.summary).toContain('finding')
  })

  it('mentions privilege escalation', () => {
    const r = scan(['vault-policy.hcl'])
    expect(r.summary.toLowerCase()).toContain('privilege escalation')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('handles backslash paths for Vault config', () => {
    expect(ruleIds(scan(['config\\vault\\app-policy.hcl']))).toContain('VAULT_POLICY_DRIFT')
  })

  it('handles backslash paths for PAM config', () => {
    expect(ruleIds(scan(['etc\\pam.d\\sshd']))).toContain('PRIVILEGED_ACCESS_DRIFT')
  })

  it('handles backslash paths for LDAP config', () => {
    expect(ruleIds(scan(['etc\\openldap\\ldap.conf']))).toContain('LDAP_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('touching Vault and PAM config triggers both rules', () => {
    const r = scan(['vault-policy.hcl', 'sudoers'])
    expect(ruleIds(r)).toContain('VAULT_POLICY_DRIFT')
    expect(ruleIds(r)).toContain('PRIVILEGED_ACCESS_DRIFT')
    expect(r.totalFindings).toBe(2)
    expect(r.highCount).toBe(2)
  })

  it('touching all 8 rule families triggers 8 findings', () => {
    const r = scan([
      'vault-policy.hcl',      // VAULT_POLICY_DRIFT
      'sssd.conf',             // LDAP_CONFIG_DRIFT
      'sudoers',               // PRIVILEGED_ACCESS_DRIFT
      'duo.conf',              // MFA_ENFORCEMENT_DRIFT
      'sp-metadata.xml',       // IDENTITY_FEDERATION_DRIFT
      'workload-identity.yaml', // SERVICE_ACCOUNT_DRIFT
      'password-policy.yaml',  // PASSWORD_POLICY_DRIFT
      'casbin.conf',           // APPLICATION_RBAC_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(3)
    expect(r.mediumCount).toBe(4)
    expect(r.lowCount).toBe(1)
  })

  it('matchCounts are tracked independently per rule', () => {
    const r = scan([
      'vault-policy.hcl', 'vault-agent.hcl',  // VAULT ×2
      'sssd.conf',                              // LDAP ×1
    ])
    const vaultFinding = r.findings.find((f) => f.ruleId === 'VAULT_POLICY_DRIFT')
    const ldapFinding  = r.findings.find((f) => f.ruleId === 'LDAP_CONFIG_DRIFT')
    expect(vaultFinding?.matchCount).toBe(2)
    expect(ldapFinding?.matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('IDENTITY_ACCESS_RULES registry completeness', () => {
  const EXPECTED_RULE_IDS = [
    'VAULT_POLICY_DRIFT',
    'LDAP_CONFIG_DRIFT',
    'PRIVILEGED_ACCESS_DRIFT',
    'MFA_ENFORCEMENT_DRIFT',
    'IDENTITY_FEDERATION_DRIFT',
    'SERVICE_ACCOUNT_DRIFT',
    'PASSWORD_POLICY_DRIFT',
    'APPLICATION_RBAC_DRIFT',
  ]

  it('has exactly 8 rules', () => {
    expect(IDENTITY_ACCESS_RULES).toHaveLength(8)
  })

  it('contains all expected rule IDs', () => {
    const ids = IDENTITY_ACCESS_RULES.map((r) => r.id)
    for (const id of EXPECTED_RULE_IDS) {
      expect(ids).toContain(id)
    }
  })

  it('every rule has a non-empty description and recommendation', () => {
    for (const rule of IDENTITY_ACCESS_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const highRules   = IDENTITY_ACCESS_RULES.filter((r) => r.severity === 'high')
    const mediumRules = IDENTITY_ACCESS_RULES.filter((r) => r.severity === 'medium')
    const lowRules    = IDENTITY_ACCESS_RULES.filter((r) => r.severity === 'low')
    expect(highRules).toHaveLength(3)
    expect(mediumRules).toHaveLength(4)
    expect(lowRules).toHaveLength(1)
  })
})
