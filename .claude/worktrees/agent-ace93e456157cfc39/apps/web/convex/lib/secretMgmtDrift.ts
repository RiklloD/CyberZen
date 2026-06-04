// WS-105 — Secret Management Configuration Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to secret management infrastructure configuration: HashiCorp Vault server and
// policy configuration (vault.hcl, *.hcl in vault policy dirs), AWS Secrets
// Manager access configuration (secrets-manager.json / rotation lambda configs),
// Azure Key Vault access policies (keyvault-*.json / azure-key-vault.yaml),
// Google Cloud Secret Manager configs (secretmanager-*.yaml), SOPS encryption
// configuration (.sops.yaml, age and PGP key references), Kubernetes Sealed
// Secrets controller configuration, Doppler/1Password Connect/Infisical
// integration configs, and secret rotation schedule/policy configuration.
//
// Distinct from:
//   WS-30  (secrets detection: finds hardcoded secrets in code/config files)
//   WS-62  (cloud security drift: IAM / S3 bucket policy / VPC security groups)
//   WS-66  (cert/PKI drift: TLS certificates, SSH keys, GPG keyrings, cosign)
//   WS-70  (identity/access drift: Vault auth methods belong here when used as
//           IdP — but this module focuses on Vault as a secret storage backend)
//   WS-83  (config management: Ansible Vault encryption is separate from
//           HashiCorp Vault server configuration)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '')
}

const VENDOR_DIRS = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '.cache/',
  'target/', '__pycache__/', '.venv/', 'venv/',
]

function isVendorPath(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Rule 1: VAULT_SERVER_DRIFT (high)
// ---------------------------------------------------------------------------
// HashiCorp Vault server configuration controls the storage backend, listener
// TLS settings, seal configuration (auto-unseal key), audit devices, and
// telemetry.  Drift here can disable auditing, change the unseal mechanism,
// or redirect traffic through a compromised listener.

const VAULT_SERVER_UNGATED = new Set([
  'vault.hcl', 'vault.json', 'vault.yaml', 'vault.yml',
  'vault-config.hcl', 'vault-config.json', 'vault-config.yaml',
  'vault-server.hcl', 'vault-server.json',
  'vault-agent.hcl', 'vault-agent.json', 'vault-agent.yaml',
])

const VAULT_SERVER_DIRS = [
  'vault/', 'vault-config/', 'hashicorp-vault/', 'hashi-vault/',
  'hvault/', 'vault-server/', 'vault-agent/', 'secrets/vault/',
]

function isVaultServerConfig(path: string, base: string): boolean {
  if (VAULT_SERVER_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('vault-') ||
    base.startsWith('hvault-')
  ) {
    return /\.(hcl|json|yaml|yml|tf|tfvars)$/.test(base)
  }

  return VAULT_SERVER_DIRS.some((d) => low.includes(d)) &&
    /\.(hcl|json|yaml|yml|conf|cfg|tf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: VAULT_POLICY_DRIFT (high)
// ---------------------------------------------------------------------------
// Vault policies (HCL ACL rules) determine which paths each identity can
// read/write/delete.  A modified policy can silently escalate privileges or
// revoke legitimate access, making this a high-impact drift category.

const VAULT_POLICY_DIRS = [
  'vault/policies/', 'vault/policy/', 'vault-policies/', 'vault-policy/',
  'policies/vault/', 'policy/vault/', 'secrets/policies/',
]

function isVaultPolicyConfig(path: string, base: string): boolean {
  const low = path.toLowerCase()

  // *.hcl in vault policy directories
  if (/\.hcl$/.test(base) && VAULT_POLICY_DIRS.some((d) => low.includes(d))) {
    return true
  }

  if (
    base.startsWith('vault-policy-') ||
    base.startsWith('vault-acl-') ||
    base.startsWith('policy-vault-')
  ) {
    return /\.(hcl|json|yaml|yml)$/.test(base)
  }

  return VAULT_POLICY_DIRS.some((d) => low.includes(d)) &&
    /\.(hcl|json|yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: AWS_SECRETS_MANAGER_DRIFT (high)
// ---------------------------------------------------------------------------
// AWS Secrets Manager configuration covers resource policies, rotation
// schedules, and the Lambda rotation function code.  Changes here can disable
// rotation, alter access policies, or redirect rotation to attacker-controlled
// functions.

const AWS_SM_UNGATED = new Set([
  'secrets-manager.json', 'secrets-manager.yaml', 'secrets-manager.yml',
  'aws-secrets-manager.json', 'aws-secrets-manager.yaml',
  'secretsmanager.json', 'secretsmanager.yaml',
])

const AWS_SM_DIRS = [
  'secrets-manager/', 'aws-secrets/', 'aws-secrets-manager/',
  'secretsmanager/', 'rotation/', 'secret-rotation/', 'secrets/aws/',
]

function isAwsSecretsManagerConfig(path: string, base: string): boolean {
  if (AWS_SM_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('secrets-manager-') ||
    base.startsWith('aws-sm-') ||
    base.startsWith('secretsmanager-') ||
    base.startsWith('secret-rotation-')
  ) {
    return /\.(json|yaml|yml|py|js|ts)$/.test(base)
  }

  return AWS_SM_DIRS.some((d) => low.includes(d)) &&
    /\.(json|yaml|yml|tf|py|js|ts|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: AZURE_KEY_VAULT_DRIFT (high)
// ---------------------------------------------------------------------------
// Azure Key Vault access policies and RBAC assignments control which principals
// can read, write, or delete secrets, keys, and certificates.  Unauthorised
// changes here represent privilege escalation in Azure environments.

const AZURE_KV_UNGATED = new Set([
  'azure-key-vault.json', 'azure-key-vault.yaml', 'azure-key-vault.yml',
  'key-vault.json', 'key-vault.yaml', 'keyvault.json', 'keyvault.yaml',
  'akv.json', 'akv.yaml',
])

const AZURE_KV_DIRS = [
  'azure-key-vault/', 'key-vault/', 'keyvault/', 'akv/',
  'azure/key-vault/', 'azure/keyvault/', 'secrets/azure/',
]

function isAzureKeyVaultConfig(path: string, base: string): boolean {
  if (AZURE_KV_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('azure-key-vault-') ||
    base.startsWith('keyvault-') ||
    base.startsWith('key-vault-') ||
    base.startsWith('akv-')
  ) {
    return /\.(json|yaml|yml|bicep|tf|tfvars)$/.test(base)
  }

  return AZURE_KV_DIRS.some((d) => low.includes(d)) &&
    /\.(json|yaml|yml|bicep|tf|tfvars|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: SOPS_ENCRYPTION_DRIFT (medium)
// ---------------------------------------------------------------------------
// SOPS .sops.yaml defines creation rules: which keys (age, PGP, AWS KMS,
// Azure Key Vault, GCP KMS) encrypt which files.  A tampered .sops.yaml can
// add an attacker-controlled key that decrypts every newly-committed secret,
// or remove keys to lock out legitimate operators.

const SOPS_UNGATED = new Set([
  '.sops.yaml', '.sops.yml', '.sops.json',
  'sops.yaml', 'sops.yml', 'sops.json',
  '.sopsrc', 'sopsrc',
])

const SOPS_DIRS = [
  'sops/', '.sops/', 'sops-config/', 'secrets/sops/', 'encrypted/',
]

function isSopsEncryptionConfig(path: string, base: string): boolean {
  if (SOPS_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('sops-') ||
    base.startsWith('.sops-')
  ) {
    return /\.(yaml|yml|json|conf)$/.test(base)
  }

  return SOPS_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|conf|cfg)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: SEALED_SECRETS_DRIFT (medium)
// ---------------------------------------------------------------------------
// Bitnami Sealed Secrets controller configuration governs which namespaces can
// unseal secrets, the sealing certificate rotation policy, and custom
// encryption scopes.  Drift can allow cross-namespace secret access or
// silently rotate the sealing key without auditing.

const SEALED_SECRETS_UNGATED = new Set([
  'sealed-secrets.yaml', 'sealed-secrets.yml', 'sealed-secrets.json',
  'sealedsecrets.yaml', 'sealedsecrets.yml',
  'sealed-secrets-controller.yaml', 'sealed-secrets-controller.yml',
])

const SEALED_SECRETS_DIRS = [
  'sealed-secrets/', 'sealedsecrets/', 'bitnami-sealed-secrets/',
  'k8s/sealed-secrets/', 'kubernetes/sealed-secrets/', 'secrets/sealed/',
]

function isSealedSecretsConfig(path: string, base: string): boolean {
  if (SEALED_SECRETS_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('sealed-secrets-') ||
    base.startsWith('sealedsecrets-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return SEALED_SECRETS_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: EXTERNAL_SECRET_OPERATOR_DRIFT (medium)
// ---------------------------------------------------------------------------
// External Secrets Operator (ESO) defines SecretStore and ClusterSecretStore
// resources that connect Kubernetes workloads to external secret backends.
// Drift can redirect which backend is consulted or change the authentication
// credentials used to access it.

const ESO_UNGATED = new Set([
  'external-secrets.yaml', 'external-secrets.yml',
  'secret-store.yaml', 'secret-store.yml',
  'cluster-secret-store.yaml', 'cluster-secret-store.yml',
  'external-secret.yaml', 'external-secret.yml',
])

const ESO_DIRS = [
  'external-secrets/', 'eso/', 'secret-store/', 'secretstore/',
  'k8s/external-secrets/', 'kubernetes/external-secrets/', 'secrets/eso/',
]

function isExternalSecretOperatorConfig(path: string, base: string): boolean {
  if (ESO_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('external-secrets-') ||
    base.startsWith('secret-store-') ||
    base.startsWith('eso-') ||
    base.startsWith('secretstore-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return ESO_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: SECRET_PROVIDER_INTEGRATION_DRIFT (low) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures a third-party secret provider
// integration: Doppler environment configs, 1Password Connect server or
// Connect token configs, Infisical project configs, or generic secrets-manager
// bridge configuration files.
//
// Trade-offs to consider:
//   - doppler.yaml is a common project-level config but also appears in other
//     tools — match ungated since "doppler" is a distinctive namespace
//   - .infisical.json is project-level and always security-relevant
//   - 1password-credentials.json is service-account specific to 1Password
//   - generic "secrets.yaml" in secrets/ dirs is too noisy; use prefix matching
//     or require well-known provider dirs

const SECRET_PROVIDER_UNGATED = new Set([
  'doppler.yaml', 'doppler.yml', 'doppler.json', '.doppler.yaml',
  '.doppler.yml', '.doppler.json', 'doppler-config.yaml',
  '.infisical.json', 'infisical.json', 'infisical.yaml', 'infisical.yml',
  '1password-credentials.json', 'op-credentials.json',
  'onepassword-connect.yaml', 'onepassword-connect.yml',
])

const SECRET_PROVIDER_DIRS = [
  'doppler/', '.doppler/', 'infisical/', '.infisical/',
  '1password/', 'onepassword/', 'op-connect/', '1password-connect/',
  'secrets-provider/', 'secret-providers/', 'secrets/providers/',
]

export function isSecretProviderIntegrationConfig(path: string, base: string): boolean {
  if (SECRET_PROVIDER_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('doppler-') ||
    base.startsWith('infisical-') ||
    base.startsWith('1password-') ||
    base.startsWith('onepassword-') ||
    base.startsWith('op-connect-') ||
    base.startsWith('op-credentials-')
  ) {
    return /\.(yaml|yml|json|conf|cfg)$/.test(base)
  }

  return SECRET_PROVIDER_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|conf|cfg|env)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type SecretMgmtDriftRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: SecretMgmtDriftRule[] = [
  {
    id: 'VAULT_SERVER_DRIFT',
    severity: 'high',
    description: 'HashiCorp Vault server configuration modified (vault.hcl / vault-agent.hcl).',
    recommendation: 'Audit changes to the storage backend, listener TLS settings, seal configuration, and audit device definitions; verify the unseal mechanism and auto-unseal key reference have not been altered; ensure audit devices are still enabled.',
    match: isVaultServerConfig,
  },
  {
    id: 'VAULT_POLICY_DRIFT',
    severity: 'high',
    description: 'HashiCorp Vault access policy modified (*.hcl in vault/policies/).',
    recommendation: 'Review path capability changes for privilege escalation; confirm no new wildcard grants or deny overrides have been introduced; verify the modified policy still follows least-privilege; cross-reference with recent Vault audit log entries.',
    match: isVaultPolicyConfig,
  },
  {
    id: 'AWS_SECRETS_MANAGER_DRIFT',
    severity: 'high',
    description: 'AWS Secrets Manager access configuration or rotation schedule modified.',
    recommendation: 'Inspect changes to resource policies for unintended cross-account access; verify rotation lambda ARN and schedule have not been altered; confirm KMS key reference for secret encryption is unchanged.',
    match: isAwsSecretsManagerConfig,
  },
  {
    id: 'AZURE_KEY_VAULT_DRIFT',
    severity: 'high',
    description: 'Azure Key Vault access policy or RBAC assignment configuration modified.',
    recommendation: 'Review principal additions and permission changes for privilege escalation; confirm that no new principals with Get/List/Set capabilities have been added; verify the Key Vault firewall rules and virtual network service endpoint policies are intact.',
    match: isAzureKeyVaultConfig,
  },
  {
    id: 'SOPS_ENCRYPTION_DRIFT',
    severity: 'medium',
    description: 'SOPS encryption configuration modified (.sops.yaml creation rules).',
    recommendation: 'Audit recipient key additions and removals in creation rules; an added age or PGP fingerprint can silently decrypt all newly-committed secrets; verify the KMS key ARN / Azure Key Vault URL / GCP KMS resource name have not changed.',
    match: isSopsEncryptionConfig,
  },
  {
    id: 'SEALED_SECRETS_DRIFT',
    severity: 'medium',
    description: 'Bitnami Sealed Secrets controller configuration modified.',
    recommendation: 'Review scope changes (cluster-wide vs namespace-scoped sealing); verify sealing certificate rotation settings; check that no additional namespaces have been granted access to unseal resources they should not read.',
    match: isSealedSecretsConfig,
  },
  {
    id: 'EXTERNAL_SECRET_OPERATOR_DRIFT',
    severity: 'medium',
    description: 'External Secrets Operator SecretStore or ClusterSecretStore configuration modified.',
    recommendation: 'Audit backend provider changes and authentication credential references; a modified SecretStore can redirect secret lookups to a different backend or use different credentials; verify the provider endpoint and auth method are unchanged.',
    match: isExternalSecretOperatorConfig,
  },
  {
    id: 'SECRET_PROVIDER_INTEGRATION_DRIFT',
    severity: 'low',
    description: 'Third-party secret provider integration configuration modified (Doppler / 1Password Connect / Infisical).',
    recommendation: 'Verify the project or environment reference has not been changed to pull secrets from an untrusted workspace; audit Connect server URL and credentials; rotate any service-account tokens if the integration credentials file was modified.',
    match: isSecretProviderIntegrationConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP: Record<Severity, number>     = { high: 45, medium: 25, low: 15 }

function computeRiskLevel(score: number): SecretMgmtDriftResult['riskLevel'] {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type SecretMgmtDriftFinding = {
  ruleId: string
  severity: Severity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type SecretMgmtDriftResult = {
  riskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none'
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: SecretMgmtDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// scanSecretMgmtDrift
// ---------------------------------------------------------------------------

export function scanSecretMgmtDrift(changedFiles: string[]): SecretMgmtDriftResult {
  const normalised = changedFiles
    .map(normalise)
    .filter((p) => !isVendorPath(p))

  const findings: SecretMgmtDriftFinding[] = []
  const perRuleScore: Record<string, number> = {}

  for (const rule of RULES) {
    const matched: string[] = []

    for (const p of normalised) {
      const base = p.split('/').pop() ?? p
      if (rule.match(p, base)) {
        matched.push(p)
      }
    }

    if (matched.length === 0) continue

    const penalty = SEVERITY_PENALTY[rule.severity]
    const cap     = SEVERITY_CAP[rule.severity]
    perRuleScore[rule.id] = Math.min(penalty, cap)

    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    matched[0],
      matchCount:     matched.length,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  const totalScore = Math.min(
    Object.values(perRuleScore).reduce((a, b) => a + b, 0),
    100,
  )

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const riskLevel = computeRiskLevel(totalScore)

  let summary: string
  if (findings.length === 0) {
    summary = 'No secret management configuration drift detected.'
  } else {
    const parts: string[] = []
    if (highCount > 0)   parts.push(`${highCount} high`)
    if (mediumCount > 0) parts.push(`${mediumCount} medium`)
    if (lowCount > 0)    parts.push(`${lowCount} low`)
    summary = `Secret management configuration drift detected: ${parts.join(', ')} severity finding${findings.length > 1 ? 's' : ''}. Risk score ${totalScore}/100 (${riskLevel}).`
  }

  return {
    riskScore:     totalScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
