// WS-70 — Identity & Privileged Access Management Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to identity and privileged access management (IAM/PAM) configuration files.
// This scanner focuses on the *identity control layer* — the configs that
// govern who can access what, at what privilege level, and through which
// authentication mechanisms.
//
// DISTINCT from:
//   WS-60  securityConfigDriftResults — OAuth CLIENT configs (oauth.config,
//                                        saml.config, okta.config) — the
//                                        application's view of its IdP
//   WS-62  cloudSecurityDriftResults  — cloud provider IAM resource policies
//                                        (AWS IAM JSON, Azure RBAC, Terraform
//                                        IAM modules) — cloud-plane permissions
//   WS-63  containerHardeningDriftResults — Kubernetes Role/RoleBinding/
//                                        ClusterRole RBAC specifically
//   WS-66  certPkiDriftResults        — cryptographic keys and SSH auth keys,
//                                        not access policy files
//   WS-67  runtimeSecurityDriftResults — runtime enforcement (fail2ban,
//                                        auditd, IDS rules), not identity
//
// WS-70 vs WS-60: WS-60 detects changes to oauth.config/keycloak.config —
//   the *application's registered OAuth client* settings. WS-70 detects
//   changes to Vault policies, LDAP directory service configs, and SAML
//   *federation metadata* — the identity infrastructure itself.
//
// WS-70 vs WS-62: WS-62 covers cloud IAM *resource policies* (what cloud
//   resources a role can access). WS-70 covers HashiCorp Vault *access
//   policies* (what secrets a workload can read), host-level PAM/sudo, and
//   application-layer RBAC frameworks (Casbin/Oso/CASL) — none of which are
//   cloud-provider-specific.
//
// Covered rule groups (8 rules):
//
//   VAULT_POLICY_DRIFT         — HashiCorp Vault policy and agent config files
//   LDAP_CONFIG_DRIFT          — LDAP/AD directory service configuration
//   PRIVILEGED_ACCESS_DRIFT    — PAM modules and sudo privilege configuration
//   MFA_ENFORCEMENT_DRIFT      — MFA/2FA policy enforcement configs
//   IDENTITY_FEDERATION_DRIFT  — SAML/OIDC federation metadata and SCIM
//   SERVICE_ACCOUNT_DRIFT      — workload identity / service account files ← user contribution
//   PASSWORD_POLICY_DRIFT      — password strength and lockout policy configs
//   APPLICATION_RBAC_DRIFT     — Casbin / Oso / CASL / Zanzibar app-level RBAC
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–69 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • .hcl extension is not unambiguous (Terraform uses it) — Vault rules
//     require directory gating or vault-prefixed filenames.
//   • PAM files in pam.d/ are high-confidence; generic pam-config.yaml
//     requires the directory context or a pam- prefix.
//   • LDAP exact filenames (ldap.conf, slapd.conf) are common enough to be
//     unambiguous without directory gating.
//   • Service account JSON files require careful scoping to avoid overlapping
//     with WS-62 (cloud IAM) and WS-63 (k8s) — the user contribution handles
//     this disambiguation.
//
// Exports:
//   isServiceAccountFile       — user contribution point (see JSDoc below)
//   IDENTITY_ACCESS_RULES      — readonly rule registry
//   scanIdentityAccessDrift    — main scanner, returns IdentityAccessDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IdentityAccessRuleId =
  | 'VAULT_POLICY_DRIFT'
  | 'LDAP_CONFIG_DRIFT'
  | 'PRIVILEGED_ACCESS_DRIFT'
  | 'MFA_ENFORCEMENT_DRIFT'
  | 'IDENTITY_FEDERATION_DRIFT'
  | 'SERVICE_ACCOUNT_DRIFT'
  | 'PASSWORD_POLICY_DRIFT'
  | 'APPLICATION_RBAC_DRIFT'

export type IdentityAccessSeverity = 'high' | 'medium' | 'low'
export type IdentityAccessRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type IdentityAccessDriftFinding = {
  ruleId: IdentityAccessRuleId
  severity: IdentityAccessSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type IdentityAccessDriftResult = {
  riskScore: number
  riskLevel: IdentityAccessRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: IdentityAccessDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/', '.git/', 'dist/', 'build/', '.next/', '.nuxt/',
  'vendor/', 'bower_components/', 'coverage/', '__pycache__/',
  '.terraform/', 'cdk.out/', '.cdk/', '.gradle/', '.m2/',
  'target/', 'out/', '.idea/', '.vscode/', '.cache/',
]

const HIGH_PENALTY_PER = 15
const HIGH_PENALTY_CAP = 45
const MED_PENALTY_PER  = 8
const MED_PENALTY_CAP  = 25
const LOW_PENALTY_PER  = 4
const LOW_PENALTY_CAP  = 15

// ---------------------------------------------------------------------------
// Detection helpers — VAULT_POLICY_DRIFT
// ---------------------------------------------------------------------------

const VAULT_EXACT = new Set([
  'vault-policy.hcl', 'vault-agent.hcl', 'vault-config.hcl',
  'vault.hcl', 'vault-server.hcl',
  'vault-policy.json', 'vault-agent-config.hcl',
  'approle-policy.hcl', 'cubbyhole-policy.hcl',
])

const VAULT_DIRS = ['vault/', '.vault/', 'vault-policies/', 'vault-config/']

function isVaultPolicyFile(pathLower: string, base: string): boolean {
  if (VAULT_EXACT.has(base)) return true
  for (const dir of VAULT_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // vault-prefixed HCL or JSON config files
  if ((base.startsWith('vault-') || base.startsWith('vault_')) &&
      (base.endsWith('.hcl') || base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — LDAP_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const LDAP_EXACT = new Set([
  'ldap.conf', 'openldap.conf', 'ldap.cfg',
  'slapd.conf', 'slapd.d',
  'sssd.conf', 'nslcd.conf', 'realmd.conf',
  'ldap-config.yaml', 'ldap-config.yml', 'ldap-config.json',
  'ad-config.yaml', 'active-directory.yaml',
])

const LDAP_DIRS = [
  'ldap/', '.ldap/', 'openldap/', '.openldap/',
  'sssd/', 'etc/ldap/', 'etc/openldap/', 'etc/sssd/',
]

function isLdapConfigFile(pathLower: string, base: string): boolean {
  if (LDAP_EXACT.has(base)) return true
  for (const dir of LDAP_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // ldap- or sssd- prefixed config files
  if (base.startsWith('ldap-') || base.startsWith('sssd-') || base.startsWith('openldap-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — PRIVILEGED_ACCESS_DRIFT
// ---------------------------------------------------------------------------

const PAM_EXACT = new Set([
  'sudoers', 'sudo.conf', 'sudo-ldap.conf',
  'pam.conf', 'pam-config.yaml', 'pam-config.yml',
  'pam_unix.conf', 'pam_tally2.conf',
  'access.conf',                               // /etc/security/access.conf
  'limits.conf',                               // /etc/security/limits.conf
  'suauth',                                    // su authorization rules
])

const PAM_DIRS = [
  'pam.d/', 'etc/pam.d/', 'etc/sudoers.d/', 'sudoers.d/',
  'etc/security/', 'security/',
]

function isPrivilegedAccessFile(pathLower: string, base: string): boolean {
  if (PAM_EXACT.has(base)) return true
  for (const dir of PAM_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // pam- or sudo- prefixed config files
  if (base.startsWith('pam-') || base.startsWith('sudo-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — MFA_ENFORCEMENT_DRIFT
// ---------------------------------------------------------------------------

const MFA_EXACT = new Set([
  'duo.conf', 'duo.ini', 'duo-config.yaml',
  'google-authenticator.conf', '.google_authenticator',
  'yubikey-policy.yaml', 'yubikey-policy.yml', 'yubikey.conf',
  'totp-policy.yaml', 'totp-policy.yml',
  'mfa-policy.yaml', 'mfa-policy.yml', 'mfa-config.yaml', 'mfa-config.yml',
  'pam_google_authenticator',
  'fido2-policy.yaml', 'webauthn-policy.yaml',
])

const MFA_DIRS = ['duo/', '.duo/', 'mfa/', 'totp/', 'yubikey/', 'etc/duo/']

function isMfaEnforcementFile(pathLower: string, base: string): boolean {
  if (MFA_EXACT.has(base)) return true
  for (const dir of MFA_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // duo- or mfa- prefixed files
  if (base.startsWith('duo-') || base.startsWith('mfa-') || base.startsWith('yubikey-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — IDENTITY_FEDERATION_DRIFT
// ---------------------------------------------------------------------------

const FEDERATION_EXACT = new Set([
  'sp-metadata.xml', 'idp-metadata.xml',
  'federation.xml', 'saml-metadata.xml',
  'trust-federation.xml', 'federation-metadata.xml',
  'shibboleth.xml', 'shibboleth2.xml',
  'scim-config.yaml', 'scim-config.yml',
  'scim-provisioning.yaml', 'scim-provisioning.yml',
  'oidc-provider.yaml', 'oidc-provider.yml',
  'oidc-config.yaml', 'oidc-config.yml',
])

const FEDERATION_DIRS = ['saml/', 'sso/saml/', 'federation/', 'scim/', 'shibboleth/']

function isIdentityFederationFile(pathLower: string, base: string): boolean {
  if (FEDERATION_EXACT.has(base)) return true
  for (const dir of FEDERATION_DIRS) {
    if (pathLower.includes(dir)) {
      // In SAML/federation directories, any XML, YAML, or JSON is relevant
      if (base.endsWith('.xml') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
    }
  }
  // Federation-specific prefix patterns
  if ((base.startsWith('sp-') || base.startsWith('idp-') || base.startsWith('saml-')) &&
      (base.endsWith('.xml') || base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// SERVICE_ACCOUNT_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isServiceAccountFile — determines whether a file path is a workload identity
 * or service account credential/config file that is NOT already covered by:
 *   - WS-62 (cloudSecurityDrift): AWS IAM policy JSON attached to cloud resources,
 *     Azure RBAC definitions, GCP IAM bindings in Terraform/cloud configs
 *   - WS-63 (containerHardeningDrift): Kubernetes ServiceAccount manifests and
 *     RBAC Role/ClusterRole resources
 *
 * Target files: application-level workload identity configs, GCP service account
 * key files (the downloaded JSON key), AWS credential files used by a service,
 * and workload identity federation configs that live in the application repo
 * rather than in infrastructure code.
 *
 * Core ambiguity: "service-account.json" can be a GCP key file (critical — must
 * detect), a Node.js config file naming a service (should not flag), or a
 * k8s ServiceAccount manifest (already covered by WS-63 — do not double-count).
 *
 * Design trade-offs to consider:
 *
 *   (a) GCP key file detection: files named exactly `service-account.json` or
 *       matching `*-sa.json` / `*-service-account.json` in non-vendor,
 *       non-k8s-manifest directories. GCP key files contain "type":
 *       "service_account" but we cannot read content — the filename itself is
 *       the signal.
 *
 *   (b) k8s exclusion: files inside k8s/, kubernetes/, kustomize/, helm/, or
 *       charts/ directories should be skipped here (WS-63 covers them). The
 *       same file in config/ or credentials/ should be flagged.
 *
 *   (c) Workload identity federation: files such as workload-identity.yaml,
 *       workload-identity-pool.yaml, and github-actions-wif.yaml are
 *       application-level identity bindings — flag regardless of directory.
 *
 *   (d) AWS credential files: ~/.aws/credentials style files committed by
 *       mistake; aws-credentials.json, credentials.json in iam/ dirs. Avoid
 *       overlap with WS-30 (hardcoded credential detection) which uses regex
 *       content scanning — path-only detection is complementary, not redundant.
 *
 * Implement to return true for service account credential/config files
 * and false for k8s manifests already covered by WS-63, cloud IAM resource
 * policy files covered by WS-62, and generic JSON config files.
 */
export function isServiceAccountFile(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

  // k8s manifest directories — skip (WS-63 covers these)
  const K8S_DIRS = ['k8s/', 'kubernetes/', 'kustomize/', 'helm/', 'charts/', 'manifests/']
  for (const dir of K8S_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  // Terraform/IaC directories — skip (WS-62 covers these)
  const IAC_DIRS = ['terraform/', 'pulumi/', 'cdk/', 'cloudformation/', 'bicep/']
  for (const dir of IAC_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  // Canonical exact filenames — always flag
  const SA_EXACT = new Set([
    'service-account.json', 'serviceaccount.json',
    'gcp-service-account.json', 'gcp-sa.json',
    'workload-identity.yaml', 'workload-identity.yml',
    'workload-identity-pool.yaml',
    'github-actions-wif.yaml', 'github-actions-wif.json',
    'aws-credentials.json', 'credentials.json',
  ])
  if (SA_EXACT.has(base)) return true

  // Workload identity federation files — flag regardless of directory
  if ((base.includes('workload-identity') || base.includes('wif-config')) &&
      (ext === '.yaml' || ext === '.yml' || ext === '.json')) {
    return true
  }

  // Service account key file patterns (GCP-style: *-sa.json, *-service-account.json)
  if ((base.endsWith('-sa.json') || base.endsWith('-service-account.json') ||
       base.endsWith('-serviceaccount.json') || base.endsWith('_sa.json'))) {
    return true
  }

  // AWS/GCP credential files in IAM or credentials directories
  const IAM_DIRS = ['iam/', 'credentials/', '.credentials/', 'secrets/', '.secrets/']
  for (const dir of IAM_DIRS) {
    if (pathLower.includes(dir) && (ext === '.json' || ext === '.yaml' || ext === '.yml')) return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — PASSWORD_POLICY_DRIFT
// ---------------------------------------------------------------------------

const PASSWORD_EXACT = new Set([
  'password-policy.yaml', 'password-policy.yml',
  'password-policy.json', 'pwquality.conf',
  'pam_pwquality.conf', 'passwdqc.conf',
  'cracklib.conf', '.cracklib_options',
  'pam_cracklib.conf', 'login.defs',
])

const PASSWORD_DIRS = ['etc/security/', 'security/']

function isPasswordPolicyFile(pathLower: string, base: string): boolean {
  if (PASSWORD_EXACT.has(base)) return true
  for (const dir of PASSWORD_DIRS) {
    if (pathLower.includes(dir) && (base.includes('password') || base.includes('passwd') || base.includes('pwquality'))) return true
  }
  if (base.startsWith('password-policy') || base.startsWith('passwd-policy')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — APPLICATION_RBAC_DRIFT
// ---------------------------------------------------------------------------

const APP_RBAC_EXACT = new Set([
  'casbin.conf', 'casbin.yaml', 'casbin.yml',
  'model.conf',                                // Casbin model file
  'policy.csv', 'rbac_policy.csv',             // Casbin policy
  'oso-policy.polar', '.oso-policy.polar',
  'authorization.polar',
  'permissions.yaml', 'permissions.yml',
  'permission-bindings.yaml', 'permission-bindings.yml',
  'zanzibar.yaml', 'zanzibar.yml',
  'fga-model.json',                            // OpenFGA
  'authz-model.json',
  'casl-abilities.ts', 'casl-abilities.js',
  'abilities.ts', 'abilities.js',
])

const APP_RBAC_DIRS = ['casbin/', 'rbac/', 'authz/', 'authorization/', 'permissions/', 'oso/', 'fga/']

function isApplicationRbacFile(pathLower: string, base: string): boolean {
  if (APP_RBAC_EXACT.has(base)) return true
  for (const dir of APP_RBAC_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // Casbin / Oso / CASL / OpenFGA specific patterns
  if (base.includes('casbin') || base.includes('.polar')) return true
  if (base.includes('openfga') || base.includes('zanzibar')) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type IdentityAccessRule = {
  id: IdentityAccessRuleId
  severity: IdentityAccessSeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const IDENTITY_ACCESS_RULES: readonly IdentityAccessRule[] = [
  {
    id: 'VAULT_POLICY_DRIFT',
    severity: 'high',
    description: 'HashiCorp Vault policy or agent configuration files were modified. Changes can expand which secrets workloads are permitted to read, silently elevating privilege without audit trail.',
    recommendation: 'Review all capability changes — especially any removal of `deny` statements or expansion of `read`/`list`/`delete` paths. Vault policy changes should require a security review and be versioned in an approved change management workflow.',
    matches: (p, b) => isVaultPolicyFile(p, b),
  },
  {
    id: 'LDAP_CONFIG_DRIFT',
    severity: 'high',
    description: 'LDAP or Active Directory configuration files (slapd.conf, sssd.conf, ldap.conf) were modified. Changes can affect directory authentication, group membership resolution, and access control enforcement.',
    recommendation: 'Audit whether bind DN credentials, access control lists, or search base configurations changed. LDAP config changes that affect authentication binding should be peer-reviewed and tested in a staging directory environment.',
    matches: (p, b) => isLdapConfigFile(p, b),
  },
  {
    id: 'PRIVILEGED_ACCESS_DRIFT',
    severity: 'high',
    description: 'PAM module configuration or sudo privilege files (pam.d/, sudoers) were modified. These files control host-level privilege escalation — changes can grant unrestricted root access or bypass password authentication entirely.',
    recommendation: 'Verify that no new users or groups received unrestricted sudo access and that no PAM modules were removed or reordered in a way that could bypass authentication. Any sudoers change should be reviewed by a security engineer.',
    matches: (p, b) => isPrivilegedAccessFile(p, b),
  },
  {
    id: 'MFA_ENFORCEMENT_DRIFT',
    severity: 'medium',
    description: 'Multi-factor authentication policy or enforcement configuration files (Duo, Google Authenticator, YubiKey, TOTP) were modified. Weakening MFA enforcement can create authentication bypass paths for high-privilege accounts.',
    recommendation: 'Confirm that MFA requirements were not downgraded or made optional for privileged users. MFA bypass exceptions should be time-bounded and documented with a business justification.',
    matches: (p, b) => isMfaEnforcementFile(p, b),
  },
  {
    id: 'IDENTITY_FEDERATION_DRIFT',
    severity: 'medium',
    description: 'SAML federation metadata, OIDC provider configurations, or SCIM provisioning files were modified. Changes can introduce unauthorized identity providers or alter which user attributes are trusted for authorization decisions.',
    recommendation: 'Review whether any new identity providers were registered, existing providers were reconfigured, or attribute mapping logic changed. Federation config changes require validation against the registered IdP metadata.',
    matches: (p, b) => isIdentityFederationFile(p, b),
  },
  {
    id: 'SERVICE_ACCOUNT_DRIFT',
    severity: 'medium',
    description: 'Workload identity, service account credential, or IAM binding files were modified. These files control which cloud resources or secrets the application is authorized to access as a non-human identity.',
    recommendation: 'Verify that no service account keys were added or rotated without authorization, and that workload identity bindings were not broadened. Service account files with broad cloud permissions should be treated with the same care as root credentials.',
    matches: (p) => isServiceAccountFile(p),
  },
  {
    id: 'PASSWORD_POLICY_DRIFT',
    severity: 'medium',
    description: 'Password quality, complexity, or lockout policy configuration files were modified. Weakening password requirements increases susceptibility to brute-force and credential-stuffing attacks.',
    recommendation: 'Confirm that minimum length, complexity requirements, and lockout thresholds were not reduced. Password policy changes should be reviewed against current NIST 800-63B guidelines and any applicable compliance framework requirements.',
    matches: (p, b) => isPasswordPolicyFile(p, b),
  },
  {
    id: 'APPLICATION_RBAC_DRIFT',
    severity: 'low',
    description: 'Application-level authorization framework configuration files (Casbin, Oso, CASL, OpenFGA) were modified. Changes to role-permission mappings can introduce unintended privilege escalation within the application.',
    recommendation: 'Review whether any new role-to-permission mappings were added or existing restrictions were removed. Authorization policy changes should be reviewed alongside the application code that enforces them.',
    matches: (p, b) => isApplicationRbacFile(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: IdentityAccessSeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): IdentityAccessRiskLevel {
  if (score === 0)  return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanIdentityAccessDrift(filePaths: string[]): IdentityAccessDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<IdentityAccessRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of IDENTITY_ACCESS_RULES) {
      if (rule.matches(pathLower, base, ext)) {
        const existing = accumulated.get(rule.id)
        if (existing) {
          existing.count += 1
        } else {
          accumulated.set(rule.id, { firstPath: path, count: 1 })
        }
      }
    }
  }

  if (accumulated.size === 0) return emptyResult()

  const SEVERITY_ORDER: Record<IdentityAccessSeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: IdentityAccessDriftFinding[] = []

  for (const rule of IDENTITY_ACCESS_RULES) {
    const match = accumulated.get(rule.id)
    if (!match) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    match.firstPath,
      matchCount:     match.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

  return { riskScore, riskLevel, totalFindings: findings.length, highCount, mediumCount, lowCount, findings, summary }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): IdentityAccessDriftResult {
  return {
    riskScore: 0, riskLevel: 'none',
    totalFindings: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    findings: [], summary: 'No identity and access management configuration drift detected.',
  }
}

function buildSummary(
  level: IdentityAccessRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: IdentityAccessDriftFinding[],
): string {
  if (level === 'none') return 'No identity and access management configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'identity config'

  return `Identity and access management drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure no privilege escalation paths were introduced.`
}
