// WS-62 — Cloud Security Configuration Drift Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to cloud-provider and infrastructure security configuration files. This
// scanner focuses on the *cloud security* layer — IAM roles, KMS key policies,
// network security groups, storage bucket policies, API gateway auth configs,
// secrets-backend configs, audit logging, and CDN/WAF configurations.
//
// DISTINCT from:
//   WS-33 iacScanResults         — content-level IaC rule checks (Terraform
//                                   misconfiguration, K8s privilege settings, etc.)
//   WS-60 securityConfigDriftResults — application-level security config files
//                                   (JWT, CORS, CSP, TLS, session options)
//
// WS-62 vs WS-33: WS-33 reads file *content* and applies static rules.
//   WS-62 is purely path-based and fires when *any* cloud security config file
//   is touched, flagging it for mandatory security review regardless of content.
//
// WS-62 vs WS-60: WS-60 covers application-layer security parameters (the web
//   server's security posture). WS-62 covers the cloud infrastructure layer:
//   who can access what resources, how encryption keys are managed, what the
//   network perimeter looks like, and who is auditing it.
//
// Covered rule groups (8 rules):
//
//   IAM_POLICY_DRIFT           — IAM role/policy/permission-boundary files changed
//   KMS_KEY_POLICY_DRIFT       — KMS key policy / encryption key management config
//   NETWORK_SECURITY_DRIFT     — Security group / VPC / firewall / NACL config
//   STORAGE_POLICY_DRIFT       — S3 / GCS / Blob storage bucket policy / ACL
//   API_GATEWAY_AUTH_DRIFT     — API Gateway authorizer / API auth configuration
//   SECRETS_BACKEND_DRIFT      — Secrets Manager / Parameter Store / Vault config
//   AUDIT_LOGGING_DRIFT        — Cloud audit trail / logging configuration  ← user contribution
//   CDN_WAF_DRIFT              — CloudFront / CDN / WAF security configuration
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories (node_modules, dist, .terraform, etc.) excluded.
//   • Same penalty/cap scoring model as WS-53–61 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Config-signal gating: topic keyword required so generic infra files that
//     happen to contain "iam" or "kms" in unrelated names are excluded.
//
// Exports:
//   isAuditLoggingConfig        — user contribution point (see TODO below)
//   scanCloudSecurityDrift      — runs all 8 rules, returns CloudSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CloudSecurityRuleId =
  | 'IAM_POLICY_DRIFT'
  | 'KMS_KEY_POLICY_DRIFT'
  | 'NETWORK_SECURITY_DRIFT'
  | 'STORAGE_POLICY_DRIFT'
  | 'API_GATEWAY_AUTH_DRIFT'
  | 'SECRETS_BACKEND_DRIFT'
  | 'AUDIT_LOGGING_DRIFT'
  | 'CDN_WAF_DRIFT'

export type CloudSecuritySeverity = 'critical' | 'high' | 'medium'
export type CloudSecurityRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface CloudSecurityDriftFinding {
  ruleId: CloudSecurityRuleId
  severity: CloudSecuritySeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface CloudSecurityDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: CloudSecurityRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  /** One finding per triggered rule (deduped). */
  findings: CloudSecurityDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

function getBasename(normalised: string): string {
  const parts = normalised.split('/')
  return parts[parts.length - 1] ?? ''
}

/** Extended vendor set for cloud security scanning — includes terraform state
 * and lock dirs, CDK output dirs, and standard build artifacts. */
const VENDOR_DIRS = new Set([
  'node_modules', 'dist', 'build', 'vendor', '.yarn',
  '.git', 'coverage', 'out', '.next', '.nuxt',
  '.terraform', '.cdk', 'cdk.out', '__pycache__',
])

function isVendoredPath(normalised: string): boolean {
  return normalised.split('/').some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function startsWithAny(base: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => base.startsWith(p))
}

function includesAny(str: string, terms: readonly string[]): boolean {
  return terms.some((t) => str.includes(t))
}

function isJsonYamlTfFile(base: string): boolean {
  return /\.(json|yaml|yml|tf|hcl|toml|conf|cfg|ini|env)$/.test(base)
}

// ---------------------------------------------------------------------------
// IAM_POLICY_DRIFT
// ---------------------------------------------------------------------------

/** IAM topic prefixes that indicate the file configures identity/access policy. */
const IAM_PREFIXES = [
  'iam', 'role', 'roles', 'policy', 'policies', 'permission', 'permissions',
  'trust-policy', 'trust_policy', 'permission-boundary', 'permission_boundary',
  'assume-role', 'assume_role', 'service-account', 'service_account',
]

/** Exact basenames that are always IAM policy files. */
const IAM_EXACT = new Set([
  'iam.json', 'iam.yaml', 'iam.yml', 'iam.tf',
  'role.json', 'roles.json', 'policy.json', 'policies.json',
  'trust-policy.json', 'trust_policy.json',
  'permission-boundary.json', 'permission_boundary.json',
  'service-account.json', 'service_account.json',
  'workload-identity.json', 'workload_identity.json',
])

function isIamPolicyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (IAM_EXACT.has(base)) return true
  if (!startsWithAny(base, IAM_PREFIXES)) return false
  // Require a config-file extension to exclude source-code files named "roles.ts"
  return isJsonYamlTfFile(base)
}

// ---------------------------------------------------------------------------
// KMS_KEY_POLICY_DRIFT
// ---------------------------------------------------------------------------

const KMS_PREFIXES = ['kms', 'key-policy', 'key_policy', 'encryption-key', 'encryption_key']
const KMS_TERMS    = ['kms', 'key-policy', 'key_policy', 'keyrings', 'keyring', 'key-ring']

const KMS_EXACT = new Set([
  'kms.json', 'kms.yaml', 'kms.yml', 'kms.tf',
  'key-policy.json', 'key_policy.json',
  'encryption-key.json', 'encryption_key.json',
  'cmk-policy.json', 'customer-managed-key.json',
])

function isKmsKeyPolicyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (KMS_EXACT.has(base)) return true
  // Also match by path segment: files under a /kms/ or /key-management/ directory
  const pathLower = normalised.toLowerCase()
  const KMS_DIR_TERMS = ['kms/', 'key-management/', 'keymanagement/', 'key_management/']
  if (KMS_DIR_TERMS.some((d) => pathLower.includes(d)) && isJsonYamlTfFile(base)) return true
  if (!startsWithAny(base, KMS_PREFIXES) && !includesAny(base, KMS_TERMS)) return false
  return isJsonYamlTfFile(base)
}

// ---------------------------------------------------------------------------
// NETWORK_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const NETWORK_SECURITY_PREFIXES = [
  'sg', 'security-group', 'security_group', 'securitygroup',
  'nacl', 'network-acl', 'network_acl',
  'firewall', 'firewall-rule', 'firewall_rule',
  'vpc', 'vnet', 'subnet',
  'nsg', 'network-security-group', 'network_security_group',
  'ingress', 'egress',
]

const NETWORK_EXACT = new Set([
  'sg.json', 'sg.yaml', 'sg.tf',
  'security-group.json', 'security_group.json',
  'firewall.json', 'firewall.yaml', 'firewall.tf',
  'nacl.json', 'nacl.yaml', 'nacl.tf',
  'nsg.json', 'nsg.yaml', 'nsg.tf',
])

function isNetworkSecurityConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (NETWORK_EXACT.has(base)) return true
  if (!startsWithAny(base, NETWORK_SECURITY_PREFIXES)) return false
  return isJsonYamlTfFile(base)
}

// ---------------------------------------------------------------------------
// STORAGE_POLICY_DRIFT
// ---------------------------------------------------------------------------

const STORAGE_PREFIXES = [
  'bucket-policy', 'bucket_policy', 'bucketpolicy',
  'bucket-acl', 'bucket_acl',
  's3-policy', 's3_policy', 's3-acl', 's3_acl',
  'gcs-policy', 'gcs_policy', 'blob-policy', 'blob_policy',
  'storage-policy', 'storage_policy',
  'cors-s3', 'public-access-block', 'public_access_block',
]

const STORAGE_EXACT = new Set([
  'bucket-policy.json', 'bucket_policy.json',
  's3-policy.json', 's3_policy.json',
  'gcs-policy.json', 'gcs_policy.json',
  'blob-policy.json', 'blob_policy.json',
  'storage-policy.json', 'storage_policy.json',
  'public-access-block.json', 'public_access_block.json',
])

function isStoragePolicyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (STORAGE_EXACT.has(base)) return true
  if (!startsWithAny(base, STORAGE_PREFIXES)) return false
  return isJsonYamlTfFile(base)
}

// ---------------------------------------------------------------------------
// API_GATEWAY_AUTH_DRIFT
// ---------------------------------------------------------------------------

const API_GATEWAY_PREFIXES = [
  'api-gateway-auth', 'api_gateway_auth', 'apigateway-auth', 'apigatewayauth',
  'authorizer', 'lambda-authorizer', 'lambda_authorizer',
  'api-auth', 'api_auth', 'apigw-auth', 'apigw_auth',
  'gateway-security', 'gateway_security',
  'api-security', 'api_security',
]

const API_GATEWAY_TERMS = [
  'authorizer', 'api-auth', 'api_auth', 'apigw', 'api-gateway',
  'gateway-security', 'apikey', 'api-key',
]

function isApiGatewayAuthConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (startsWithAny(base, API_GATEWAY_PREFIXES)) return isJsonYamlTfFile(base)
  // Also catch files with api-auth terms anywhere in basename
  if (includesAny(base, API_GATEWAY_TERMS) && isJsonYamlTfFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// SECRETS_BACKEND_DRIFT
// ---------------------------------------------------------------------------

const SECRETS_PREFIXES = [
  'secrets-manager', 'secrets_manager', 'secretsmanager',
  'parameter-store', 'parameter_store', 'parameterstore',
  'vault', 'vault-config', 'vault_config',
  'secret-backend', 'secret_backend',
  'ssm-config', 'ssm_config',
]

const SECRETS_TERMS = [
  'secrets-manager', 'secrets_manager', 'secretsmanager',
  'parameter-store', 'parameterstore', 'vault-config', 'vault_config',
]

const SECRETS_EXACT = new Set([
  'vault.json', 'vault.yaml', 'vault.yml', 'vault.hcl',
  'vault-config.json', 'vault_config.json',
  'secrets-manager.json', 'secrets_manager.json',
  'parameter-store.json', 'parameter_store.json',
])

function isSecretsBackendConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (SECRETS_EXACT.has(base)) return true
  if (startsWithAny(base, SECRETS_PREFIXES)) return isJsonYamlTfFile(base)
  if (includesAny(base, SECRETS_TERMS) && isJsonYamlTfFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// AUDIT_LOGGING_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents a cloud audit logging
 * or trail configuration file.
 *
 * Called by the AUDIT_LOGGING_DRIFT rule.
 *
 * Cloud audit logging files configure which API calls, resource changes, and
 * data-access events are recorded. Disabling or narrowing audit logs silently
 * removes the organisation's ability to detect breaches and comply with
 * regulatory requirements (SOC 2 CC7.2, PCI-DSS Req.10, HIPAA §164.312).
 *
 * Files to detect (examples):
 *   cloudtrail.json / cloudtrail.tf / cloudtrail-config.yaml
 *   audit-log.json / audit_log.yaml / auditlog.tf
 *   stackdriver-logging.yaml / cloud-logging.json
 *   azure-monitor.json / activity-log.yaml / diagnostic-settings.json
 *   siem-config.json / siem-integration.yaml
 *   log-analytics.json / log_analytics.yaml
 *
 * Trade-offs to consider:
 *   - Should plain `log.json` or `logging.yaml` match? (probably too broad)
 *   - Should "audit" alone be sufficient, or require a cloud provider term too?
 *   - Should SIEM integration files (Splunk, Elastic, Sentinel) be included?
 *   - Provider-specific terms (cloudtrail, stackdriver, azure-monitor, activity-log)
 *     are unambiguous; generic terms (audit, logging) may need qualifier support.
 *
 * The current implementation requires either a specific audit provider term OR
 * the word "audit" combined with a cloud/log qualifier in the basename.
 */
export function isAuditLoggingConfig(normalisedPath: string): boolean {
  const base = getBasename(normalisedPath).toLowerCase()
  if (!isJsonYamlTfFile(base)) return false

  // Specific cloud audit trail identifiers (unambiguous)
  const AUDIT_EXACT_TERMS = [
    'cloudtrail', 'cloud-trail', 'cloud_trail',
    'stackdriver', 'cloud-logging', 'cloud_logging',
    'azure-monitor', 'azure_monitor', 'activity-log', 'activity_log',
    'diagnostic-setting', 'diagnostic_setting',
    'audit-log', 'audit_log', 'auditlog',
    'siem-config', 'siem_config', 'siem-integration', 'siem_integration',
    'log-analytics', 'log_analytics', 'loganalytics',
  ]
  if (AUDIT_EXACT_TERMS.some((t) => base.includes(t))) return true

  // Generic "audit" combined with a cloud/log qualifier
  if (base.includes('audit')) {
    const CLOUD_QUALIFIERS = ['cloud', 'aws', 'gcp', 'azure', 'log', 'trail', 'event', 'monitor']
    if (CLOUD_QUALIFIERS.some((q) => base.includes(q))) return true
  }

  return false
}

// ---------------------------------------------------------------------------
// CDN_WAF_DRIFT
// ---------------------------------------------------------------------------

const CDN_WAF_PREFIXES = [
  'cloudfront', 'cloud-front', 'cloud_front',
  'waf', 'waf-rule', 'waf_rule', 'waf-config', 'waf_config',
  'cdn', 'cdn-config', 'cdn_config',
  'akamai', 'fastly', 'cloudflare',
  'ddos', 'ddos-protection', 'ddos_protection',
  'shield', 'aws-shield',
]

const CDN_WAF_EXACT = new Set([
  'cloudfront.json', 'cloudfront.yaml', 'cloudfront.tf',
  'waf.json', 'waf.yaml', 'waf.tf',
  'cdn.json', 'cdn.yaml', 'cdn.tf',
  'akamai.json', 'fastly.json', 'cloudflare.json',
  'ddos-protection.json', 'ddos_protection.json',
])

function isCdnWafConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (CDN_WAF_EXACT.has(base)) return true
  if (!startsWithAny(base, CDN_WAF_PREFIXES)) return false
  return isJsonYamlTfFile(base)
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface CloudSecurityRule {
  id: CloudSecurityRuleId
  severity: CloudSecuritySeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const CLOUD_SECURITY_RULES: readonly CloudSecurityRule[] = [
  {
    id: 'IAM_POLICY_DRIFT',
    severity: 'critical',
    description:
      'IAM role, policy, or permission-boundary configuration modified — IAM policy changes are the highest-risk class of cloud security change. A single wildcard action (`"*"`) or overly permissive resource scope in an IAM policy grants lateral-movement opportunities to any attacker who compromises the associated principal.',
    recommendation:
      'Review every modified IAM statement for new `"*"` actions or resources, new wildcard conditions, and new trust-relationship principals. Validate that the principle of least privilege is maintained. Run `aws iam simulate-principal-policy` or equivalent to verify the effective permissions before merging.',
    matches: isIamPolicyConfig,
  },
  {
    id: 'KMS_KEY_POLICY_DRIFT',
    severity: 'critical',
    description:
      'KMS key policy or encryption key management configuration modified — KMS key policy changes can silently grant additional principals the ability to decrypt data-at-rest, re-encrypt data under a different key, or schedule key deletion. These changes are difficult to detect post-deployment and can affect all data encrypted under the key.',
    recommendation:
      'Audit every modified key policy statement for new grantees, new actions (especially `kms:Decrypt`, `kms:GenerateDataKey`, `kms:ScheduleKeyDeletion`), and any relaxed condition keys. Verify that key deletion is protected by `kms:ScheduleKeyDeletion` requires MFA. Ensure key rotation policy was not extended.',
    matches: isKmsKeyPolicyConfig,
  },
  {
    id: 'NETWORK_SECURITY_DRIFT',
    severity: 'high',
    description:
      'Network security group, VPC, or firewall configuration modified — changes to security groups, NACLs, or firewall rules can open inbound or outbound connectivity to previously restricted resources. A single overly permissive rule (`0.0.0.0/0`) can expose internal services to the public internet.',
    recommendation:
      'Review every modified ingress and egress rule for new open CIDR ranges (`0.0.0.0/0` or `::/0`), new open port ranges, and removed deny rules. Validate that no publicly accessible ports were added to private subnets. Run `aws ec2 describe-security-group-rules` or equivalent post-deploy verification.',
    matches: isNetworkSecurityConfig,
  },
  {
    id: 'STORAGE_POLICY_DRIFT',
    severity: 'high',
    description:
      'Cloud storage bucket policy or ACL modified — S3, GCS, or Blob storage policy changes can make previously private buckets publicly readable or writable. Public storage buckets are one of the most common cloud data-breach vectors, and changes are often not caught until a breach notification.',
    recommendation:
      'Verify that `"Principal": "*"` or `"allUsers"` are not present in the updated policy. Confirm that `s3:GetObject` or equivalent read actions are not granted to anonymous principals. Ensure that Block Public Access settings remain enabled at the account and bucket level.',
    matches: isStoragePolicyConfig,
  },
  {
    id: 'API_GATEWAY_AUTH_DRIFT',
    severity: 'high',
    description:
      'API Gateway authorizer or API authentication configuration modified — changes to API Gateway security settings can remove or weaken the authentication layer for all API endpoints behind that gateway. An incorrectly configured authorizer can allow unauthenticated access to backend services.',
    recommendation:
      'Verify that the authorizer type was not changed from a stricter type (e.g. Cognito/Lambda) to a more permissive one (e.g. no-auth). Confirm that the authorizer is still attached to all required routes. Validate any changes to token validation logic or TTL caching behaviour.',
    matches: isApiGatewayAuthConfig,
  },
  {
    id: 'SECRETS_BACKEND_DRIFT',
    severity: 'high',
    description:
      'Secrets Manager, Parameter Store, or Vault backend configuration modified — these files control how secrets are stored, rotated, and accessed. Weakening encryption, expanding access policies, disabling rotation, or changing the backend endpoint can expose all application secrets.',
    recommendation:
      'Audit any changes to secret access policies, rotation configurations, and encryption settings. Ensure KMS key references were not changed to a less secure key or removed. Verify that no new IAM roles or service accounts were granted read access to production secrets.',
    matches: isSecretsBackendConfig,
  },
  {
    id: 'AUDIT_LOGGING_DRIFT',
    severity: 'medium',
    description:
      'Cloud audit trail, CloudTrail, StackDriver, or SIEM integration configuration modified — audit logging configurations determine which cloud API calls, data-access events, and resource changes are recorded. Narrowing the scope, disabling global events, or changing the logging destination can create blind spots in your security monitoring and break regulatory compliance (SOC 2 CC7.2, PCI-DSS Req.10, HIPAA §164.312).',
    recommendation:
      'Verify that all management events and data events remain enabled. Confirm that S3 server access logging and CloudTrail log file validation are still active. Ensure the logging destination (S3 bucket, SIEM endpoint) was not changed to a less secure or unmonitored location. Review any changes to log retention periods.',
    matches: isAuditLoggingConfig,
  },
  {
    id: 'CDN_WAF_DRIFT',
    severity: 'medium',
    description:
      'CDN or WAF security configuration modified — CloudFront, Akamai, Fastly, or Cloudflare WAF configurations control DDoS protection, bot mitigation, rate limiting, and IP allowlisting for all traffic to your application. Weakening these rules silently removes protection layers without visible application changes.',
    recommendation:
      'Review any removed or disabled WAF rules — especially OWASP Core Rule Set rules. Verify that rate limiting thresholds were not raised significantly. Confirm that geo-restriction rules remain in place where required. Ensure SSL/TLS minimum version was not lowered on the CDN origin configuration.',
    matches: isCdnWafConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–61 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<CloudSecuritySeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
}

const PENALTY_CAP: Record<CloudSecuritySeverity, number> = {
  critical: 75,
  high:     35,
  medium:   20,
}

function toRiskLevel(score: number): CloudSecurityRiskLevel {
  if (score === 0)  return 'none'
  if (score < 25)   return 'low'
  if (score < 50)   return 'medium'
  if (score < 75)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_SHORT_LABEL: Record<CloudSecurityRuleId, string> = {
  IAM_POLICY_DRIFT:        'IAM policy',
  KMS_KEY_POLICY_DRIFT:    'KMS key policy',
  NETWORK_SECURITY_DRIFT:  'network security group',
  STORAGE_POLICY_DRIFT:    'storage bucket policy',
  API_GATEWAY_AUTH_DRIFT:  'API Gateway auth',
  SECRETS_BACKEND_DRIFT:   'secrets backend',
  AUDIT_LOGGING_DRIFT:     'audit logging config',
  CDN_WAF_DRIFT:           'CDN / WAF config',
}

function buildSummary(
  findings: CloudSecurityDriftFinding[],
  riskLevel: CloudSecurityRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no cloud security configuration file changes detected.`
  }
  const critOrHigh = findings.filter((f) => f.severity === 'critical' || f.severity === 'high')
  if (critOrHigh.length > 0) {
    const labels = critOrHigh.map((f) => RULE_SHORT_LABEL[f.ruleId])
    const unique  = [...new Set(labels)]
    const joined  =
      unique.length <= 2
        ? unique.join(' and ')
        : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return (
      `${findings.length} cloud security configuration file${findings.length === 1 ? '' : 's'} modified ` +
      `including ${joined} — mandatory cloud-security review required before merge.`
    )
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${findings.length} cloud security configuration change${findings.length === 1 ? '' : 's'} across ` +
    `${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which cloud security configuration files
 * were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor/build directories are excluded.
 * - Each rule fires at most once per scan (deduplicated per rule ID).
 * - The finding records the first matched path and total count of matched paths.
 */
export function scanCloudSecurityDrift(filePaths: string[]): CloudSecurityDriftResult {
  const ruleAccumulator = new Map<CloudSecurityRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of CLOUD_SECURITY_RULES) {
      if (!rule.matches(normalised)) continue
      const acc = ruleAccumulator.get(rule.id)
      if (acc) {
        acc.count++
      } else {
        ruleAccumulator.set(rule.id, { firstPath: rawPath, count: 1 })
      }
    }
  }

  // Build findings in rule-definition order for consistent output
  const findings: CloudSecurityDriftFinding[] = []
  for (const rule of CLOUD_SECURITY_RULES) {
    const acc = ruleAccumulator.get(rule.id)
    if (!acc) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    acc.firstPath,
      matchCount:     acc.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  // Compute score with per-tier caps
  const penaltyByTier: Partial<Record<CloudSecuritySeverity, number>> = {}
  for (const f of findings) {
    penaltyByTier[f.severity] = (penaltyByTier[f.severity] ?? 0) + PENALTY_PER[f.severity]
  }

  let riskScore = 0
  for (const [sev, total] of Object.entries(penaltyByTier) as [CloudSecuritySeverity, number][]) {
    riskScore += Math.min(total, PENALTY_CAP[sev])
  }
  riskScore = Math.min(riskScore, 100)

  const riskLevel     = toRiskLevel(riskScore)
  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount     = findings.filter((f) => f.severity === 'high').length
  const mediumCount   = findings.filter((f) => f.severity === 'medium').length

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    findings,
    summary: buildSummary(findings, riskLevel, filePaths.filter((p) => p.trim()).length),
  }
}
