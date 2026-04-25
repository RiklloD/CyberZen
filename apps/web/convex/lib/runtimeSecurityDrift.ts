// WS-67 — Runtime Security Policy & Enforcement Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to runtime security enforcement policy files. This scanner focuses on the
// *runtime enforcement layer* — active rule sets and profiles that detect,
// block, or alert on malicious behaviour at runtime.
//
// DISTINCT from:
//   WS-60  securityConfigDriftResults — application-level security *options*
//                                       (CORS, CSP, TLS settings, WAF config
//                                       file) — not enforcement rule content
//   WS-62  cloudSecurityDriftResults  — cloud IAM/KMS/network infrastructure
//                                       policy files
//   WS-63  containerHardeningDriftResults — Kubernetes pod security, RBAC,
//                                       Dockerfile hardening, admission
//                                       webhook registration (not Kyverno CRDs)
//   WS-66  certPkiDriftResults        — cryptographic trust-layer config
//
// WS-67 vs WS-60: WS-60 detects changes to "which security controls are
//   enabled" (e.g. cors.config.json). WS-67 detects changes to "what
//   behaviour is detected/blocked at runtime" (e.g. falco_rules.yaml,
//   seccomp.json, local.rules). These are separate concerns — a repo can have
//   both and they test different failure modes.
//
// WS-67 vs WS-63: WS-63 covers admission *webhook* registration and
//   ValidatingWebhookConfiguration/OPA-Gatekeeper ConstraintTemplates. WS-67
//   covers Kyverno ClusterPolicy/Policy CRDs (a different admission controller
//   ecosystem) and runtime *enforcement* rule files (Falco, seccomp, IDS).
//
// Covered rule groups (8 rules):
//
//   FALCO_RULES_DRIFT            — Falco behavioral security rules
//   OPA_REGO_POLICY_DRIFT        — Open Policy Agent Rego policy files
//   SECCOMP_APPARMOR_DRIFT       — seccomp JSON profiles + AppArmor profiles
//   KYVERNO_POLICY_DRIFT         — Kyverno ClusterPolicy/Policy CRD resources
//   FAIL2BAN_CONFIG_DRIFT        — fail2ban jail/filter configuration
//   AUDITD_RULES_DRIFT           — Linux auditd / auditbeat rules
//   IDS_RULES_DRIFT              — Snort/Suricata IDS rule files  ← user contribution
//   SIGMA_YARA_RULE_DRIFT        — Sigma detection rules + YARA malware signatures
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories (node_modules, dist, .terraform, etc.) excluded.
//   • Same penalty/cap scoring model as WS-60–66 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • .rego extension is the definitive OPA signal — very few non-OPA files use it.
//   • .rules extension is used for both Snort/Suricata AND iptables-save output;
//     the user contribution point resolves this ambiguity.
//
// Exports:
//   isIdsRuleFile         — user contribution point (see JSDoc below)
//   RUNTIME_SECURITY_RULES — readonly rule registry (for tests / introspection)
//   scanRuntimeSecurityDrift — runs all 8 rules, returns RuntimeSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RuntimeSecurityRuleId =
  | 'FALCO_RULES_DRIFT'
  | 'OPA_REGO_POLICY_DRIFT'
  | 'SECCOMP_APPARMOR_DRIFT'
  | 'KYVERNO_POLICY_DRIFT'
  | 'FAIL2BAN_CONFIG_DRIFT'
  | 'AUDITD_RULES_DRIFT'
  | 'IDS_RULES_DRIFT'
  | 'SIGMA_YARA_RULE_DRIFT'

export type RuntimeSecuritySeverity = 'high' | 'medium' | 'low'
export type RuntimeSecurityRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface RuntimeSecurityDriftFinding {
  ruleId: RuntimeSecurityRuleId
  severity: RuntimeSecuritySeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface RuntimeSecurityDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: RuntimeSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule (deduped). */
  findings: RuntimeSecurityDriftFinding[]
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

function isYamlJson(base: string): boolean {
  return /\.(yaml|yml|json)$/.test(base)
}

function isConfigFile(base: string): boolean {
  return /\.(yaml|yml|json|conf|cfg|toml|ini|local)$/.test(base)
}

function pathHasSegment(normalised: string, segment: string): boolean {
  return normalised.split('/').some((s) => s.toLowerCase() === segment)
}

// ---------------------------------------------------------------------------
// FALCO_RULES_DRIFT
// ---------------------------------------------------------------------------

const FALCO_EXACT = new Set([
  'falco.yaml', 'falco.yml',
  'falco_rules.yaml', 'falco_rules.yml',
  'falco_rules.local.yaml', 'falco_rules.local.yml',
  'falco-rules.yaml', 'falco-rules.yml',
])

const FALCO_PREFIXES = [
  'falco', 'falco-rules', 'falco_rules', 'falco-config', 'falco_config',
]

function isFalcoRulesConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (FALCO_EXACT.has(base)) return true

  // Files inside /falco/ directory
  if (pathLower.includes('/falco/') && isYamlJson(base)) return true

  if (!startsWithAny(base, FALCO_PREFIXES)) return false
  return isYamlJson(base)
}

// ---------------------------------------------------------------------------
// OPA_REGO_POLICY_DRIFT
// ---------------------------------------------------------------------------

const OPA_EXACT = new Set([
  'opa.yaml', 'opa.yml', 'opa.json',
  'opa-config.yaml', 'opa-config.yml', 'opa-config.json',
  'opa_config.yaml', 'opa_config.yml',
  'bundle.tar.gz',  // OPA bundle archives
])

const OPA_PREFIXES = [
  'opa', 'opa-policy', 'opa_policy', 'opa-config', 'opa_config',
]

function isOpaRegoPolicy(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  // .rego extension is the primary and unambiguous OPA signal
  if (base.endsWith('.rego')) return true

  if (OPA_EXACT.has(base)) return true

  // Files inside /opa/ or /policies/ directory that are yaml/json
  if ((pathLower.includes('/opa/') || pathLower.includes('/opa-policies/')) && isYamlJson(base)) return true

  if (!startsWithAny(base, OPA_PREFIXES)) return false
  return isYamlJson(base)
}

// ---------------------------------------------------------------------------
// SECCOMP_APPARMOR_DRIFT
// ---------------------------------------------------------------------------

const SECCOMP_EXACT = new Set([
  'seccomp.json', 'seccomp-default.json', 'docker-default.json',
  'seccomp-profile.json', 'default-seccomp.json',
  'seccomp.yaml', 'seccomp.yml',
])

const SECCOMP_PREFIXES = [
  'seccomp', 'apparmor', 'seccomp-profile', 'seccomp_profile',
]

function isSeccompApparmorProfile(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (SECCOMP_EXACT.has(base)) return true

  // Files in seccomp-specific directories
  if (pathLower.includes('/seccomp/') && /\.(json|yaml|yml)$/.test(base)) return true

  // AppArmor profiles — conventionally in apparmor.d/ or apparmor/ dirs
  if (pathHasSegment(normalised, 'apparmor.d') || pathHasSegment(normalised, 'apparmor')) {
    // AppArmor profiles are often extensionless or have no standard extension
    return true
  }

  // Files in /etc/apparmor.d/ path
  if (pathLower.includes('/apparmor.d/')) return true

  if (!startsWithAny(base, SECCOMP_PREFIXES)) return false
  return /\.(json|yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// KYVERNO_POLICY_DRIFT
// ---------------------------------------------------------------------------

const KYVERNO_EXACT = new Set([
  'kyverno.yaml', 'kyverno.yml', 'kyverno.json',
  'clusterpolicy.yaml', 'clusterpolicy.yml',
  'kyverno-policy.yaml', 'kyverno-policy.yml',
  'kyverno_policy.yaml', 'kyverno_policy.yml',
])

const KYVERNO_PREFIXES = [
  'kyverno', 'kyverno-policy', 'kyverno_policy',
  'clusterpolicy', 'cluster-policy',
]

function isKyvernoPolicyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (KYVERNO_EXACT.has(base)) return true

  // Files inside /kyverno/ directory
  if (pathLower.includes('/kyverno/') && isYamlJson(base)) return true

  if (!startsWithAny(base, KYVERNO_PREFIXES)) return false
  return isYamlJson(base)
}

// ---------------------------------------------------------------------------
// FAIL2BAN_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const FAIL2BAN_EXACT = new Set([
  'jail.conf', 'jail.local',
  'fail2ban.conf', 'fail2ban.local',
])

const FAIL2BAN_PREFIXES = [
  'fail2ban', 'jail', 'f2b-',
]

function isFail2BanConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (FAIL2BAN_EXACT.has(base)) return true

  // Any file in a fail2ban directory (leading-slash-agnostic)
  if (pathLower.includes('fail2ban/')) return true

  if (!startsWithAny(base, FAIL2BAN_PREFIXES)) return false
  return isConfigFile(base)
}

// ---------------------------------------------------------------------------
// AUDITD_RULES_DRIFT
// ---------------------------------------------------------------------------

const AUDITD_EXACT = new Set([
  'audit.rules', 'auditd.conf', 'auditd.service',
  'auditbeat.yml', 'auditbeat.yaml',
  '99-audit.rules', '10-base-config.rules', '30-stig.rules',
  'audit-rules.conf',
])

const AUDITD_PREFIXES = [
  'audit', 'auditd', 'auditbeat',
]

const AUDITD_DIRS = ['/etc/audit/', '/etc/audit.d/', '/audit/', '/auditd/']

function isAuditdRulesConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (AUDITD_EXACT.has(base)) return true

  // Linux audit rules are typically .rules files in /etc/audit/rules.d/
  if (AUDITD_DIRS.some((d) => pathLower.includes(d))) return true

  // *.rules files in audit-specific directories
  if (base.endsWith('.rules') && pathHasSegment(normalised, 'audit')) return true

  if (!startsWithAny(base, AUDITD_PREFIXES)) return false
  return isConfigFile(base) || base.endsWith('.rules')
}

// ---------------------------------------------------------------------------
// IDS_RULES_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents an intrusion detection
 * system (IDS) rule file.
 *
 * Called by the IDS_RULES_DRIFT rule.
 *
 * IDS rule files define the signatures and heuristics used to detect known
 * attacks, port scans, malware C2 traffic, and policy violations at the
 * network layer. Changes to IDS rules can silently remove detection
 * capabilities (deleted signatures) or introduce false positives that blind
 * operators to real attacks.
 *
 * Files to detect (examples):
 *   Snort:
 *     snort.conf, snort.lua, local.rules, community.rules, snort.rules
 *     custom-rules.rules, my-alerts.rules
 *   Suricata:
 *     suricata.yaml, suricata.yml, emerging-threats.rules, suricata.rules
 *     custom.rules, local.rules (inside /suricata/ context)
 *   Zeek (Bro):
 *     zeek-policy.zeek, local.zeek, site.zeek (in /zeek/ or /bro/ directory)
 *   Generic:
 *     *.rules files in /snort/, /suricata/, /ids/ directories
 *
 * Trade-offs to consider:
 *   - Should ALL `.rules` files match regardless of directory context?
 *     Pro: iptables.rules / ip6tables.rules are also security-critical.
 *     Con: `.rules` is used for many non-IDS configs (lint rules, make rules).
 *     The current implementation requires either an IDS-specific directory
 *     context OR an IDS-specific prefix/exact name to reduce false positives.
 *   - Should `local.rules` match outside of an IDS directory? Unlikely to be
 *     useful — too many false positives from other tooling.
 *   - Should Zeek/Bro `.zeek` script files be included? They configure
 *     network behaviour analysis and have similar security impact to IDS rules.
 *
 * The current implementation errs on the conservative side for generic .rules
 * files: they must be in a known IDS directory or have an IDS-specific name.
 * Suricata and Snort-specific names are always matched.
 */
export function isIdsRuleFile(normalisedPath: string): boolean {
  const base = getBasename(normalisedPath).toLowerCase()
  const pathLower = normalisedPath.toLowerCase()

  // Exact Snort/Suricata config names
  if (base === 'snort.conf' || base === 'snort.lua') return true
  if (base === 'suricata.yaml' || base === 'suricata.yml') return true

  // Snort/Suricata-prefixed rule files
  const IDS_PREFIXES = [
    'snort', 'suricata', 'emerging-threats', 'community',
  ]
  if (IDS_PREFIXES.some((p) => base.startsWith(p)) && base.endsWith('.rules')) return true

  // Any .rules file in a known IDS directory (leading-slash-agnostic)
  const IDS_DIR_TERMS = ['snort/', 'suricata/', '/ids/', '/ids-rules/', '/nids/']
  if (IDS_DIR_TERMS.some((d) => pathLower.includes(d)) && base.endsWith('.rules')) return true

  // Zeek/Bro policy files in zeek/bro directories (leading-slash-agnostic)
  const ZEEK_DIR_TERMS = ['zeek/', 'bro/', '/zeek-policy/']
  if (ZEEK_DIR_TERMS.some((d) => pathLower.includes(d)) && /\.(zeek|bro)$/.test(base)) return true

  // Snort/Suricata config directories (leading-slash-agnostic)
  const ETC_IDS_TERMS = ['etc/snort/', 'etc/suricata/']
  if (ETC_IDS_TERMS.some((d) => pathLower.includes(d))) return true

  return false
}

// ---------------------------------------------------------------------------
// SIGMA_YARA_RULE_DRIFT
// ---------------------------------------------------------------------------

const SIGMA_YARA_PREFIXES = [
  'sigma', 'sigma-rule', 'sigma_rule',
  'yara', 'yara-rule', 'yara_rule',
  'detection-rule', 'detection_rule',
  'threat-hunt', 'threat_hunt', 'threat-detection', 'threat_detection',
]

// leading-slash-agnostic: matches both /sigma/ subdirectory and sigma/ at root
const SIGMA_DIRS = ['sigma/', 'sigma-rules/', 'yara/', 'yara-rules/', 'detection-rules/']

function isSigmaYaraRule(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  // YARA rule files (unambiguous extension)
  if (base.endsWith('.yar') || base.endsWith('.yara')) return true

  // Files in sigma-specific directories
  if (SIGMA_DIRS.some((d) => pathLower.includes(d)) && /\.(yaml|yml|json)$/.test(base)) return true

  if (!startsWithAny(base, SIGMA_YARA_PREFIXES)) return false
  return /\.(yaml|yml|json|yar|yara)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface RuntimeSecurityRule {
  id: RuntimeSecurityRuleId
  severity: RuntimeSecuritySeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const RUNTIME_SECURITY_RULES: readonly RuntimeSecurityRule[] = [
  {
    id: 'FALCO_RULES_DRIFT',
    severity: 'high',
    description:
      'Falco behavioral security rule file modified — Falco rules define which system calls, process activities, and network connections are flagged as security incidents at runtime. Removing or weakening rules silently eliminates detection coverage: an attacker spawning a shell from a container or reading sensitive files could execute undetected. Falco is often the sole source of runtime intrusion signals in Kubernetes environments.',
    recommendation:
      'Review every modified or deleted Falco rule for coverage reduction. Confirm that no high-signal rules (proc.name=shell, container.privileged=true, network.outbound to unexpected IPs) were weakened or commented out. Run `falco --validate <rules-file>` before deploying. Ensure the updated rules are consistent with the current threat model and that any new allow-listed syscalls are justified.',
    matches: isFalcoRulesConfig,
  },
  {
    id: 'OPA_REGO_POLICY_DRIFT',
    severity: 'high',
    description:
      'Open Policy Agent (OPA) Rego policy file modified — OPA policies are the enforcement point for admission control, authorisation, and data-access decisions in Kubernetes and API gateways. A policy edit that widens an allow rule or removes a deny clause can immediately permit previously-rejected API calls, resource creations, or data queries without any other observable change in application behaviour.',
    recommendation:
      'Audit every modified allow/deny rule for scope expansion. Confirm that default-deny baselines are preserved and no new wildcard principals were added. Run `opa test` and `opa eval` against a known-bad request to verify the policy still rejects it. Review the change in the context of your authorisation model — a single extra `allow = true` branch can bypass all other constraints.',
    matches: isOpaRegoPolicy,
  },
  {
    id: 'SECCOMP_APPARMOR_DRIFT',
    severity: 'high',
    description:
      'seccomp profile or AppArmor profile modified — seccomp profiles restrict which Linux syscalls a process may invoke; AppArmor profiles restrict file, network, and capability access. Removing a syscall restriction (e.g. re-enabling `ptrace`, `mount`, or `clone`) can enable container escapes and privilege escalation. These profiles are the last kernel-level enforcement line after container runtime security controls.',
    recommendation:
      'Verify that no previously-denied syscalls were added to the seccomp allow-list. Check for any new SCMP_ACT_ALLOW actions that replace SCMP_ACT_ERRNO entries. For AppArmor, confirm that no new file-system paths with write or execute permissions were added. Test the updated profile in a staging environment against known container-escape payloads before deploying to production.',
    matches: isSeccompApparmorProfile,
  },
  {
    id: 'KYVERNO_POLICY_DRIFT',
    severity: 'medium',
    description:
      "Kyverno ClusterPolicy or Policy CRD resource modified — Kyverno policies validate, mutate, and generate Kubernetes resources at admission time. A policy change that relaxes a validation rule (e.g. removing a required `securityContext.runAsNonRoot` check) immediately allows previously-rejected workloads. Unlike OPA/Gatekeeper, Kyverno's ClusterPolicy CRDs are often managed in Git and pushed directly to clusters, making drift detection particularly important.",
    recommendation:
      'Review modified ClusterPolicy validate/deny rules for any removal of security constraints. Confirm that `failurePolicy: Fail` is still set for security-critical policies. Verify that `namespaceSelector` was not widened to include sensitive namespaces. Check that any new `mutate` rules do not inject credentials or remove security annotations. Test against a known-bad resource manifest to confirm rejection still works.',
    matches: isKyvernoPolicyConfig,
  },
  {
    id: 'FAIL2BAN_CONFIG_DRIFT',
    severity: 'medium',
    description:
      "fail2ban jail or filter configuration modified — fail2ban monitors log files and bans IP addresses that show signs of brute-force attacks, credential stuffing, or repeated error patterns. Changes to jail.conf/jail.local can raise thresholds (allowing more failed attempts before banning), reduce ban durations, or disable jails entirely. Filter changes can cause fail2ban to stop recognising attack patterns, leaving the service open to password-spraying attacks.",
    recommendation:
      "Verify that maxretry and bantime values were not increased significantly (e.g. maxretry > 10 or bantime < 600s for SSH). Confirm that critical jails (sshd, nginx-auth, apache-auth) were not disabled. Review any filter.d changes for pattern removal — test updated patterns against sample log lines containing known attack signatures. Ensure the `ignoreip` allowlist was not expanded to include production IP ranges.",
    matches: isFail2BanConfig,
  },
  {
    id: 'AUDITD_RULES_DRIFT',
    severity: 'medium',
    description:
      'Linux auditd or auditbeat rule file modified — auditd rules define which system calls, file access events, and user actions are recorded in the kernel audit log. These records are the primary forensic evidence source for post-breach investigation and satisfy compliance requirements (PCI-DSS Req.10, NIST 800-53 AU-2). Removing audit rules creates blind spots in the forensic trail that attackers actively exploit to cover their tracks.',
    recommendation:
      'Verify that STIG/CIS-required audit rules are not removed (especially: `/etc/passwd` writes, `setuid` syscalls, `execve` calls from privileged processes, `/etc/sudoers` modifications). Confirm that `-e 2` (immutable audit config) is still set where required. Review any added rules for performance impact — overly broad `syscall` watchers can cause log storms. Ensure the updated rules are tested against your compliance framework before deployment.',
    matches: isAuditdRulesConfig,
  },
  {
    id: 'IDS_RULES_DRIFT',
    severity: 'medium',
    description:
      'Snort/Suricata IDS or Zeek network policy rule file modified — IDS rules detect known attack patterns, exploit attempts, C2 beaconing, and policy violations at the network layer. Removing or weakening rules silently eliminates network-level intrusion detection: a lateral-movement scan or data-exfiltration over common ports may proceed undetected. Suricata in inline IPS mode can also actively block traffic — rule changes can re-enable previously-blocked traffic flows.',
    recommendation:
      'Review deleted or disabled rules for coverage against OWASP Top 10 attack vectors, CVE-specific exploit signatures, and C2 detection patterns. Verify that the updated rule set still covers the emerging-threats categories relevant to your environment. Test the changes in IDS mode before applying to inline IPS mode. Confirm that rule suppressions/thresholds were not widened to the point of missing real attacks.',
    matches: isIdsRuleFile,
  },
  {
    id: 'SIGMA_YARA_RULE_DRIFT',
    severity: 'low',
    description:
      'Sigma detection rule or YARA malware signature file modified — Sigma rules are the vendor-agnostic detection rule format used by SIEM platforms (Splunk, Elastic, Microsoft Sentinel, QRadar). YARA rules are pattern-matching signatures for malware identification. Changes to these files affect which attack techniques are detected by the SIEM and which files are flagged as malware. Removing or weakening a detection rule creates silent blindspots in the security operations centre.',
    recommendation:
      'Review any removed or modified Sigma rules for MITRE ATT&CK technique coverage reduction. Confirm that changes to YARA signatures do not remove detection of actively-exploited malware families. Validate updated rules against the intended SIEM platform using `sigma convert` or equivalent tooling. Ensure that any new false-positive suppressions are justified and time-bounded.',
    matches: isSigmaYaraRule,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<RuntimeSecuritySeverity, number> = { high: 15, medium: 8, low: 4 }
const PENALTY_CAP: Record<RuntimeSecuritySeverity, number> = { high: 45, medium: 25, low: 15 }

function toRiskLevel(score: number): RuntimeSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_SHORT_LABEL: Record<RuntimeSecurityRuleId, string> = {
  FALCO_RULES_DRIFT:       'Falco rules',
  OPA_REGO_POLICY_DRIFT:   'OPA Rego policy',
  SECCOMP_APPARMOR_DRIFT:  'seccomp / AppArmor',
  KYVERNO_POLICY_DRIFT:    'Kyverno policy',
  FAIL2BAN_CONFIG_DRIFT:   'fail2ban config',
  AUDITD_RULES_DRIFT:      'auditd rules',
  IDS_RULES_DRIFT:         'IDS rules',
  SIGMA_YARA_RULE_DRIFT:   'Sigma / YARA rules',
}

function buildSummary(
  findings: RuntimeSecurityDriftFinding[],
  riskLevel: RuntimeSecurityRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no runtime security enforcement file changes detected.`
  }
  const highFindings = findings.filter((f) => f.severity === 'high')
  if (highFindings.length > 0) {
    const labels = highFindings.map((f) => RULE_SHORT_LABEL[f.ruleId])
    const unique  = [...new Set(labels)]
    const joined  =
      unique.length <= 2
        ? unique.join(' and ')
        : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return (
      `${findings.length} runtime security enforcement file${findings.length === 1 ? '' : 's'} modified ` +
      `including ${joined} — mandatory security review required before merge.`
    )
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${findings.length} runtime security policy change${findings.length === 1 ? '' : 's'} across ` +
    `${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which runtime security enforcement policy
 * files were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor/build directories are excluded.
 * - Each rule fires at most once per scan (deduplicated per rule ID).
 * - The finding records the first matched path and total count of matched paths.
 */
export function scanRuntimeSecurityDrift(filePaths: string[]): RuntimeSecurityDriftResult {
  const ruleAccumulator = new Map<RuntimeSecurityRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of RUNTIME_SECURITY_RULES) {
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
  const findings: RuntimeSecurityDriftFinding[] = []
  for (const rule of RUNTIME_SECURITY_RULES) {
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
  const penaltyByTier: Partial<Record<RuntimeSecuritySeverity, number>> = {}
  for (const f of findings) {
    penaltyByTier[f.severity] = (penaltyByTier[f.severity] ?? 0) + PENALTY_PER[f.severity]
  }

  let riskScore = 0
  for (const [sev, total] of Object.entries(penaltyByTier) as [RuntimeSecuritySeverity, number][]) {
    riskScore += Math.min(total, PENALTY_CAP[sev])
  }
  riskScore = Math.min(riskScore, 100)

  const riskLevel   = toRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary: buildSummary(findings, riskLevel, filePaths.filter((p) => p.trim()).length),
  }
}
