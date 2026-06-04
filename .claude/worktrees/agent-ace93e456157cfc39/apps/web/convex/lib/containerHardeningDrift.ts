// WS-63 — Kubernetes & Container Security Hardening Drift Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to Kubernetes security configuration and container hardening files. This
// scanner focuses on the *container orchestration security* layer — RBAC
// manifests, NetworkPolicy definitions, PodSecurityAdmission/PodSecurityPolicy,
// admission controller (OPA/Kyverno/Gatekeeper) policies, ExternalSecrets and
// SealedSecrets, Dockerfiles, container runtime security profiles (Seccomp /
// AppArmor / Falco), and Helm chart security values.
//
// DISTINCT from:
//   WS-33 iacScanResults         — content-level IaC rule checks (reads YAML *content*
//                                   for privileged: true, runAsRoot, hostPID, etc.)
//   WS-45 containerSecurity      — SBOM-level container image inventory (what packages
//                                   are in the image, not what k8s config changed)
//   WS-62 cloudSecurityDrift     — cloud-provider layer (AWS IAM, GCP KMS, Azure NSG)
//                                   WS-63 covers the k8s / container runtime layer.
//
// WS-63 vs WS-33: WS-33 reads file *content* and applies static rules.
//   WS-63 is purely path-based and fires when *any* container hardening config
//   file is touched, flagging it for mandatory security review regardless of content.
//
// Covered rule groups (8 rules):
//
//   KUBE_RBAC_DRIFT               — Role / ClusterRole / RoleBinding / ClusterRoleBinding
//   KUBE_NETWORK_POLICY_DRIFT     — NetworkPolicy / Calico / Cilium policy manifests
//   KUBE_POD_SECURITY_DRIFT       — PodSecurityPolicy / PodSecurityAdmission / OPA / Kyverno
//   KUBE_ADMISSION_CONTROLLER_DRIFT — ValidatingWebhookConfiguration / MutatingWebhookConfiguration
//   KUBE_EXTERNAL_SECRETS_DRIFT   — ExternalSecret / SecretStore / SealedSecret   ← user contribution
//   DOCKERFILE_HARDENING_DRIFT    — Dockerfile / .dockerignore changed
//   CONTAINER_RUNTIME_POLICY_DRIFT — Seccomp / AppArmor / Falco / containerd policy
//   HELM_SECURITY_VALUES_DRIFT    — Helm security-relevant values / chart security overrides
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories (node_modules, dist, .terraform, etc.) excluded.
//   • Same penalty/cap scoring model as WS-53–62 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Kubernetes YAML files are detected by .yaml/.yml extension combined with
//     k8s-specific term matching to avoid false positives from generic YAML files.
//
// Exports:
//   isKubeExternalSecretConfig    — user contribution point (see TODO below)
//   scanContainerHardeningDrift   — runs all 8 rules, returns ContainerHardeningDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ContainerHardeningRuleId =
  | 'KUBE_RBAC_DRIFT'
  | 'KUBE_NETWORK_POLICY_DRIFT'
  | 'KUBE_POD_SECURITY_DRIFT'
  | 'KUBE_ADMISSION_CONTROLLER_DRIFT'
  | 'KUBE_EXTERNAL_SECRETS_DRIFT'
  | 'DOCKERFILE_HARDENING_DRIFT'
  | 'CONTAINER_RUNTIME_POLICY_DRIFT'
  | 'HELM_SECURITY_VALUES_DRIFT'

export type ContainerHardeningSeverity = 'critical' | 'high' | 'medium'
export type ContainerHardeningRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface ContainerHardeningFinding {
  ruleId: ContainerHardeningRuleId
  severity: ContainerHardeningSeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface ContainerHardeningDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: ContainerHardeningRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  /** One finding per triggered rule (deduped). */
  findings: ContainerHardeningFinding[]
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

/** Vendor directories — identical extended set as WS-62. */
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

/** k8s manifests are almost exclusively YAML; accept JSON too for API-dumped resources. */
function isYamlJsonFile(base: string): boolean {
  return /\.(yaml|yml|json)$/.test(base)
}

function isYamlFile(base: string): boolean {
  return /\.(yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// KUBE_RBAC_DRIFT
// ---------------------------------------------------------------------------

const RBAC_EXACT = new Set([
  'role.yaml', 'role.yml', 'clusterrole.yaml', 'clusterrole.yml',
  'rolebinding.yaml', 'rolebinding.yml',
  'clusterrolebinding.yaml', 'clusterrolebinding.yml',
])

const RBAC_PREFIXES = [
  'role-', 'clusterrole-', 'rolebinding-', 'clusterrolebinding-',
  'admin-role', 'viewer-role', 'editor-role', 'read-role', 'write-role',
]

const RBAC_DIR_TERMS = ['rbac/', 'roles/', '/role/', '/roles/']

function isKubeRbacConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (RBAC_EXACT.has(base)) return true
  if (startsWithAny(base, RBAC_PREFIXES) && isYamlJsonFile(base)) return true
  if (RBAC_DIR_TERMS.some((d) => lower.includes(d)) && isYamlJsonFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// KUBE_NETWORK_POLICY_DRIFT
// ---------------------------------------------------------------------------

const NETPOL_EXACT = new Set([
  'networkpolicy.yaml', 'networkpolicy.yml',
  'network-policy.yaml', 'network-policy.yml',
  'calico-policy.yaml', 'calico-policy.yml',
  'cilium-policy.yaml', 'cilium-policy.yml',
])

const NETPOL_PREFIXES = [
  'networkpolicy-', 'network-policy-',
  'calico-', 'cilium-policy-', 'netpol-',
  'ingress-policy', 'egress-policy',
  'deny-all', 'allow-', 'deny-',
]

const NETPOL_DIR_TERMS = [
  'network-policies/', 'networkpolicies/', 'netpol/',
  '/calico/', '/cilium/policies/',
]

function isKubeNetworkPolicyConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (NETPOL_EXACT.has(base)) return true
  if (startsWithAny(base, NETPOL_PREFIXES) && isYamlJsonFile(base)) return true
  if (NETPOL_DIR_TERMS.some((d) => lower.includes(d)) && isYamlJsonFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// KUBE_POD_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const PODSEC_EXACT = new Set([
  'podsecuritypolicy.yaml', 'podsecuritypolicy.yml',
  'pod-security-policy.yaml', 'pod-security-policy.yml',
  'psp.yaml', 'psp.yml',
  'podsecurityadmission.yaml', 'podsecurityadmission.yml',
  'pod-security-admission.yaml', 'pod-security-admission.yml',
])

const PODSEC_PREFIXES = [
  'podsecuritypolicy-', 'pod-security-policy-', 'psp-',
  'podsecurityadmission-', 'pod-security-admission-',
  'kyverno-policy', 'opa-policy', 'constraint-',
]

const PODSEC_TERMS = [
  'podsecuritypolicy', 'pod-security-policy', 'pod-security-admission',
  'kyverno', 'constrainttemplate', 'gatekeeper',
]

const PODSEC_DIR_TERMS = ['psp/', 'pod-security/', 'kyverno/', 'gatekeeper/', 'opa/policies/']

function isKubePodSecurityConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (PODSEC_EXACT.has(base)) return true
  if (startsWithAny(base, PODSEC_PREFIXES) && isYamlJsonFile(base)) return true
  if (includesAny(base, PODSEC_TERMS) && isYamlJsonFile(base)) return true
  if (PODSEC_DIR_TERMS.some((d) => lower.includes(d)) && isYamlJsonFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// KUBE_ADMISSION_CONTROLLER_DRIFT
// ---------------------------------------------------------------------------

const ADMISSION_EXACT = new Set([
  'validatingwebhookconfiguration.yaml', 'validatingwebhookconfiguration.yml',
  'mutatingwebhookconfiguration.yaml', 'mutatingwebhookconfiguration.yml',
  'validating-webhook.yaml', 'validating-webhook.yml',
  'mutating-webhook.yaml', 'mutating-webhook.yml',
  'admission-controller.yaml', 'admission-controller.yml',
])

const ADMISSION_PREFIXES = [
  'validatingwebhook', 'mutatingwebhook', 'validating-webhook', 'mutating-webhook',
  'admission-controller', 'admission-policy',
]

const ADMISSION_TERMS = [
  'validatingwebhookconfiguration', 'mutatingwebhookconfiguration',
  'admission-webhook', 'admission-controller',
]

const ADMISSION_DIR_TERMS = [
  'admission-controllers/', 'admission/', 'webhooks/',
]

function isKubeAdmissionControllerConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (ADMISSION_EXACT.has(base)) return true
  if (startsWithAny(base, ADMISSION_PREFIXES) && isYamlJsonFile(base)) return true
  if (includesAny(base, ADMISSION_TERMS) && isYamlJsonFile(base)) return true
  if (ADMISSION_DIR_TERMS.some((d) => lower.includes(d)) && isYamlJsonFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// KUBE_EXTERNAL_SECRETS_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents a Kubernetes external
 * secrets, sealed secrets, or secrets-store configuration file.
 *
 * Called by the KUBE_EXTERNAL_SECRETS_DRIFT rule.
 *
 * External Secrets Operator (ESO), Sealed Secrets, and CSI Secrets Store
 * configuration files bridge Kubernetes workloads to cloud secret backends.
 * Changes to these files may expose new secret material, alter access scopes,
 * modify encryption keys, or redirect secrets to a different backend entirely.
 *
 * Files to detect (examples):
 *   externalsecret.yaml / externalsecret-prod.yaml
 *   secretstore.yaml / secretstore-aws.yaml / clustersecretstore.yaml
 *   sealedsecret.yaml / sealedsecret-db.yaml
 *   secrets-store-csi.yaml / csi-secrets-store.yaml
 *   vault-agent-config.yaml / vault-secret-operator.yaml
 *
 * Trade-offs to consider:
 *   - Should plain `secret.yaml` match? (probably not — it's too generic and
 *     would fire on every Kubernetes Secret manifest, not just external-secrets config)
 *   - Should files inside an `external-secrets/` directory always match?
 *   - Should vault-agent and vault operator configs be included?
 *   - Should CSI secrets store provider config be included?
 *
 * The current implementation requires an unambiguous external-secrets-specific
 * term in the basename or path, or the file to be inside a known
 * external-secrets directory.
 */
export function isKubeExternalSecretConfig(normalisedPath: string): boolean {
  const base  = getBasename(normalisedPath).toLowerCase()
  const lower = normalisedPath.toLowerCase()

  if (!isYamlJsonFile(base)) return false

  // Unambiguous external-secrets-specific terms
  const EXACT_TERMS = [
    'externalsecret', 'external-secret', 'external_secret',
    'secretstore', 'secret-store', 'secret_store',
    'clustersecretstore', 'cluster-secret-store',
    'sealedsecret', 'sealed-secret', 'sealed_secret',
    'secrets-store-csi', 'csi-secrets-store', 'secretstorecsi',
    'vault-agent', 'vault-operator', 'vault-secret-operator',
    'vault-secret-store',
  ]
  if (EXACT_TERMS.some((t) => base.includes(t))) return true

  // Directory-level signals
  const SECRET_DIRS = [
    'external-secrets/', 'externalsecrets/', 'sealed-secrets/', 'sealedsecrets/',
    'secrets-store/', 'secretsstore/', 'vault-secrets/',
  ]
  if (SECRET_DIRS.some((d) => lower.includes(d)) && isYamlJsonFile(base)) return true

  return false
}

// ---------------------------------------------------------------------------
// DOCKERFILE_HARDENING_DRIFT
// ---------------------------------------------------------------------------

/** Base names that are Dockerfiles (with or without extension). */
const DOCKERFILE_NAMES = new Set([
  'dockerfile', 'dockerfile.dev', 'dockerfile.prod', 'dockerfile.test',
  'dockerfile.staging', 'dockerfile.local', 'dockerfile.base', 'dockerfile.ci',
  'dockerfile.build', 'dockerfile.release',
  '.dockerignore',
  'containerfile', 'containerfile.dev', 'containerfile.prod',
])

function isDockerfileHardeningFile(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  if (DOCKERFILE_NAMES.has(base)) return true
  // Matches Dockerfile.something (e.g. Dockerfile.amd64, Dockerfile.alpine)
  if (/^dockerfile\./i.test(base)) return true
  if (/^containerfile\./i.test(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// CONTAINER_RUNTIME_POLICY_DRIFT
// ---------------------------------------------------------------------------

/** Exact basenames for container runtime security profiles. */
const RUNTIME_EXACT = new Set([
  'seccomp.json', 'seccomp-profile.json',
  'audit.json',  // common seccomp profile name
  'containerd.toml', 'config.toml',    // containerd config (dir-gated below)
  'falco.yaml', 'falco.yml',
  'falco_rules.yaml', 'falco_rules.yml',
])

const RUNTIME_PREFIXES = [
  'seccomp-', 'apparmor-', 'falco-rule', 'falco_rule',
  'runtime-policy', 'runtime_policy',
]

const RUNTIME_TERMS = [
  'seccomp', 'apparmor', 'falco',
]

const RUNTIME_DIR_TERMS = [
  'seccomp/', 'apparmor/', 'falco/', '/containerd/config',
  'security-profiles/', 'runtime-policies/',
]

/** AppArmor profiles often have no extension — match by suffix. */
function isContainerRuntimePolicyFile(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (RUNTIME_EXACT.has(base)) return true
  if (startsWithAny(base, RUNTIME_PREFIXES)) return true
  if (includesAny(base, RUNTIME_TERMS)) return true
  if (RUNTIME_DIR_TERMS.some((d) => lower.includes(d))) return true
  // AppArmor profiles: files ending with .profile
  if (base.endsWith('.profile') && includesAny(lower, ['apparmor', 'security-profile'])) return true
  return false
}

// ---------------------------------------------------------------------------
// HELM_SECURITY_VALUES_DRIFT
// ---------------------------------------------------------------------------

/** Helm values files with security-signal names. */
const HELM_SECURITY_EXACT = new Set([
  'values-security.yaml', 'values-security.yml',
  'values.security.yaml', 'values.security.yml',
  'security-values.yaml', 'security-values.yml',
  'values-prod.yaml', 'values-prod.yml',
  'values-production.yaml', 'values-production.yml',
  'values-staging.yaml', 'values-staging.yml',
])

const HELM_SECURITY_PREFIXES = [
  'values-security', 'security-values', 'security-overrides',
  'hardening-values',
]

/** Security-relevant Helm chart sub-files. */
const HELM_SECURITY_TERMS = [
  'securitycontext', 'security-context', 'podSecurityContext',
  'network-policy', 'networkpolicy', 'rbac', 'serviceaccount',
  'psp', 'podsecurity', 'tls-values', 'ingress-tls',
]

const HELM_DIR_TERMS = ['/charts/', '/chart/', 'helm/']

function isHelmSecurityValuesFile(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (HELM_SECURITY_EXACT.has(base)) return true
  if (startsWithAny(base, HELM_SECURITY_PREFIXES) && isYamlFile(base)) return true
  // Generic values.yaml inside a Helm directory with a security-signal directory name
  if (base === 'values.yaml' || base === 'values.yml') {
    if (HELM_DIR_TERMS.some((d) => lower.includes(d))) {
      const SECURITY_DIR_SIGNALS = [
        'security', 'hardening', 'rbac', 'psp', 'networkpolicy', 'admission',
      ]
      if (SECURITY_DIR_SIGNALS.some((s) => lower.includes(s))) return true
    }
  }
  // HELM_SECURITY_TERMS only fire when the file is inside a Helm chart directory
  // to prevent false positives from k8s manifests with similar names.
  if (includesAny(base, HELM_SECURITY_TERMS) && isYamlFile(base) &&
      HELM_DIR_TERMS.some((d) => lower.includes(d))) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface ContainerHardeningRule {
  id: ContainerHardeningRuleId
  severity: ContainerHardeningSeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const CONTAINER_HARDENING_RULES: readonly ContainerHardeningRule[] = [
  {
    id: 'KUBE_RBAC_DRIFT',
    severity: 'critical',
    description:
      'Kubernetes RBAC Role, ClusterRole, RoleBinding, or ClusterRoleBinding manifest modified — RBAC changes are the highest-risk class of Kubernetes security change. A single overly permissive ClusterRole (e.g. `"*"` verbs on `"*"` resources) effectively grants the bound service account cluster-admin rights, enabling lateral movement, secret exfiltration, and persistent access.',
    recommendation:
      'Review every modified `rules` block for new wildcard (`"*"`) verbs or resources. Validate that new RoleBindings do not elevate service accounts beyond their intended scope. Run `kubectl auth can-i --list --as=<service-account>` post-deploy to verify effective permissions. Ensure changes comply with the principle of least privilege.',
    matches: isKubeRbacConfig,
  },
  {
    id: 'KUBE_NETWORK_POLICY_DRIFT',
    severity: 'high',
    description:
      'Kubernetes NetworkPolicy, Calico, or Cilium policy manifest modified — NetworkPolicy changes can open previously isolated pod-to-pod or pod-to-external communication paths. Removing a default-deny policy or adding overly broad `{}` selectors can expose internal services to the entire cluster or to the internet.',
    recommendation:
      'Verify that a default-deny ingress and egress policy remains in effect for all namespaces. Confirm that new `ingress`/`egress` rules use specific `podSelector` and `namespaceSelector` labels rather than empty selectors (`{}`). Validate that no new routes to external IPs were added for sensitive namespaces.',
    matches: isKubeNetworkPolicyConfig,
  },
  {
    id: 'KUBE_POD_SECURITY_DRIFT',
    severity: 'high',
    description:
      'Kubernetes PodSecurityPolicy, PodSecurityAdmission, OPA/Gatekeeper ConstraintTemplate, or Kyverno policy modified — pod security controls enforce runtime hardening across every workload in the cluster. Weakening or removing these policies can silently allow containers to run as root, mount host paths, use privileged mode, or escalate privileges via `allowPrivilegeEscalation`.',
    recommendation:
      'Verify that `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and dropped capabilities remain enforced. Confirm that PodSecurityAdmission labels were not changed from `enforce` to `warn` or `audit`. Review any modified ConstraintTemplate or Kyverno policy rules for removed security constraints.',
    matches: isKubePodSecurityConfig,
  },
  {
    id: 'KUBE_ADMISSION_CONTROLLER_DRIFT',
    severity: 'high',
    description:
      'Kubernetes ValidatingWebhookConfiguration or MutatingWebhookConfiguration modified — admission webhook changes control which requests are validated or mutated before they reach the API server. Removing a validating webhook silently disables security enforcement (e.g. OPA policies, image scanning gates). A maliciously crafted mutating webhook can intercept every resource creation and inject hostile configuration.',
    recommendation:
      'Verify that security-critical validating webhooks (OPA, Gatekeeper, Kyverno, image scanner) were not removed or set to `Ignore` failure policy. Confirm that mutating webhook `namespaceSelector` rules were not broadened to include system namespaces. Review any new webhooks for trusted service endpoints and valid TLS certificates.',
    matches: isKubeAdmissionControllerConfig,
  },
  {
    id: 'KUBE_EXTERNAL_SECRETS_DRIFT',
    severity: 'high',
    description:
      'Kubernetes ExternalSecret, SecretStore, SealedSecret, or CSI Secrets Store configuration modified — external secrets configurations bridge Kubernetes workloads to cloud secret backends (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault). Changes can expose new secret material, alter the IAM identity used to fetch secrets, or redirect a workload to a different — potentially attacker-controlled — backend.',
    recommendation:
      'Review every modified `SecretStore` for changes to the IAM role, Vault path, or credential source. Verify that `ExternalSecret` target names did not change to overwrite existing secrets. Confirm that `SealedSecret` encryption key references were not changed. Audit any new secret paths being fetched for least-privilege alignment.',
    matches: isKubeExternalSecretConfig,
  },
  {
    id: 'DOCKERFILE_HARDENING_DRIFT',
    severity: 'medium',
    description:
      'Dockerfile or .dockerignore modified — Dockerfile changes affect every downstream container image built from this repository. A base image downgrade, removal of a non-root `USER` directive, a new `COPY --chown=root` step, or an added `RUN chmod 777` line can silently re-introduce container hardening regressions that are difficult to detect in code review.',
    recommendation:
      'Verify that the base image tag was not changed to a less-hardened or unpinned variant (e.g. `latest`). Confirm that a non-root `USER` directive is still present before the final `ENTRYPOINT`/`CMD`. Check that no new `COPY` or `ADD` instructions include sensitive files. Verify `.dockerignore` was not modified to exclude fewer files.',
    matches: isDockerfileHardeningFile,
  },
  {
    id: 'CONTAINER_RUNTIME_POLICY_DRIFT',
    severity: 'medium',
    description:
      'Container runtime security profile (Seccomp, AppArmor, Falco, or containerd policy) modified — runtime security profiles define the syscall filter, MAC policy, and behavioural rules enforced at runtime for every container. Loosening a Seccomp profile (e.g. removing SCMP_ACT_ERRNO entries) or disabling Falco rules silently removes protection layers that defend against container escapes and post-compromise activity.',
    recommendation:
      'Review any syscall removals from Seccomp profiles — particularly for ptrace, mount, and clone syscalls which are commonly used in container escapes. Verify that Falco rule `condition` expressions were not narrowed or set to `false`. Confirm that AppArmor profile deny rules were not removed. Validate that containerd configuration changes do not disable seccomp or apparmor defaults.',
    matches: isContainerRuntimePolicyFile,
  },
  {
    id: 'HELM_SECURITY_VALUES_DRIFT',
    severity: 'medium',
    description:
      'Helm chart security values or security-specific chart overrides modified — Helm values files control security context settings, NetworkPolicy generation, RBAC creation, service account binding, and TLS configuration for all resources deployed by the chart. A single values change can disable NetworkPolicy creation, allow privilege escalation, or change the service account bound to a sensitive workload.',
    recommendation:
      'Verify that `securityContext.runAsNonRoot`, `securityContext.readOnlyRootFilesystem`, and `securityContext.capabilities.drop` settings were not removed or relaxed. Confirm that `networkPolicy.enabled` was not set to `false`. Check that `serviceAccount.create` and `rbac.create` flag changes do not bypass intended isolation boundaries.',
    matches: isHelmSecurityValuesFile,
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–62 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<ContainerHardeningSeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
}

const PENALTY_CAP: Record<ContainerHardeningSeverity, number> = {
  critical: 75,
  high:     35,
  medium:   20,
}

function toRiskLevel(score: number): ContainerHardeningRiskLevel {
  if (score === 0)  return 'none'
  if (score < 25)   return 'low'
  if (score < 50)   return 'medium'
  if (score < 75)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_SHORT_LABEL: Record<ContainerHardeningRuleId, string> = {
  KUBE_RBAC_DRIFT:               'Kubernetes RBAC',
  KUBE_NETWORK_POLICY_DRIFT:     'NetworkPolicy',
  KUBE_POD_SECURITY_DRIFT:       'Pod security policy',
  KUBE_ADMISSION_CONTROLLER_DRIFT: 'admission controller',
  KUBE_EXTERNAL_SECRETS_DRIFT:   'external secrets config',
  DOCKERFILE_HARDENING_DRIFT:    'Dockerfile',
  CONTAINER_RUNTIME_POLICY_DRIFT: 'container runtime policy',
  HELM_SECURITY_VALUES_DRIFT:    'Helm security values',
}

function buildSummary(
  findings: ContainerHardeningFinding[],
  riskLevel: ContainerHardeningRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return (
      `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — ` +
      'no Kubernetes or container security configuration file changes detected.'
    )
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
      `${findings.length} container hardening configuration file${findings.length === 1 ? '' : 's'} modified ` +
      `including ${joined} — mandatory container security review required before merge.`
    )
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${findings.length} container security configuration change${findings.length === 1 ? '' : 's'} across ` +
    `${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which Kubernetes and container security
 * configuration files were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor/build directories are excluded.
 * - Each rule fires at most once per scan (deduplicated per rule ID).
 * - The finding records the first matched path and total count of matched paths.
 */
export function scanContainerHardeningDrift(filePaths: string[]): ContainerHardeningDriftResult {
  const ruleAccumulator = new Map<ContainerHardeningRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of CONTAINER_HARDENING_RULES) {
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
  const findings: ContainerHardeningFinding[] = []
  for (const rule of CONTAINER_HARDENING_RULES) {
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
  const penaltyByTier: Partial<Record<ContainerHardeningSeverity, number>> = {}
  for (const f of findings) {
    penaltyByTier[f.severity] = (penaltyByTier[f.severity] ?? 0) + PENALTY_PER[f.severity]
  }

  let riskScore = 0
  for (const [sev, total] of Object.entries(penaltyByTier) as [ContainerHardeningSeverity, number][]) {
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
