// WS-107 — Kubernetes Admission Controller & Policy Engine Configuration Drift
// Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to Kubernetes admission controller and policy enforcement configuration:
// Kyverno ClusterPolicy/Policy resources, OPA Gatekeeper ConstraintTemplate
// and Constraint resources, ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration, image admission policy enforcement (Connaisseur
// / image-policy-webhook), Kubernetes NetworkPolicy, Pod Security Admission
// configuration, ResourceQuota and LimitRange resources, and policy exception
// or exemption overrides.
//
// Distinct from:
//   WS-63  (container hardening: Dockerfile security, pod securityContext,
//           PodSecurityPolicy/PodSecurityStandards namespace labels)
//   WS-67  (runtime security: Falco rules, OPA runtime policies, Seccomp
//           profiles, AppArmor, auditd — enforcement at pod runtime level)
//   WS-72  (service mesh: Istio/Envoy mTLS, traffic policies, PeerAuthentication)
//   WS-73  (CI/CD pipeline: GitHub Actions, Tekton, SLSA provenance)

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
// Rule 1: KYVERNO_POLICY_DRIFT (high)
// ---------------------------------------------------------------------------
// Kyverno ClusterPolicy and Policy resources define which workloads are
// permitted to run and what mutations are applied.  A silently weakened
// Kyverno policy can bypass image signing requirements, permit privileged
// containers, or disable network policy enforcement.

const KYVERNO_UNGATED = new Set([
  'kyverno-policy.yaml', 'kyverno-policy.yml',
  'kyverno-cluster-policy.yaml', 'kyverno-cluster-policy.yml',
  'clusterpolicy.yaml', 'clusterpolicy.yml',
])

const KYVERNO_DIRS = [
  'kyverno/', 'kyverno-policies/', 'policies/kyverno/', 'policy/kyverno/',
  'k8s/kyverno/', 'kubernetes/kyverno/', 'kyverno-config/',
]

function isKyvernoPolicy(path: string, base: string): boolean {
  if (KYVERNO_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('kyverno-') ||
    base.startsWith('clusterpolicy-') ||
    base.startsWith('kyverno-cluster-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return KYVERNO_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: OPA_GATEKEEPER_DRIFT (high)
// ---------------------------------------------------------------------------
// OPA Gatekeeper ConstraintTemplates define the Rego-based policy logic;
// Constraints instantiate those templates.  Removing a constraint stops policy
// enforcement; weakening a ConstraintTemplate changes the rules applied to
// every matching resource in the cluster.

const GATEKEEPER_UNGATED = new Set([
  'constraint-template.yaml', 'constraint-template.yml',
  'constrainttemplate.yaml', 'constrainttemplate.yml',
  'gatekeeper-config.yaml', 'gatekeeper-config.yml',
  'gatekeeper.yaml', 'gatekeeper.yml',
])

const GATEKEEPER_DIRS = [
  'gatekeeper/', 'opa-gatekeeper/', 'gatekeeper-policies/', 'gatekeeper-config/',
  'policies/gatekeeper/', 'k8s/gatekeeper/', 'kubernetes/gatekeeper/',
]

function isOpaGatekeeperConfig(path: string, base: string): boolean {
  if (GATEKEEPER_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('gatekeeper-') ||
    base.startsWith('constraint-template-') ||
    base.startsWith('opa-constraint-') ||
    base.startsWith('opa-gatekeeper-')
  ) {
    return /\.(yaml|yml|json|rego)$/.test(base)
  }

  return GATEKEEPER_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|rego)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: ADMISSION_WEBHOOK_DRIFT (high)
// ---------------------------------------------------------------------------
// ValidatingWebhookConfiguration and MutatingWebhookConfiguration resources
// define which webhooks are called for which API operations.  Adding a
// MutatingWebhookConfiguration is a well-known persistence technique that
// injects malicious sidecars; removing a ValidatingWebhookConfiguration
// disables an enforcement gate.

const WEBHOOK_UNGATED = new Set([
  'validating-webhook-configuration.yaml', 'validating-webhook-configuration.yml',
  'mutating-webhook-configuration.yaml', 'mutating-webhook-configuration.yml',
  'validatingwebhookconfiguration.yaml', 'validatingwebhookconfiguration.yml',
  'mutatingwebhookconfiguration.yaml', 'mutatingwebhookconfiguration.yml',
  'admission-webhook.yaml', 'admission-webhook.yml',
])

const WEBHOOK_DIRS = [
  'webhooks/', 'admission-webhooks/', 'admission-controller/', 'webhook-configs/',
  'k8s/webhooks/', 'kubernetes/webhooks/', 'manifests/webhooks/',
]

function isAdmissionWebhookConfig(path: string, base: string): boolean {
  if (WEBHOOK_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('validating-webhook-') ||
    base.startsWith('mutating-webhook-') ||
    base.startsWith('admission-webhook-') ||
    base.startsWith('webhook-config-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return WEBHOOK_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: IMAGE_ADMISSION_POLICY_DRIFT (high)
// ---------------------------------------------------------------------------
// Image admission policies enforce that only signed, trusted images can be
// deployed.  Connaisseur, image-policy-webhook, and Notary V2 configs define
// signing key trust anchors.  Drift here can allow unsigned or tampered
// images to bypass the gate.

const IMAGE_POLICY_UNGATED = new Set([
  'connaisseur-config.yaml', 'connaisseur.yaml', 'connaisseur.yml',
  'image-policy.yaml', 'image-policy.yml',
  'image-policy-webhook.yaml', 'image-policy-webhook.yml',
  'notaryv2-config.yaml', 'notary-config.yaml',
  'cosign-policy.yaml', 'cosign-policy.yml',
])

const IMAGE_POLICY_DIRS = [
  'connaisseur/', 'image-policy/', 'notary/', 'notaryv2/',
  'image-admission/', 'signing-policy/', 'cosign-policy/',
  'k8s/image-policy/', 'kubernetes/image-policy/',
]

function isImageAdmissionPolicy(path: string, base: string): boolean {
  if (IMAGE_POLICY_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('connaisseur-') ||
    base.startsWith('image-policy-') ||
    base.startsWith('image-admission-') ||
    base.startsWith('notary-config-') ||
    base.startsWith('cosign-policy-')
  ) {
    return /\.(yaml|yml|json|toml)$/.test(base)
  }

  return IMAGE_POLICY_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|toml|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: NETWORK_POLICY_DRIFT (medium)
// ---------------------------------------------------------------------------
// Kubernetes NetworkPolicy resources define which pods can communicate with
// each other and the outside world.  Removing or weakening a NetworkPolicy
// opens lateral movement paths; adding overly broad egress rules can create
// data exfiltration channels.

const NETPOL_UNGATED = new Set([
  'network-policy.yaml', 'network-policy.yml',
  'networkpolicy.yaml', 'networkpolicy.yml',
  'network-policies.yaml', 'network-policies.yml',
])

const NETPOL_DIRS = [
  'network-policies/', 'netpol/', 'network-policy/', 'networkpolicies/',
  'k8s/network-policies/', 'kubernetes/network-policies/', 'policies/network/',
]

function isNetworkPolicyConfig(path: string, base: string): boolean {
  if (NETPOL_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('netpol-') ||
    base.startsWith('network-policy-') ||
    base.startsWith('np-deny-') ||
    base.startsWith('np-allow-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return NETPOL_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: POD_SECURITY_ADMISSION_DRIFT (medium)
// ---------------------------------------------------------------------------
// Pod Security Admission configuration controls whether namespaces enforce
// `restricted`, `baseline`, or `privileged` security standards.  Downgrading
// a namespace from `restricted` to `privileged` removes all pod security
// enforcement for workloads in that namespace.

const PSA_UNGATED = new Set([
  'pod-security-admission.yaml', 'pod-security-admission.yml',
  'pod-security-policy.yaml', 'pod-security-policy.yml',
  'psa-config.yaml', 'psa-config.yml',
  'psp.yaml', 'psp.yml',
  'pod-security-standards.yaml', 'pod-security-standards.yml',
])

const PSA_DIRS = [
  'pod-security/', 'psa/', 'psp/', 'pod-security-admission/',
  'k8s/pod-security/', 'kubernetes/pod-security/', 'policies/pod-security/',
]

function isPodSecurityAdmissionConfig(path: string, base: string): boolean {
  if (PSA_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('pod-security-') ||
    base.startsWith('psa-') ||
    base.startsWith('psp-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return PSA_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: RESOURCE_QUOTA_POLICY_DRIFT (medium)
// ---------------------------------------------------------------------------
// ResourceQuota and LimitRange resources limit CPU, memory, and object counts
// per namespace.  Removing quotas enables resource exhaustion attacks and
// denial-of-service from misconfigured or compromised workloads; relaxing
// LimitRange defaults can allow containers to request unbounded resources.

const QUOTA_UNGATED = new Set([
  'resource-quota.yaml', 'resource-quota.yml',
  'resourcequota.yaml', 'resourcequota.yml',
  'limit-range.yaml', 'limit-range.yml',
  'limitrange.yaml', 'limitrange.yml',
])

const QUOTA_DIRS = [
  'resource-quotas/', 'quotas/', 'limit-ranges/', 'limitranges/',
  'k8s/quotas/', 'kubernetes/quotas/', 'policies/quotas/',
]

function isResourceQuotaPolicy(path: string, base: string): boolean {
  if (QUOTA_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('resource-quota-') ||
    base.startsWith('limit-range-') ||
    base.startsWith('quota-policy-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return QUOTA_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: POLICY_EXCEPTION_DRIFT (low) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures a policy exception, exemption, or
// override: Kyverno PolicyException resources, OPA Gatekeeper Config
// exemptions, or admission controller allowlist overrides.  Policy exceptions
// exist to handle legitimate edge cases, but drift in this area can silently
// extend exceptions to cover additional workloads or namespaces.
//
// Trade-offs to consider:
//   - "exceptions/" is a common directory name in non-k8s contexts
//   - kyverno-exception.yaml and policy-exception.yaml are fairly distinctive
//   - Require policy-exception/ or exceptions/ dir context for generic filenames
//   - gatekeeper-config.yaml is already ungated in Rule 2 — this rule focuses
//     on exception lists rather than the overall Gatekeeper config

const EXCEPTION_UNGATED = new Set([
  'policy-exception.yaml', 'policy-exception.yml',
  'kyverno-exception.yaml', 'kyverno-exception.yml',
  'policy-exceptions.yaml', 'policy-exceptions.yml',
  'admission-allowlist.yaml', 'admission-allowlist.yml',
  'webhook-bypass.yaml', 'webhook-bypass.yml',
])

const EXCEPTION_DIRS = [
  'policy-exceptions/', 'exceptions/', 'allowlists/', 'exemptions/',
  'kyverno/exceptions/', 'kyverno/allowlist/', 'gatekeeper/exceptions/',
]

export function isPolicyExceptionConfig(path: string, base: string): boolean {
  if (EXCEPTION_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('policy-exception-') ||
    base.startsWith('kyverno-exception-') ||
    base.startsWith('admission-allowlist-') ||
    base.startsWith('admission-exception-') ||
    base.startsWith('webhook-bypass-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return EXCEPTION_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type K8sAdmissionDriftRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: K8sAdmissionDriftRule[] = [
  {
    id: 'KYVERNO_POLICY_DRIFT',
    severity: 'high',
    description: 'Kyverno ClusterPolicy or Policy resource modified.',
    recommendation: 'Audit rule changes for weakened validations, relaxed image registry restrictions, or removed enforce-mode rules; confirm no policy has been switched from Enforce to Audit mode without change-control approval; verify auto-gen rules for pod controllers are still intact.',
    match: isKyvernoPolicy,
  },
  {
    id: 'OPA_GATEKEEPER_DRIFT',
    severity: 'high',
    description: 'OPA Gatekeeper ConstraintTemplate or Constraint resource modified.',
    recommendation: 'Review Rego logic changes in modified ConstraintTemplates for weakened enforcement; check that no Constraint has been deleted or reduced in scope; verify the Gatekeeper Config exemptionNamespaces list has not been expanded.',
    match: isOpaGatekeeperConfig,
  },
  {
    id: 'ADMISSION_WEBHOOK_DRIFT',
    severity: 'high',
    description: 'Kubernetes ValidatingWebhookConfiguration or MutatingWebhookConfiguration modified.',
    recommendation: 'Inspect changes to webhook rules, namespaceSelector, objectSelector, and failurePolicy; a MutatingWebhook added without change control can inject sidecars into every pod; verify caBundle references and service endpoints still point to trusted controllers.',
    match: isAdmissionWebhookConfig,
  },
  {
    id: 'IMAGE_ADMISSION_POLICY_DRIFT',
    severity: 'high',
    description: 'Image admission policy or signing configuration modified (Connaisseur / image-policy-webhook / Cosign policy).',
    recommendation: 'Verify trust anchor keys and cosign public keys have not been replaced; ensure the policy still enforces signature verification for production namespaces; check that no registry or image prefix has been added to an allowlist that bypasses verification.',
    match: isImageAdmissionPolicy,
  },
  {
    id: 'NETWORK_POLICY_DRIFT',
    severity: 'medium',
    description: 'Kubernetes NetworkPolicy resource modified.',
    recommendation: 'Review ingress and egress rule changes for new paths that permit lateral movement or external data exfiltration; confirm default-deny policies have not been removed; validate that namespace selectors still restrict cross-namespace traffic correctly.',
    match: isNetworkPolicyConfig,
  },
  {
    id: 'POD_SECURITY_ADMISSION_DRIFT',
    severity: 'medium',
    description: 'Kubernetes Pod Security Admission configuration or PodSecurityPolicy modified.',
    recommendation: 'Verify that namespace PodSecurity labels have not been downgraded from restricted to baseline or privileged; check that enforcement mode labels are still "enforce" rather than "audit" or "warn" in production namespaces.',
    match: isPodSecurityAdmissionConfig,
  },
  {
    id: 'RESOURCE_QUOTA_POLICY_DRIFT',
    severity: 'medium',
    description: 'Kubernetes ResourceQuota or LimitRange resource modified.',
    recommendation: 'Audit quota increases for namespaces handling sensitive workloads; removing or relaxing ResourceQuotas can enable resource exhaustion attacks; verify default memory and CPU limits in LimitRange still enforce reasonable container boundaries.',
    match: isResourceQuotaPolicy,
  },
  {
    id: 'POLICY_EXCEPTION_DRIFT',
    severity: 'low',
    description: 'Kubernetes policy exception, exemption, or admission allowlist modified.',
    recommendation: 'Audit which workloads or namespaces were added to the exception list; confirm each exception has a documented justification and expiry; verify that exception scope (namespace / resource name) is as narrow as possible.',
    match: isPolicyExceptionConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP: Record<Severity, number>     = { high: 45, medium: 25, low: 15 }

function computeRiskLevel(score: number): K8sAdmissionDriftResult['riskLevel'] {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type K8sAdmissionDriftFinding = {
  ruleId: string
  severity: Severity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type K8sAdmissionDriftResult = {
  riskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none'
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: K8sAdmissionDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// scanK8sAdmissionDrift
// ---------------------------------------------------------------------------

export function scanK8sAdmissionDrift(changedFiles: string[]): K8sAdmissionDriftResult {
  const normalised = changedFiles
    .map(normalise)
    .filter((p) => !isVendorPath(p))

  const findings: K8sAdmissionDriftFinding[] = []
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
    summary = 'No Kubernetes admission controller or policy configuration drift detected.'
  } else {
    const parts: string[] = []
    if (highCount > 0)   parts.push(`${highCount} high`)
    if (mediumCount > 0) parts.push(`${mediumCount} medium`)
    if (lowCount > 0)    parts.push(`${lowCount} low`)
    summary = `Kubernetes admission controller drift detected: ${parts.join(', ')} severity finding${findings.length > 1 ? 's' : ''}. Risk score ${totalScore}/100 (${riskLevel}).`
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
