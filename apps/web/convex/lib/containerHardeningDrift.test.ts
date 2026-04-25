import { describe, expect, it } from 'vitest'
import {
  CONTAINER_HARDENING_RULES,
  isKubeExternalSecretConfig,
  scanContainerHardeningDrift,
  type ContainerHardeningDriftResult,
} from './containerHardeningDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): ContainerHardeningDriftResult {
  return scanContainerHardeningDrift(paths)
}

function expectClean(result: ContainerHardeningDriftResult) {
  expect(result.riskScore).toBe(0)
  expect(result.riskLevel).toBe('none')
  expect(result.totalFindings).toBe(0)
  expect(result.findings).toHaveLength(0)
}

function hasRule(result: ContainerHardeningDriftResult, ruleId: string) {
  return result.findings.some((f) => f.ruleId === ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('scanContainerHardeningDrift — trivial inputs', () => {
  it('returns clean result for empty array', () => {
    expectClean(scan([]))
  })

  it('returns clean result for whitespace-only paths', () => {
    expectClean(scan(['', '   ', '\t']))
  })

  it('returns clean result for non-container-security files', () => {
    expectClean(scan(['src/index.ts', 'README.md', 'package.json']))
  })

  it('summary mentions scanned file count for clean result', () => {
    const result = scan(['src/index.ts', 'src/app.ts'])
    expect(result.summary).toMatch(/2 changed file/)
    expect(result.summary).toMatch(/no Kubernetes or container/)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('scanContainerHardeningDrift — vendor path exclusion', () => {
  it('ignores role.yaml inside node_modules', () => {
    expectClean(scan(['node_modules/helm-chart/role.yaml']))
  })

  it('ignores Dockerfile inside dist', () => {
    expectClean(scan(['dist/Dockerfile']))
  })

  it('ignores networkpolicy.yaml inside .terraform', () => {
    expectClean(scan(['.terraform/modules/networkpolicy.yaml']))
  })

  it('flags role.yaml in non-vendor path', () => {
    const result = scan(['k8s/rbac/role.yaml'])
    expect(result.totalFindings).toBeGreaterThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// KUBE_RBAC_DRIFT
// ---------------------------------------------------------------------------

describe('KUBE_RBAC_DRIFT rule', () => {
  it('fires for role.yaml', () => {
    expect(hasRule(scan(['k8s/rbac/role.yaml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('fires for clusterrole.yaml', () => {
    expect(hasRule(scan(['k8s/clusterrole.yaml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('fires for rolebinding.yaml', () => {
    expect(hasRule(scan(['k8s/rbac/rolebinding.yaml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('fires for clusterrolebinding.yml', () => {
    expect(hasRule(scan(['infra/clusterrolebinding.yml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('fires for role- prefixed file', () => {
    expect(hasRule(scan(['k8s/rbac/role-admin.yaml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('fires for files inside rbac/ directory', () => {
    expect(hasRule(scan(['infra/rbac/custom-permissions.yaml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('fires for files inside roles/ directory', () => {
    expect(hasRule(scan(['helm/roles/developer.yaml']), 'KUBE_RBAC_DRIFT')).toBe(true)
  })

  it('does NOT fire for role.ts source file', () => {
    expectClean(scan(['src/auth/role.ts']))
  })

  it('does NOT fire for auth-model.json (non-k8s)', () => {
    expectClean(scan(['src/models/auth-model.json']))
  })

  it('severity is critical', () => {
    const result = scan(['k8s/rbac/role.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_RBAC_DRIFT')!
    expect(f.severity).toBe('critical')
  })

  it('records matchCount for multiple RBAC files', () => {
    const result = scan(['k8s/role.yaml', 'k8s/clusterrole.yaml', 'k8s/rolebinding.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_RBAC_DRIFT')!
    expect(f.matchCount).toBe(3)
  })

  it('records matchedPath as first matched file', () => {
    const result = scan(['k8s/role.yaml', 'k8s/clusterrole.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_RBAC_DRIFT')!
    expect(f.matchedPath).toBe('k8s/role.yaml')
  })
})

// ---------------------------------------------------------------------------
// KUBE_NETWORK_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('KUBE_NETWORK_POLICY_DRIFT rule', () => {
  it('fires for networkpolicy.yaml', () => {
    expect(hasRule(scan(['k8s/networkpolicy.yaml']), 'KUBE_NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('fires for network-policy.yml', () => {
    expect(hasRule(scan(['k8s/network-policy.yml']), 'KUBE_NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('fires for calico-policy.yaml', () => {
    expect(hasRule(scan(['infra/calico-policy.yaml']), 'KUBE_NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('fires for files inside network-policies/ directory', () => {
    expect(hasRule(scan(['k8s/network-policies/deny-all.yaml']), 'KUBE_NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('fires for files inside netpol/ directory', () => {
    expect(hasRule(scan(['infra/netpol/allow-frontend.yaml']), 'KUBE_NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('fires for deny-all prefixed file', () => {
    expect(hasRule(scan(['k8s/deny-all.yaml']), 'KUBE_NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT fire for networking.ts source file', () => {
    expectClean(scan(['src/networking.ts']))
  })

  it('severity is high', () => {
    const result = scan(['k8s/networkpolicy.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_NETWORK_POLICY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// KUBE_POD_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('KUBE_POD_SECURITY_DRIFT rule', () => {
  it('fires for podsecuritypolicy.yaml', () => {
    expect(hasRule(scan(['k8s/podsecuritypolicy.yaml']), 'KUBE_POD_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for psp.yaml', () => {
    expect(hasRule(scan(['k8s/psp.yaml']), 'KUBE_POD_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for pod-security-admission.yaml', () => {
    expect(hasRule(scan(['k8s/pod-security-admission.yaml']), 'KUBE_POD_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for kyverno-policy prefixed file', () => {
    expect(hasRule(scan(['policies/kyverno-policy-restrict.yaml']), 'KUBE_POD_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for files inside kyverno/ directory', () => {
    expect(hasRule(scan(['infra/kyverno/require-non-root.yaml']), 'KUBE_POD_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for gatekeeper constrainttemplate', () => {
    expect(hasRule(scan(['opa/constrainttemplate-no-priv.yaml']), 'KUBE_POD_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT fire for security.ts source file', () => {
    expectClean(scan(['src/security.ts']))
  })

  it('severity is high', () => {
    const result = scan(['k8s/psp.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_POD_SECURITY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// KUBE_ADMISSION_CONTROLLER_DRIFT
// ---------------------------------------------------------------------------

describe('KUBE_ADMISSION_CONTROLLER_DRIFT rule', () => {
  it('fires for validatingwebhookconfiguration.yaml', () => {
    expect(
      hasRule(scan(['k8s/validatingwebhookconfiguration.yaml']), 'KUBE_ADMISSION_CONTROLLER_DRIFT'),
    ).toBe(true)
  })

  it('fires for mutatingwebhookconfiguration.yml', () => {
    expect(
      hasRule(scan(['k8s/mutatingwebhookconfiguration.yml']), 'KUBE_ADMISSION_CONTROLLER_DRIFT'),
    ).toBe(true)
  })

  it('fires for validating-webhook.yaml', () => {
    expect(
      hasRule(scan(['infra/validating-webhook.yaml']), 'KUBE_ADMISSION_CONTROLLER_DRIFT'),
    ).toBe(true)
  })

  it('fires for files inside admission-controllers/ directory', () => {
    expect(
      hasRule(scan(['k8s/admission-controllers/opa-webhook.yaml']), 'KUBE_ADMISSION_CONTROLLER_DRIFT'),
    ).toBe(true)
  })

  it('does NOT fire for webhook.ts source file', () => {
    expectClean(scan(['src/webhook.ts']))
  })

  it('severity is high', () => {
    const result = scan(['k8s/validatingwebhookconfiguration.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_ADMISSION_CONTROLLER_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// KUBE_EXTERNAL_SECRETS_DRIFT — isKubeExternalSecretConfig helper
// ---------------------------------------------------------------------------

describe('isKubeExternalSecretConfig', () => {
  it('detects externalsecret.yaml', () => {
    expect(isKubeExternalSecretConfig('k8s/externalsecret.yaml')).toBe(true)
  })

  it('detects external-secret.yaml', () => {
    expect(isKubeExternalSecretConfig('k8s/external-secret.yaml')).toBe(true)
  })

  it('detects secretstore.yaml', () => {
    expect(isKubeExternalSecretConfig('k8s/secretstore.yaml')).toBe(true)
  })

  it('detects clustersecretstore.yaml', () => {
    expect(isKubeExternalSecretConfig('k8s/clustersecretstore.yaml')).toBe(true)
  })

  it('detects sealedsecret.yaml', () => {
    expect(isKubeExternalSecretConfig('k8s/sealedsecret.yaml')).toBe(true)
  })

  it('detects vault-agent.yaml', () => {
    expect(isKubeExternalSecretConfig('infra/vault-agent.yaml')).toBe(true)
  })

  it('detects vault-secret-store.yaml', () => {
    expect(isKubeExternalSecretConfig('infra/vault-secret-store.yaml')).toBe(true)
  })

  it('detects files inside external-secrets/ directory', () => {
    expect(isKubeExternalSecretConfig('k8s/external-secrets/db-secret.yaml')).toBe(true)
  })

  it('detects files inside sealed-secrets/ directory', () => {
    expect(isKubeExternalSecretConfig('k8s/sealed-secrets/api-key.yaml')).toBe(true)
  })

  it('does NOT detect plain secret.yaml (too generic)', () => {
    expect(isKubeExternalSecretConfig('k8s/secret.yaml')).toBe(false)
  })

  it('does NOT detect secrets.ts source file', () => {
    expect(isKubeExternalSecretConfig('src/secrets.ts')).toBe(false)
  })

  it('does NOT detect README.md', () => {
    expect(isKubeExternalSecretConfig('k8s/external-secrets/README.md')).toBe(false)
  })
})

describe('KUBE_EXTERNAL_SECRETS_DRIFT rule (via scanner)', () => {
  it('fires for externalsecret.yaml', () => {
    expect(hasRule(scan(['k8s/externalsecret.yaml']), 'KUBE_EXTERNAL_SECRETS_DRIFT')).toBe(true)
  })

  it('fires for sealedsecret.yaml', () => {
    expect(hasRule(scan(['k8s/sealedsecret.yaml']), 'KUBE_EXTERNAL_SECRETS_DRIFT')).toBe(true)
  })

  it('fires for files in external-secrets/ directory', () => {
    expect(
      hasRule(scan(['k8s/external-secrets/api-key.yaml']), 'KUBE_EXTERNAL_SECRETS_DRIFT'),
    ).toBe(true)
  })

  it('does NOT fire for plain secret.yaml', () => {
    expect(hasRule(scan(['k8s/secret.yaml']), 'KUBE_EXTERNAL_SECRETS_DRIFT')).toBe(false)
  })

  it('severity is high', () => {
    const result = scan(['k8s/externalsecret.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'KUBE_EXTERNAL_SECRETS_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// DOCKERFILE_HARDENING_DRIFT
// ---------------------------------------------------------------------------

describe('DOCKERFILE_HARDENING_DRIFT rule', () => {
  it('fires for Dockerfile', () => {
    expect(hasRule(scan(['Dockerfile']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(true)
  })

  it('fires for Dockerfile.prod', () => {
    expect(hasRule(scan(['Dockerfile.prod']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(true)
  })

  it('fires for Dockerfile.dev', () => {
    expect(hasRule(scan(['services/api/Dockerfile.dev']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(true)
  })

  it('fires for .dockerignore', () => {
    expect(hasRule(scan(['.dockerignore']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(true)
  })

  it('fires for Containerfile', () => {
    expect(hasRule(scan(['Containerfile']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(true)
  })

  it('fires for dockerfile.ci variant', () => {
    expect(hasRule(scan(['ci/dockerfile.ci']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(true)
  })

  it('does NOT fire for docker-compose.yml', () => {
    expect(hasRule(scan(['docker-compose.yml']), 'DOCKERFILE_HARDENING_DRIFT')).toBe(false)
  })

  it('does NOT fire for dockerfile-utils.ts source file', () => {
    expectClean(scan(['src/dockerfile-utils.ts']))
  })

  it('severity is medium', () => {
    const result = scan(['Dockerfile'])
    const f = result.findings.find((f) => f.ruleId === 'DOCKERFILE_HARDENING_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// CONTAINER_RUNTIME_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('CONTAINER_RUNTIME_POLICY_DRIFT rule', () => {
  it('fires for seccomp.json', () => {
    expect(hasRule(scan(['profiles/seccomp.json']), 'CONTAINER_RUNTIME_POLICY_DRIFT')).toBe(true)
  })

  it('fires for seccomp-profile.json', () => {
    expect(hasRule(scan(['security/seccomp-profile.json']), 'CONTAINER_RUNTIME_POLICY_DRIFT')).toBe(true)
  })

  it('fires for falco.yaml', () => {
    expect(hasRule(scan(['infra/falco.yaml']), 'CONTAINER_RUNTIME_POLICY_DRIFT')).toBe(true)
  })

  it('fires for falco_rules.yaml', () => {
    expect(hasRule(scan(['falco/falco_rules.yaml']), 'CONTAINER_RUNTIME_POLICY_DRIFT')).toBe(true)
  })

  it('fires for files in seccomp/ directory', () => {
    expect(
      hasRule(scan(['k8s/seccomp/runtime-default.json']), 'CONTAINER_RUNTIME_POLICY_DRIFT'),
    ).toBe(true)
  })

  it('fires for files in apparmor/ directory', () => {
    expect(
      hasRule(scan(['security/apparmor/container-profile']), 'CONTAINER_RUNTIME_POLICY_DRIFT'),
    ).toBe(true)
  })

  it('does NOT fire for plain config.ts source file', () => {
    expectClean(scan(['src/config.ts']))
  })

  it('severity is medium', () => {
    const result = scan(['security/seccomp.json'])
    const f = result.findings.find((f) => f.ruleId === 'CONTAINER_RUNTIME_POLICY_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// HELM_SECURITY_VALUES_DRIFT
// ---------------------------------------------------------------------------

describe('HELM_SECURITY_VALUES_DRIFT rule', () => {
  it('fires for values-security.yaml', () => {
    expect(hasRule(scan(['helm/values-security.yaml']), 'HELM_SECURITY_VALUES_DRIFT')).toBe(true)
  })

  it('fires for values-prod.yaml', () => {
    expect(hasRule(scan(['helm/values-prod.yaml']), 'HELM_SECURITY_VALUES_DRIFT')).toBe(true)
  })

  it('fires for values.yaml inside helm/security/ directory', () => {
    expect(
      hasRule(scan(['helm/security/values.yaml']), 'HELM_SECURITY_VALUES_DRIFT'),
    ).toBe(true)
  })

  it('fires for values-production.yml', () => {
    expect(hasRule(scan(['charts/api/values-production.yml']), 'HELM_SECURITY_VALUES_DRIFT')).toBe(true)
  })

  it('does NOT fire for generic values.yaml not inside a helm directory', () => {
    expect(hasRule(scan(['config/values.yaml']), 'HELM_SECURITY_VALUES_DRIFT')).toBe(false)
  })

  it('does NOT fire for values.ts source file', () => {
    expectClean(scan(['src/values.ts']))
  })

  it('severity is medium', () => {
    const result = scan(['helm/values-security.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'HELM_SECURITY_VALUES_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanContainerHardeningDrift — scoring', () => {
  it('riskScore is 0 for clean result', () => {
    expect(scan([]).riskScore).toBe(0)
  })

  it('riskLevel is none for zero findings', () => {
    expect(scan([]).riskLevel).toBe('none')
  })

  it('riskScore is positive when KUBE_RBAC_DRIFT fires', () => {
    const result = scan(['k8s/role.yaml'])
    expect(result.riskScore).toBeGreaterThan(0)
  })

  it('riskLevel is elevated (medium or above) when critical rule fires', () => {
    // Single critical finding: penalty=30 → riskScore=30 → 'medium' band (25–49)
    const result = scan(['k8s/role.yaml'])
    expect(['medium', 'high', 'critical']).toContain(result.riskLevel)
  })

  it('riskScore increases with more rules firing', () => {
    const single = scan(['k8s/role.yaml'])
    const multi  = scan(['k8s/role.yaml', 'k8s/networkpolicy.yaml'])
    expect(multi.riskScore).toBeGreaterThan(single.riskScore)
  })

  it('riskScore is capped at 100', () => {
    const result = scan([
      'k8s/role.yaml',
      'k8s/networkpolicy.yaml',
      'k8s/psp.yaml',
      'k8s/validatingwebhookconfiguration.yaml',
      'k8s/externalsecret.yaml',
      'Dockerfile',
      'security/seccomp.json',
      'helm/values-security.yaml',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })

  it('criticalCount and highCount are populated correctly', () => {
    const result = scan([
      'k8s/role.yaml',                          // critical
      'k8s/networkpolicy.yaml',                 // high
      'k8s/validatingwebhookconfiguration.yaml', // high
    ])
    expect(result.criticalCount).toBe(1)
    expect(result.highCount).toBe(2)
  })

  it('mediumCount is populated correctly', () => {
    const result = scan(['Dockerfile', 'security/seccomp.json'])
    expect(result.mediumCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('scanContainerHardeningDrift — summary', () => {
  it('mentions "container hardening" in findings summary', () => {
    const result = scan(['k8s/role.yaml'])
    expect(result.summary).toMatch(/container hardening/)
  })

  it('mentions "mandatory" for critical/high findings', () => {
    const result = scan(['k8s/role.yaml'])
    expect(result.summary).toMatch(/mandatory/)
  })

  it('mentions "no Kubernetes or container" for clean result', () => {
    const result = scan(['src/index.ts'])
    expect(result.summary).toMatch(/no Kubernetes or container/)
  })

  it('includes finding count in multi-finding summary', () => {
    const result = scan(['k8s/role.yaml', 'k8s/networkpolicy.yaml'])
    expect(result.summary).toMatch(/2 container hardening/)
  })
})

// ---------------------------------------------------------------------------
// CONTAINER_HARDENING_RULES constant integrity
// ---------------------------------------------------------------------------

describe('CONTAINER_HARDENING_RULES constants', () => {
  it('contains 8 rules', () => {
    expect(CONTAINER_HARDENING_RULES).toHaveLength(8)
  })

  it('all rules have non-empty descriptions', () => {
    for (const rule of CONTAINER_HARDENING_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
    }
  })

  it('all rules have non-empty recommendations', () => {
    for (const rule of CONTAINER_HARDENING_RULES) {
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })

  it('critical rules come before high and medium', () => {
    const severities = CONTAINER_HARDENING_RULES.map((r) => r.severity)
    const criticalIdx = severities.findIndex((s) => s === 'critical')
    const mediumIdx   = severities.findIndex((s) => s === 'medium')
    expect(criticalIdx).toBeLessThan(mediumIdx)
  })

  it('all rule IDs are unique', () => {
    const ids = CONTAINER_HARDENING_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})
