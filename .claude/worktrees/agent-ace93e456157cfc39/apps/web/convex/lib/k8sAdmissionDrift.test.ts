/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { isPolicyExceptionConfig, scanK8sAdmissionDrift } from './k8sAdmissionDrift'

// ---------------------------------------------------------------------------
// Rule 1: KYVERNO_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('KYVERNO_POLICY_DRIFT detection', () => {
  it('detects ungated kyverno-policy.yaml at repo root', () => {
    const r = scanK8sAdmissionDrift(['kyverno-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('detects clusterpolicy.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['clusterpolicy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('detects kyverno-cluster-policy.yml ungated', () => {
    const r = scanK8sAdmissionDrift(['kyverno-cluster-policy.yml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('detects prefixed kyverno-*.yaml files', () => {
    const r = scanK8sAdmissionDrift(['kyverno-require-labels.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('detects clusterpolicy-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['clusterpolicy-disallow-latest.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in kyverno/ directory', () => {
    const r = scanK8sAdmissionDrift(['k8s/kyverno/require-labels.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in kyverno-policies/ directory', () => {
    const r = scanK8sAdmissionDrift(['kyverno-policies/block-privilege.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('ignores generic policy.yaml outside kyverno dirs', () => {
    const r = scanK8sAdmissionDrift(['config/policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: OPA_GATEKEEPER_DRIFT
// ---------------------------------------------------------------------------

describe('OPA_GATEKEEPER_DRIFT detection', () => {
  it('detects constrainttemplate.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['constrainttemplate.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(true)
  })

  it('detects gatekeeper.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['gatekeeper.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(true)
  })

  it('detects gatekeeper-config.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['gatekeeper-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(true)
  })

  it('detects gatekeeper-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['gatekeeper-require-labels.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(true)
  })

  it('detects .rego files in gatekeeper/ directory', () => {
    const r = scanK8sAdmissionDrift(['gatekeeper/policies/require-labels.rego'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(true)
  })

  it('detects yaml in opa-gatekeeper/ directory', () => {
    const r = scanK8sAdmissionDrift(['opa-gatekeeper/constraint.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(true)
  })

  it('ignores generic constraint.yaml outside gatekeeper dirs', () => {
    const r = scanK8sAdmissionDrift(['config/constraint.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: ADMISSION_WEBHOOK_DRIFT
// ---------------------------------------------------------------------------

describe('ADMISSION_WEBHOOK_DRIFT detection', () => {
  it('detects validating-webhook-configuration.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['validating-webhook-configuration.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('detects mutating-webhook-configuration.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['mutating-webhook-configuration.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('detects admission-webhook.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['admission-webhook.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('detects validating-webhook-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['validating-webhook-kyverno.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('detects admission-webhook-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['admission-webhook-cert-manager.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('detects yaml in webhooks/ directory', () => {
    const r = scanK8sAdmissionDrift(['k8s/webhooks/tls-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('detects yaml in admission-controller/ directory', () => {
    const r = scanK8sAdmissionDrift(['admission-controller/deploy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(true)
  })

  it('ignores generic webhook.yaml outside webhook dirs', () => {
    const r = scanK8sAdmissionDrift(['config/webhook.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ADMISSION_WEBHOOK_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: IMAGE_ADMISSION_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('IMAGE_ADMISSION_POLICY_DRIFT detection', () => {
  it('detects connaisseur.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['connaisseur.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects image-policy.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['image-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects cosign-policy.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['cosign-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects notaryv2-config.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['notaryv2-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects connaisseur-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['connaisseur-deployment.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects image-policy-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['image-policy-webhook.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects files in image-policy/ directory', () => {
    const r = scanK8sAdmissionDrift(['k8s/image-policy/trust.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })

  it('detects .toml in connaisseur/ directory', () => {
    const r = scanK8sAdmissionDrift(['connaisseur/config.toml'])
    expect(r.findings.some((f) => f.ruleId === 'IMAGE_ADMISSION_POLICY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: NETWORK_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('NETWORK_POLICY_DRIFT detection', () => {
  it('detects network-policy.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['network-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('detects networkpolicy.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['networkpolicy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('detects network-policies.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['network-policies.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('detects netpol-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['netpol-deny-all.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('detects np-deny-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['np-deny-egress.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in network-policies/ directory', () => {
    const r = scanK8sAdmissionDrift(['k8s/network-policies/deny-all.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in netpol/ directory', () => {
    const r = scanK8sAdmissionDrift(['netpol/allow-internal.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })

  it('ignores generic policy.yaml outside network-policy dirs', () => {
    const r = scanK8sAdmissionDrift(['k8s/deploy/policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: POD_SECURITY_ADMISSION_DRIFT
// ---------------------------------------------------------------------------

describe('POD_SECURITY_ADMISSION_DRIFT detection', () => {
  it('detects pod-security-admission.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['pod-security-admission.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects psa-config.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['psa-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects psp.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['psp.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects pod-security-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['pod-security-restricted.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects psa-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['psa-namespace-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects psp-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['psp-privileged.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects yaml in pod-security/ directory', () => {
    const r = scanK8sAdmissionDrift(['k8s/pod-security/baseline.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })

  it('detects yaml in psa/ directory', () => {
    const r = scanK8sAdmissionDrift(['psa/production-namespace.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POD_SECURITY_ADMISSION_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: RESOURCE_QUOTA_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('RESOURCE_QUOTA_POLICY_DRIFT detection', () => {
  it('detects resource-quota.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['resource-quota.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })

  it('detects limitrange.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['limitrange.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })

  it('detects limit-range.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['limit-range.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })

  it('detects resource-quota-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['resource-quota-prod.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })

  it('detects limit-range-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['limit-range-default.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in resource-quotas/ directory', () => {
    const r = scanK8sAdmissionDrift(['k8s/quotas/namespaced.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in limit-ranges/ directory', () => {
    const r = scanK8sAdmissionDrift(['limit-ranges/default.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RESOURCE_QUOTA_POLICY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: POLICY_EXCEPTION_DRIFT — exported
// ---------------------------------------------------------------------------

describe('POLICY_EXCEPTION_DRIFT detection', () => {
  it('detects policy-exception.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['policy-exception.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects kyverno-exception.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['kyverno-exception.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects admission-allowlist.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['admission-allowlist.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects webhook-bypass.yaml ungated', () => {
    const r = scanK8sAdmissionDrift(['webhook-bypass.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects policy-exception-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['policy-exception-legacy-app.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects kyverno-exception-*.yaml prefix', () => {
    const r = scanK8sAdmissionDrift(['kyverno-exception-monitoring.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects yaml in policy-exceptions/ directory', () => {
    const r = scanK8sAdmissionDrift(['policy-exceptions/legacy-services.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects yaml in exceptions/ directory', () => {
    const r = scanK8sAdmissionDrift(['kyverno/exceptions/monitoring.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'POLICY_EXCEPTION_DRIFT')).toBe(true)
  })

  it('isPolicyExceptionConfig: matches ungated policy-exception.yaml', () => {
    expect(isPolicyExceptionConfig('policy-exception.yaml', 'policy-exception.yaml')).toBe(true)
  })

  it('isPolicyExceptionConfig: matches kyverno-exception-*.yaml prefix', () => {
    expect(isPolicyExceptionConfig('kyverno-exception-batch.yaml', 'kyverno-exception-batch.yaml')).toBe(true)
  })

  it('isPolicyExceptionConfig: matches yaml in policy-exceptions/ dir', () => {
    expect(isPolicyExceptionConfig('policy-exceptions/override.yaml', 'override.yaml')).toBe(true)
  })

  it('isPolicyExceptionConfig: rejects generic override.yaml outside exception dirs', () => {
    expect(isPolicyExceptionConfig('config/override.yaml', 'override.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns riskLevel=none and riskScore=0 for empty input', () => {
    const r = scanK8sAdmissionDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('single high finding scores 15 → riskLevel=medium (15 is not < 15)', () => {
    const r = scanK8sAdmissionDrift(['kyverno-policy.yaml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('single medium finding scores 8 → riskLevel=low', () => {
    const r = scanK8sAdmissionDrift(['network-policy.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('single low finding scores 4 → riskLevel=low', () => {
    const r = scanK8sAdmissionDrift(['policy-exception.yaml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('two high findings score 30 → riskLevel=medium', () => {
    const r = scanK8sAdmissionDrift(['kyverno-policy.yaml', 'gatekeeper.yaml'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('three high findings score 45 → riskLevel=high (45 is not < 45)', () => {
    const r = scanK8sAdmissionDrift([
      'kyverno-policy.yaml',
      'gatekeeper.yaml',
      'validating-webhook-configuration.yaml',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('all 8 rules triggered scores 88 → riskLevel=critical', () => {
    const r = scanK8sAdmissionDrift([
      'kyverno-policy.yaml',         // KYVERNO_POLICY_DRIFT          H +15
      'gatekeeper.yaml',             // OPA_GATEKEEPER_DRIFT          H +15
      'admission-webhook.yaml',      // ADMISSION_WEBHOOK_DRIFT       H +15
      'connaisseur.yaml',            // IMAGE_ADMISSION_POLICY_DRIFT  H +15
      'network-policy.yaml',         // NETWORK_POLICY_DRIFT          M +8
      'pod-security-admission.yaml', // POD_SECURITY_ADMISSION_DRIFT  M +8
      'resource-quota.yaml',         // RESOURCE_QUOTA_POLICY_DRIFT   M +8
      'policy-exception.yaml',       // POLICY_EXCEPTION_DRIFT        L +4
    ])
    expect(r.riskScore).toBe(88)
    expect(r.riskLevel).toBe('critical')
  })

  it('riskScore is capped at 100 when total exceeds cap', () => {
    const many = Array.from({ length: 20 }, (_, i) => `kyverno-policy-${i}.yaml`)
    const r = scanK8sAdmissionDrift(many)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Per-rule deduplication
// ---------------------------------------------------------------------------

describe('per-rule deduplication', () => {
  it('multiple kyverno files still score only 15 for that rule', () => {
    const r = scanK8sAdmissionDrift([
      'kyverno-policy.yaml',
      'kyverno-cluster-policy.yaml',
      'kyverno-require-labels.yaml',
    ])
    const finding = r.findings.find((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')
    expect(finding?.matchCount).toBe(3)
    expect(r.riskScore).toBe(15)
  })

  it('multiple gatekeeper files still score only 15 for that rule', () => {
    const r = scanK8sAdmissionDrift([
      'gatekeeper.yaml',
      'gatekeeper-config.yaml',
      'constrainttemplate.yaml',
    ])
    const finding = r.findings.find((f) => f.ruleId === 'OPA_GATEKEEPER_DRIFT')
    expect(finding?.matchCount).toBe(3)
    expect(r.riskScore).toBe(15)
  })

  it('matchedPath is the first matched file', () => {
    const r = scanK8sAdmissionDrift([
      'network-policy.yaml',
      'netpol-deny-all.yaml',
    ])
    const finding = r.findings.find((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')
    expect(finding?.matchedPath).toBe('network-policy.yaml')
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('vendor path exclusion', () => {
  it('ignores kyverno policy files under node_modules/', () => {
    const r = scanK8sAdmissionDrift(['node_modules/pkg/kyverno-policy.yaml'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores gatekeeper files under vendor/', () => {
    const r = scanK8sAdmissionDrift(['vendor/opa/gatekeeper.yaml'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores admission webhook files under dist/', () => {
    const r = scanK8sAdmissionDrift(['dist/webhook/admission-webhook.yaml'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('path normalisation', () => {
  it('normalises Windows backslashes', () => {
    const r = scanK8sAdmissionDrift(['k8s\\kyverno\\require-labels.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KYVERNO_POLICY_DRIFT')).toBe(true)
  })

  it('normalises leading ./', () => {
    const r = scanK8sAdmissionDrift(['./network-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'NETWORK_POLICY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('returns clean summary for no findings', () => {
    const r = scanK8sAdmissionDrift([])
    expect(r.summary).toBe('No Kubernetes admission controller or policy configuration drift detected.')
  })

  it('summary mentions risk score and level for findings', () => {
    const r = scanK8sAdmissionDrift(['kyverno-policy.yaml'])
    expect(r.summary).toContain('15/100')
    expect(r.summary).toContain('medium')
  })

  it('summary uses plural "findings" when multiple rules fire', () => {
    const r = scanK8sAdmissionDrift(['kyverno-policy.yaml', 'gatekeeper.yaml'])
    expect(r.summary).toContain('findings')
  })

  it('counts are correct for mixed-severity batch', () => {
    const r = scanK8sAdmissionDrift([
      'kyverno-policy.yaml',
      'network-policy.yaml',
      'policy-exception.yaml',
    ])
    expect(r.highCount).toBe(1)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(3)
  })
})
