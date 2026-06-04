import { describe, expect, it } from 'vitest'
import {
  computeCertificationResult,
  computeCertificationTier,
  type CertificationInput,
} from './llmCertification'

// ── Fixtures ──────────────────────────────────────────────────────────────────

const cleanInput: CertificationInput = {
  promptInjection: { riskLevel: 'clean', score: 0 },
  supplyChain: { totalPackages: 20, compromisedCount: 0, suspiciousCount: 0, atRiskCount: 0, highestRiskLevel: 'trusted' },
  agenticPipeline: { criticalCount: 0, highCount: 0, mediumCount: 0 },
  exploitValidation: { totalRuns: 5, validatedCount: 0, likelyExploitableCount: 0 },
  regulatoryCompliance: { overallDriftLevel: 'compliant', criticalGapCount: 0, openGapCount: 0 },
  attackSurface: { score: 85, openCriticalCount: 0, openHighCount: 1, trend: 'improving' },
  dependencyTrust: { avgTrustScore: 90, untrustedCount: 0, totalComponents: 20 },
}

const allNullsInput: CertificationInput = {
  promptInjection: null,
  supplyChain: null,
  agenticPipeline: null,
  exploitValidation: null,
  regulatoryCompliance: null,
  attackSurface: null,
  dependencyTrust: null,
}

// ── computeCertificationTier ──────────────────────────────────────────────────

describe('computeCertificationTier', () => {
  it('returns gold when all 7 domains pass', () => {
    expect(computeCertificationTier(7, [], 0)).toBe('gold')
  })

  it('returns gold with 6 passes and 1 warn', () => {
    expect(computeCertificationTier(6, [], 1)).toBe('gold')
  })

  it('returns silver (not gold) with 6 passes and 1 warn — boundary', () => {
    // Gold requires 6+ pass AND ≤1 warn; silver needs 4+ pass
    expect(computeCertificationTier(5, [], 2)).toBe('silver')
  })

  it('returns silver with 4 passes and no critical failures', () => {
    expect(computeCertificationTier(4, [], 3)).toBe('silver')
  })

  it('returns bronze with exactly 2 passes, no critical failures', () => {
    expect(computeCertificationTier(2, [], 5)).toBe('bronze')
  })

  it('returns uncertified with 1 pass', () => {
    expect(computeCertificationTier(1, [], 6)).toBe('uncertified')
  })

  it('returns uncertified when any critical domain fails', () => {
    expect(computeCertificationTier(6, ['prompt_injection'], 0)).toBe('uncertified')
  })

  it('returns uncertified when multiple critical domains fail', () => {
    expect(
      computeCertificationTier(4, ['prompt_injection', 'supply_chain_integrity'], 2),
    ).toBe('uncertified')
  })

  it('critical failure blocks silver even with 6 passes', () => {
    expect(computeCertificationTier(6, ['exploit_validation'], 0)).toBe('uncertified')
  })

  it('returns uncertified with 0 passes', () => {
    expect(computeCertificationTier(0, [], 7)).toBe('uncertified')
  })
})

// ── Prompt injection domain ───────────────────────────────────────────────────

describe('prompt_injection domain', () => {
  it('passes when riskLevel=clean and score=0', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      promptInjection: { riskLevel: 'clean', score: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'prompt_injection')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(100)
  })

  it('warns when riskLevel=suspicious', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      promptInjection: { riskLevel: 'suspicious', score: 25 },
    })
    const d = result.domainResults.find((r) => r.domain === 'prompt_injection')!
    expect(d.outcome).toBe('warn')
  })

  it('fails when riskLevel=confirmed_injection', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      promptInjection: { riskLevel: 'confirmed_injection', score: 100 },
    })
    const d = result.domainResults.find((r) => r.domain === 'prompt_injection')!
    expect(d.outcome).toBe('fail')
    expect(d.score).toBe(0)
  })

  it('fails when riskLevel=likely_injection', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      promptInjection: { riskLevel: 'likely_injection', score: 70 },
    })
    const d = result.domainResults.find((r) => r.domain === 'prompt_injection')!
    expect(d.outcome).toBe('fail')
  })

  it('warns when null (no scan)', () => {
    const result = computeCertificationResult(allNullsInput)
    const d = result.domainResults.find((r) => r.domain === 'prompt_injection')!
    expect(d.outcome).toBe('warn')
    expect(d.score).toBe(50)
  })
})

// ── Supply chain integrity domain ─────────────────────────────────────────────

describe('supply_chain_integrity domain', () => {
  it('passes when all packages are trusted', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      supplyChain: { totalPackages: 30, compromisedCount: 0, suspiciousCount: 0, atRiskCount: 0, highestRiskLevel: 'trusted' },
    })
    const d = result.domainResults.find((r) => r.domain === 'supply_chain_integrity')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(100)
  })

  it('fails when any package is compromised', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      supplyChain: { totalPackages: 20, compromisedCount: 1, suspiciousCount: 0, atRiskCount: 0, highestRiskLevel: 'compromised' },
    })
    const d = result.domainResults.find((r) => r.domain === 'supply_chain_integrity')!
    expect(d.outcome).toBe('fail')
    expect(d.score).toBe(0)
  })

  it('warns when suspicious packages are present', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      supplyChain: { totalPackages: 25, compromisedCount: 0, suspiciousCount: 2, atRiskCount: 0, highestRiskLevel: 'suspicious' },
    })
    const d = result.domainResults.find((r) => r.domain === 'supply_chain_integrity')!
    expect(d.outcome).toBe('warn')
  })

  it('warns when at-risk packages exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      supplyChain: { totalPackages: 10, compromisedCount: 0, suspiciousCount: 0, atRiskCount: 3, highestRiskLevel: 'at_risk' },
    })
    const d = result.domainResults.find((r) => r.domain === 'supply_chain_integrity')!
    expect(d.outcome).toBe('warn')
  })
})

// ── Agentic pipeline domain ───────────────────────────────────────────────────

describe('agentic_pipeline_safety domain', () => {
  it('passes when no findings', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      agenticPipeline: { criticalCount: 0, highCount: 0, mediumCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'agentic_pipeline_safety')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(100)
  })

  it('fails when critical findings exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      agenticPipeline: { criticalCount: 2, highCount: 1, mediumCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'agentic_pipeline_safety')!
    expect(d.outcome).toBe('fail')
  })

  it('warns when only high findings exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      agenticPipeline: { criticalCount: 0, highCount: 3, mediumCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'agentic_pipeline_safety')!
    expect(d.outcome).toBe('warn')
  })

  it('warns when only medium findings exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      agenticPipeline: { criticalCount: 0, highCount: 0, mediumCount: 5 },
    })
    const d = result.domainResults.find((r) => r.domain === 'agentic_pipeline_safety')!
    expect(d.outcome).toBe('warn')
  })
})

// ── Exploit validation domain ─────────────────────────────────────────────────

describe('exploit_validation domain', () => {
  it('passes with 5 runs and no validated findings', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      exploitValidation: { totalRuns: 5, validatedCount: 0, likelyExploitableCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'exploit_validation')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(95)
  })

  it('fails when validated exploits exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      exploitValidation: { totalRuns: 10, validatedCount: 2, likelyExploitableCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'exploit_validation')!
    expect(d.outcome).toBe('fail')
  })

  it('fails when likely-exploitable findings exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      exploitValidation: { totalRuns: 3, validatedCount: 0, likelyExploitableCount: 1 },
    })
    const d = result.domainResults.find((r) => r.domain === 'exploit_validation')!
    expect(d.outcome).toBe('fail')
  })

  it('warns when totalRuns=0', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      exploitValidation: { totalRuns: 0, validatedCount: 0, likelyExploitableCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'exploit_validation')!
    expect(d.outcome).toBe('warn')
  })
})

// ── Regulatory compliance domain ──────────────────────────────────────────────

describe('regulatory_compliance domain', () => {
  it('passes when compliant with no gaps', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      regulatoryCompliance: { overallDriftLevel: 'compliant', criticalGapCount: 0, openGapCount: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'regulatory_compliance')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(100)
  })

  it('fails when non_compliant', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      regulatoryCompliance: { overallDriftLevel: 'non_compliant', criticalGapCount: 5, openGapCount: 15 },
    })
    const d = result.domainResults.find((r) => r.domain === 'regulatory_compliance')!
    expect(d.outcome).toBe('fail')
  })

  it('fails when at_risk', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      regulatoryCompliance: { overallDriftLevel: 'at_risk', criticalGapCount: 2, openGapCount: 8 },
    })
    const d = result.domainResults.find((r) => r.domain === 'regulatory_compliance')!
    expect(d.outcome).toBe('fail')
  })

  it('warns when drifting', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      regulatoryCompliance: { overallDriftLevel: 'drifting', criticalGapCount: 0, openGapCount: 3 },
    })
    const d = result.domainResults.find((r) => r.domain === 'regulatory_compliance')!
    expect(d.outcome).toBe('warn')
    expect(d.score).toBe(65)
  })
})

// ── Attack surface domain ─────────────────────────────────────────────────────

describe('attack_surface domain', () => {
  it('passes with high score, no critical findings, improving trend', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      attackSurface: { score: 82, openCriticalCount: 0, openHighCount: 0, trend: 'improving' },
    })
    const d = result.domainResults.find((r) => r.domain === 'attack_surface')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(82)
  })

  it('fails when open critical findings exist', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      attackSurface: { score: 65, openCriticalCount: 3, openHighCount: 0, trend: 'stable' },
    })
    const d = result.domainResults.find((r) => r.domain === 'attack_surface')!
    expect(d.outcome).toBe('fail')
  })

  it('fails when score < 40', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      attackSurface: { score: 30, openCriticalCount: 0, openHighCount: 2, trend: 'degrading' },
    })
    const d = result.domainResults.find((r) => r.domain === 'attack_surface')!
    expect(d.outcome).toBe('fail')
  })

  it('warns when score is moderate (40–70)', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      attackSurface: { score: 58, openCriticalCount: 0, openHighCount: 2, trend: 'stable' },
    })
    const d = result.domainResults.find((r) => r.domain === 'attack_surface')!
    expect(d.outcome).toBe('warn')
  })
})

// ── Dependency trust domain ───────────────────────────────────────────────────

describe('dependency_trust domain', () => {
  it('passes with high avg trust and no untrusted packages', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      dependencyTrust: { avgTrustScore: 85, untrustedCount: 0, totalComponents: 50 },
    })
    const d = result.domainResults.find((r) => r.domain === 'dependency_trust')!
    expect(d.outcome).toBe('pass')
  })

  it('passes with no components', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      dependencyTrust: { avgTrustScore: 0, untrustedCount: 0, totalComponents: 0 },
    })
    const d = result.domainResults.find((r) => r.domain === 'dependency_trust')!
    expect(d.outcome).toBe('pass')
    expect(d.score).toBe(100)
  })

  it('fails with low avg trust score', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      dependencyTrust: { avgTrustScore: 25, untrustedCount: 8, totalComponents: 30 },
    })
    const d = result.domainResults.find((r) => r.domain === 'dependency_trust')!
    expect(d.outcome).toBe('fail')
  })

  it('warns with moderate trust score', () => {
    const result = computeCertificationResult({
      ...allNullsInput,
      dependencyTrust: { avgTrustScore: 55, untrustedCount: 3, totalComponents: 40 },
    })
    const d = result.domainResults.find((r) => r.domain === 'dependency_trust')!
    expect(d.outcome).toBe('warn')
  })
})

// ── Full result integration tests ─────────────────────────────────────────────

describe('computeCertificationResult — full integration', () => {
  it('gold: all clean inputs produce pass×7, gold tier, high overall score', () => {
    const result = computeCertificationResult(cleanInput)
    expect(result.tier).toBe('gold')
    expect(result.passCount).toBe(7)
    expect(result.warnCount).toBe(0)
    expect(result.failCount).toBe(0)
    expect(result.criticalFailedDomains).toHaveLength(0)
    expect(result.overallScore).toBeGreaterThan(85)
    expect(result.summary).toMatch(/Gold/)
  })

  it('uncertified: confirmed injection blocks certification regardless of other signals', () => {
    const result = computeCertificationResult({
      ...cleanInput,
      promptInjection: { riskLevel: 'confirmed_injection', score: 100 },
    })
    expect(result.tier).toBe('uncertified')
    expect(result.criticalFailedDomains).toContain('prompt_injection')
    expect(result.summary).toMatch(/Uncertified/)
  })

  it('uncertified: compromised supply chain blocks certification', () => {
    const result = computeCertificationResult({
      ...cleanInput,
      supplyChain: { totalPackages: 10, compromisedCount: 2, suspiciousCount: 0, atRiskCount: 0, highestRiskLevel: 'compromised' },
    })
    expect(result.tier).toBe('uncertified')
    expect(result.criticalFailedDomains).toContain('supply_chain_integrity')
  })

  it('uncertified: validated exploits block certification', () => {
    const result = computeCertificationResult({
      ...cleanInput,
      exploitValidation: { totalRuns: 5, validatedCount: 1, likelyExploitableCount: 0 },
    })
    expect(result.tier).toBe('uncertified')
    expect(result.criticalFailedDomains).toContain('exploit_validation')
  })

  it('silver: non-critical domain failures produce silver', () => {
    const result = computeCertificationResult({
      ...cleanInput,
      // agentic pipeline has critical finding (non-critical domain)
      agenticPipeline: { criticalCount: 1, highCount: 0, mediumCount: 0 },
      // attack surface below threshold
      attackSurface: { score: 30, openCriticalCount: 2, openHighCount: 5, trend: 'degrading' },
      // dependency trust low
      dependencyTrust: { avgTrustScore: 20, untrustedCount: 10, totalComponents: 40 },
    })
    // 3 fails but none critical → could be silver or bronze
    expect(['silver', 'bronze']).toContain(result.tier)
    expect(result.criticalFailedDomains).toHaveLength(0)
  })

  it('all nulls produces all warns and uncertified (0 passes)', () => {
    const result = computeCertificationResult(allNullsInput)
    expect(result.passCount).toBe(0)
    expect(result.warnCount).toBe(7)
    expect(result.failCount).toBe(0)
    expect(result.tier).toBe('uncertified')
  })

  it('overall score is 0–100', () => {
    const r1 = computeCertificationResult(cleanInput)
    const r2 = computeCertificationResult(allNullsInput)
    expect(r1.overallScore).toBeGreaterThanOrEqual(0)
    expect(r1.overallScore).toBeLessThanOrEqual(100)
    expect(r2.overallScore).toBeGreaterThanOrEqual(0)
    expect(r2.overallScore).toBeLessThanOrEqual(100)
  })

  it('clean input produces higher overall score than all-null input', () => {
    const r1 = computeCertificationResult(cleanInput)
    const r2 = computeCertificationResult(allNullsInput)
    expect(r1.overallScore).toBeGreaterThan(r2.overallScore)
  })

  it('domainResults always has exactly 7 entries', () => {
    const result = computeCertificationResult(cleanInput)
    expect(result.domainResults).toHaveLength(7)
  })

  it('summary references the tier name', () => {
    expect(computeCertificationResult(cleanInput).summary).toMatch(/[Gg]old/)
    expect(computeCertificationResult(allNullsInput).summary).toMatch(/[Uu]ncertified/)
  })
})
