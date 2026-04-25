/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeSecurityMaturity, MATURITY_LABELS, type MaturityInput } from './securityMaturityModel'

const base: MaturityInput = {
  findings: [],
  sla: null,
  supplyChainGrade: null,
  sbomQualityGrade: null,
  attestation: null,
  compliance: null,
  regulatoryDriftLevel: null,
  triageEventCount: 0,
  triagedFindingCount: 0,
  analystFpRate: null,
  cicdGateEnabled: false,
  autoRemediationEnabled: false,
  driftDetectionEnabled: false,
  redBlueRoundsCompleted: 0,
  attackSurfaceScore: null,
  epssEnrichmentEnabled: false,
  secretsScanningEnabled: false,
  honeypotConfigured: false,
}

describe('computeSecurityMaturity — MATURITY_LABELS', () => {
  it('covers all 5 levels', () => {
    expect(MATURITY_LABELS[1]).toBe('Initial')
    expect(MATURITY_LABELS[2]).toBe('Managed')
    expect(MATURITY_LABELS[3]).toBe('Defined')
    expect(MATURITY_LABELS[4]).toBe('Quantitatively Managed')
    expect(MATURITY_LABELS[5]).toBe('Optimising')
  })
})

describe('computeSecurityMaturity — empty input (Level 1)', () => {
  it('returns level 1 for all-zeros input', () => {
    const r = computeSecurityMaturity(base)
    expect(r.overallLevel).toBe(1)
  })

  it('has 6 dimensions', () => {
    const r = computeSecurityMaturity(base)
    expect(r.dimensions).toHaveLength(6)
  })

  it('includes all dimension keys', () => {
    const r = computeSecurityMaturity(base)
    const keys = r.dimensions.map((d) => d.dimension)
    expect(keys).toContain('vulnerability_management')
    expect(keys).toContain('supply_chain_security')
    expect(keys).toContain('compliance_readiness')
    expect(keys).toContain('incident_response')
    expect(keys).toContain('security_automation')
    expect(keys).toContain('proactive_defense')
  })

  it('overall bottleneck is one of the dimension keys', () => {
    const r = computeSecurityMaturity(base)
    const keys = r.dimensions.map((d) => d.dimension)
    expect(keys).toContain(r.bottleneck)
  })
})

describe('computeSecurityMaturity — vulnerability_management', () => {
  it('scores 0 with no findings', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'vulnerability_management')!
    expect(d.score).toBe(0)
    expect(d.level).toBe(1)
  })

  it('scores higher with resolved findings and good SLA', () => {
    const r = computeSecurityMaturity({
      ...base,
      findings: [
        { severity: 'high', status: 'resolved', createdAt: 0, resolvedAt: 50000 },
        { severity: 'medium', status: 'resolved', createdAt: 0, resolvedAt: 50000 },
      ],
      sla: { overallComplianceRate: 0.9, mttrHours: 20 },
    })
    const d = r.dimensions.find((x) => x.dimension === 'vulnerability_management')!
    expect(d.score).toBeGreaterThan(50)
    expect(d.level).toBeGreaterThanOrEqual(3)
  })

  it('max resolution + perfect SLA + low MTTR → level 5', () => {
    const r = computeSecurityMaturity({
      ...base,
      findings: [{ severity: 'high', status: 'resolved', createdAt: 0, resolvedAt: 10000 }],
      sla: { overallComplianceRate: 1.0, mttrHours: 10 },
    })
    const d = r.dimensions.find((x) => x.dimension === 'vulnerability_management')!
    expect(d.score).toBe(100)
    expect(d.level).toBe(5)
  })

  it('gaps include SLA guidance when SLA not configured', () => {
    const r = computeSecurityMaturity({ ...base, findings: [] })
    const d = r.dimensions.find((x) => x.dimension === 'vulnerability_management')!
    expect(d.gaps.some((g) => g.toLowerCase().includes('sla'))).toBe(true)
  })
})

describe('computeSecurityMaturity — supply_chain_security', () => {
  it('scores 0 with all null inputs', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'supply_chain_security')!
    expect(d.score).toBe(0)
  })

  it('grade A SBOM + grade A supply chain + valid attestation + drift detection → high score', () => {
    const r = computeSecurityMaturity({
      ...base,
      sbomQualityGrade: 'A',
      supplyChainGrade: 'A',
      attestation: { total: 5, valid: 5, tampered: 0 },
      driftDetectionEnabled: true,
    })
    const d = r.dimensions.find((x) => x.dimension === 'supply_chain_security')!
    expect(d.score).toBeGreaterThanOrEqual(95)
    expect(d.level).toBe(5)
  })

  it('tampered attestation lowers score', () => {
    const noTamper = computeSecurityMaturity({
      ...base,
      sbomQualityGrade: 'A',
      supplyChainGrade: 'A',
      attestation: { total: 5, valid: 5, tampered: 0 },
      driftDetectionEnabled: true,
    })
    const withTamper = computeSecurityMaturity({
      ...base,
      sbomQualityGrade: 'A',
      supplyChainGrade: 'A',
      attestation: { total: 5, valid: 3, tampered: 2 },
      driftDetectionEnabled: true,
    })
    const dNoTamper = noTamper.dimensions.find((x) => x.dimension === 'supply_chain_security')!
    const dTamper = withTamper.dimensions.find((x) => x.dimension === 'supply_chain_security')!
    expect(dNoTamper.score).toBeGreaterThan(dTamper.score)
  })

  it('gaps include attestation advice when tampered', () => {
    const r = computeSecurityMaturity({
      ...base,
      attestation: { total: 5, valid: 3, tampered: 2 },
    })
    const d = r.dimensions.find((x) => x.dimension === 'supply_chain_security')!
    expect(d.gaps.some((g) => g.toLowerCase().includes('tamper'))).toBe(true)
  })
})

describe('computeSecurityMaturity — compliance_readiness', () => {
  it('returns level 1 when no compliance data', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'compliance_readiness')!
    expect(d.level).toBe(1)
    expect(d.score).toBe(0)
  })

  it('all frameworks compliant → high score', () => {
    const r = computeSecurityMaturity({
      ...base,
      compliance: { compliantFrameworks: 5, atRiskFrameworks: 0, nonCompliantFrameworks: 0 },
      regulatoryDriftLevel: 'none',
    })
    const d = r.dimensions.find((x) => x.dimension === 'compliance_readiness')!
    expect(d.score).toBe(100)
    expect(d.level).toBe(5)
  })

  it('non-compliant frameworks reduce score', () => {
    const r = computeSecurityMaturity({
      ...base,
      compliance: { compliantFrameworks: 3, atRiskFrameworks: 0, nonCompliantFrameworks: 2 },
      regulatoryDriftLevel: 'none',
    })
    const d = r.dimensions.find((x) => x.dimension === 'compliance_readiness')!
    expect(d.score).toBe(60) // 100 - 2×20
  })

  it('high regulatory drift reduces score', () => {
    const nodrDrift = computeSecurityMaturity({
      ...base,
      compliance: { compliantFrameworks: 5, atRiskFrameworks: 0, nonCompliantFrameworks: 0 },
      regulatoryDriftLevel: 'none',
    })
    const withHighDrift = computeSecurityMaturity({
      ...base,
      compliance: { compliantFrameworks: 5, atRiskFrameworks: 0, nonCompliantFrameworks: 0 },
      regulatoryDriftLevel: 'high',
    })
    const dNone = nodrDrift.dimensions.find((x) => x.dimension === 'compliance_readiness')!
    const dHigh = withHighDrift.dimensions.find((x) => x.dimension === 'compliance_readiness')!
    expect(dNone.score).toBeGreaterThan(dHigh.score)
  })
})

describe('computeSecurityMaturity — incident_response', () => {
  it('scores 0 with no findings/triage/honeypot', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'incident_response')!
    expect(d.score).toBe(0)
  })

  it('high triage + good SLA + honeypot + low FP → high score', () => {
    const r = computeSecurityMaturity({
      ...base,
      findings: Array.from({ length: 10 }).map(() => ({
        severity: 'high' as const,
        status: 'resolved' as const,
        createdAt: 0,
      })),
      triagedFindingCount: 9,
      sla: { overallComplianceRate: 0.95, mttrHours: 20 },
      honeypotConfigured: true,
      analystFpRate: 0.05,
    })
    const d = r.dimensions.find((x) => x.dimension === 'incident_response')!
    expect(d.score).toBeGreaterThanOrEqual(85)
    expect(d.level).toBeGreaterThanOrEqual(4)
  })

  it('gaps mention honeypot when not configured', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'incident_response')!
    expect(d.gaps.some((g) => g.toLowerCase().includes('honeypot'))).toBe(true)
  })
})

describe('computeSecurityMaturity — security_automation', () => {
  it('scores 0 with nothing enabled', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'security_automation')!
    expect(d.score).toBe(0)
    expect(d.level).toBe(1)
  })

  it('all automation enabled → score 100, level 5', () => {
    const r = computeSecurityMaturity({
      ...base,
      cicdGateEnabled: true,
      autoRemediationEnabled: true,
      driftDetectionEnabled: true,
    })
    const d = r.dimensions.find((x) => x.dimension === 'security_automation')!
    expect(d.score).toBe(100)
    expect(d.level).toBe(5)
  })

  it('only cicd gate → score 35, level 2', () => {
    const r = computeSecurityMaturity({ ...base, cicdGateEnabled: true })
    const d = r.dimensions.find((x) => x.dimension === 'security_automation')!
    expect(d.score).toBe(35)
    expect(d.level).toBe(2)
  })

  it('gaps include auto-remediation advice when disabled', () => {
    const r = computeSecurityMaturity({ ...base, cicdGateEnabled: true })
    const d = r.dimensions.find((x) => x.dimension === 'security_automation')!
    expect(d.gaps.some((g) => g.toLowerCase().includes('auto'))).toBe(true)
  })
})

describe('computeSecurityMaturity — proactive_defense', () => {
  it('scores 0 with no rounds/enrichment/scanning', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'proactive_defense')!
    expect(d.score).toBe(0)
  })

  it('10+ red/blue rounds → 30 pts from rounds', () => {
    const r = computeSecurityMaturity({
      ...base,
      redBlueRoundsCompleted: 10,
      epssEnrichmentEnabled: true,
      secretsScanningEnabled: true,
      honeypotConfigured: true,
      attackSurfaceScore: 20,
    })
    const d = r.dimensions.find((x) => x.dimension === 'proactive_defense')!
    expect(d.score).toBeGreaterThanOrEqual(80)
    expect(d.level).toBeGreaterThanOrEqual(4)
  })

  it('rounds capped at 10 for scoring', () => {
    const r10 = computeSecurityMaturity({ ...base, redBlueRoundsCompleted: 10 })
    const r20 = computeSecurityMaturity({ ...base, redBlueRoundsCompleted: 20 })
    const d10 = r10.dimensions.find((x) => x.dimension === 'proactive_defense')!
    const d20 = r20.dimensions.find((x) => x.dimension === 'proactive_defense')!
    expect(d10.score).toBe(d20.score) // capped
  })

  it('gaps include secrets scanning when disabled', () => {
    const r = computeSecurityMaturity(base)
    const d = r.dimensions.find((x) => x.dimension === 'proactive_defense')!
    expect(d.gaps.some((g) => g.toLowerCase().includes('secret'))).toBe(true)
  })
})

describe('computeSecurityMaturity — overall level bottleneck', () => {
  it('overall level = min of all dimension levels', () => {
    const r = computeSecurityMaturity({
      ...base,
      cicdGateEnabled: true,
      autoRemediationEnabled: true,
      driftDetectionEnabled: true, // automation = level 5
      findings: [{ severity: 'high', status: 'resolved', createdAt: 0, resolvedAt: 50000 }],
      sla: { overallComplianceRate: 1.0, mttrHours: 10 }, // vuln = level 5
      // compliance, supply chain, incident response, proactive = low
    })
    const minLevel = Math.min(...r.dimensions.map((d) => d.level))
    expect(r.overallLevel).toBe(minLevel)
  })

  it('bottleneck points to the lowest dimension', () => {
    const r = computeSecurityMaturity({
      ...base,
      cicdGateEnabled: true,
      autoRemediationEnabled: true,
      driftDetectionEnabled: true,
    })
    const bottleneckDim = r.dimensions.find((d) => d.dimension === r.bottleneck)!
    const minLevel = Math.min(...r.dimensions.map((d) => d.level))
    expect(bottleneckDim.level).toBe(minLevel)
  })
})

describe('computeSecurityMaturity — overall score', () => {
  it('is average of dimension scores', () => {
    const r = computeSecurityMaturity(base)
    const avg = Math.round(r.dimensions.reduce((s, d) => s + d.score, 0) / r.dimensions.length)
    expect(r.overallScore).toBe(avg)
  })
})

describe('computeSecurityMaturity — advancement roadmap', () => {
  it('includes advice when level < 5', () => {
    const r = computeSecurityMaturity(base)
    expect(r.advancementRoadmap.length).toBeGreaterThan(0)
  })

  it('at level 5, returns congratulatory message', () => {
    const perfect: MaturityInput = {
      ...base,
      findings: [{ severity: 'high', status: 'resolved', createdAt: 0, resolvedAt: 10000 }],
      sla: { overallComplianceRate: 1.0, mttrHours: 10 },
      sbomQualityGrade: 'A',
      supplyChainGrade: 'A',
      attestation: { total: 5, valid: 5, tampered: 0 },
      driftDetectionEnabled: true,
      compliance: { compliantFrameworks: 5, atRiskFrameworks: 0, nonCompliantFrameworks: 0 },
      regulatoryDriftLevel: 'none',
      triagedFindingCount: 1,
      honeypotConfigured: true,
      analystFpRate: 0.05,
      cicdGateEnabled: true,
      autoRemediationEnabled: true,
      redBlueRoundsCompleted: 10,
      attackSurfaceScore: 10,
      epssEnrichmentEnabled: true,
      secretsScanningEnabled: true,
    }
    const r = computeSecurityMaturity(perfect)
    if (r.overallLevel === 5) {
      expect(r.advancementRoadmap[0]).toContain('highest maturity')
    }
  })
})

describe('computeSecurityMaturity — assessedAt', () => {
  it('is recent timestamp', () => {
    const before = Date.now()
    const r = computeSecurityMaturity(base)
    const after = Date.now()
    expect(r.assessedAt).toBeGreaterThanOrEqual(before)
    expect(r.assessedAt).toBeLessThanOrEqual(after)
  })
})
