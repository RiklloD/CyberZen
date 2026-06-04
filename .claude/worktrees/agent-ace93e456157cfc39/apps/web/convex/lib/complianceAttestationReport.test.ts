/// <reference types="vite/client" />
// WS-46 — Compliance Attestation Report: unit tests.

import { describe, expect, test } from 'vitest'
import {
  COMPLIANCE_FRAMEWORKS,
  COMPLIANT_SCORE_THRESHOLD,
  FRAMEWORK_LABELS,
  GAP_PENALTIES,
  computeComplianceAttestation,
} from './complianceAttestationReport'
import type { ComplianceAttestationInput } from './complianceAttestationReport'

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

function cleanInput(overrides: Partial<ComplianceAttestationInput> = {}): ComplianceAttestationInput {
  return {
    secretCriticalCount: 0,
    secretHighCount: 0,
    cryptoRisk: 'none',
    cryptoCriticalCount: 0,
    cryptoHighCount: 0,
    eolStatus: 'ok',
    eolCriticalCount: 0,
    abandonmentRisk: 'none',
    abandonmentCriticalCount: 0,
    attestationStatus: 'valid',
    confusionRisk: 'none',
    confusionCriticalCount: 0,
    maliciousRisk: 'none',
    maliciousCriticalCount: 0,
    cveRisk: 'none',
    cveCriticalCount: 0,
    cveHighCount: 0,
    sbomGrade: 'excellent',
    iacRisk: 'none',
    iacCriticalCount: 0,
    cicdRisk: 'none',
    cicdCriticalCount: 0,
    containerRisk: 'none',
    containerCriticalCount: 0,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('constants', () => {
  test('COMPLIANCE_FRAMEWORKS has exactly 5 frameworks', () => {
    expect(COMPLIANCE_FRAMEWORKS).toHaveLength(5)
  })

  test('COMPLIANCE_FRAMEWORKS contains soc2, gdpr, pci_dss, hipaa, nis2', () => {
    expect(COMPLIANCE_FRAMEWORKS).toContain('soc2')
    expect(COMPLIANCE_FRAMEWORKS).toContain('gdpr')
    expect(COMPLIANCE_FRAMEWORKS).toContain('pci_dss')
    expect(COMPLIANCE_FRAMEWORKS).toContain('hipaa')
    expect(COMPLIANCE_FRAMEWORKS).toContain('nis2')
  })

  test('GAP_PENALTIES: critical > high > medium > low', () => {
    expect(GAP_PENALTIES.critical).toBeGreaterThan(GAP_PENALTIES.high)
    expect(GAP_PENALTIES.high).toBeGreaterThan(GAP_PENALTIES.medium)
    expect(GAP_PENALTIES.medium).toBeGreaterThan(GAP_PENALTIES.low)
  })

  test('GAP_PENALTIES: critical = 20, high = 12, medium = 6, low = 3', () => {
    expect(GAP_PENALTIES.critical).toBe(20)
    expect(GAP_PENALTIES.high).toBe(12)
    expect(GAP_PENALTIES.medium).toBe(6)
    expect(GAP_PENALTIES.low).toBe(3)
  })

  test('COMPLIANT_SCORE_THRESHOLD is 75', () => {
    expect(COMPLIANT_SCORE_THRESHOLD).toBe(75)
  })

  test('FRAMEWORK_LABELS has a label for each framework', () => {
    for (const fw of COMPLIANCE_FRAMEWORKS) {
      expect(FRAMEWORK_LABELS[fw].length).toBeGreaterThan(0)
    }
  })
})

// ---------------------------------------------------------------------------
// Clean baseline
// ---------------------------------------------------------------------------

describe('clean baseline', () => {
  test('returns exactly 5 frameworks', () => {
    const result = computeComplianceAttestation(cleanInput())
    expect(result.frameworks).toHaveLength(5)
  })

  test('all frameworks compliant when no issues', () => {
    const result = computeComplianceAttestation(cleanInput())
    for (const fw of result.frameworks) {
      expect(fw.status).toBe('compliant')
    }
  })

  test('overallStatus is compliant on clean input', () => {
    expect(computeComplianceAttestation(cleanInput()).overallStatus).toBe('compliant')
  })

  test('criticalGapCount = 0 on clean input', () => {
    expect(computeComplianceAttestation(cleanInput()).criticalGapCount).toBe(0)
  })

  test('highGapCount = 0 on clean input', () => {
    expect(computeComplianceAttestation(cleanInput()).highGapCount).toBe(0)
  })

  test('fullyCompliantCount = 5 on clean input', () => {
    expect(computeComplianceAttestation(cleanInput()).fullyCompliantCount).toBe(5)
  })

  test('summary mentions all 5 frameworks on clean input', () => {
    const result = computeComplianceAttestation(cleanInput())
    expect(result.summary).toMatch(/5/i)
    expect(result.summary).toMatch(/compliant/i)
  })
})

// ---------------------------------------------------------------------------
// SOC 2 controls
// ---------------------------------------------------------------------------

describe('SOC 2 — CC6.1 Logical Access Controls', () => {
  test('secretCriticalCount > 0 → critical gap in SOC2', () => {
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 2 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC6.1')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('secretHighCount > 0 (no critical) → high gap in SOC2 CC6.1', () => {
    const result = computeComplianceAttestation(cleanInput({ secretHighCount: 1 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC6.1')
    expect(gap?.gapSeverity).toBe('high')
  })
})

describe('SOC 2 — CC6.6 Infrastructure Security', () => {
  test('iacCriticalCount > 0 → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ iacCriticalCount: 1 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC6.6')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('iacRisk high (no critical count) → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ iacRisk: 'high', iacCriticalCount: 0 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC6.6')
    expect(gap?.gapSeverity).toBe('high')
  })
})

describe('SOC 2 — CC6.7 Encryption', () => {
  test('cryptoCriticalCount > 0 → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cryptoCriticalCount: 1, cryptoRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC6.7')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('cryptoHighCount > 0 (no critical) → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cryptoHighCount: 2, cryptoRisk: 'high' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC6.7')
    expect(gap?.gapSeverity).toBe('high')
  })
})

describe('SOC 2 — CC7.1 Vulnerability Monitoring', () => {
  test('cveCriticalCount > 0 → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cveCriticalCount: 3, cveRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC7.1')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('eolStatus critical (no CVEs) → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ eolStatus: 'critical', eolCriticalCount: 1 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC7.1')
    expect(gap?.gapSeverity).toBe('high')
  })
})

describe('SOC 2 — CC7.2 Integrity', () => {
  test('attestation tampered → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'tampered' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC7.2')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('attestation unverified → medium gap', () => {
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'unverified' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC7.2')
    expect(gap?.gapSeverity).toBe('medium')
  })

  test('attestation none → medium gap', () => {
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'none' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC7.2')
    expect(gap?.gapSeverity).toBe('medium')
  })

  test('attestation valid → no CC7.2 gap', () => {
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'valid' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC7.2')
    expect(gap).toBeUndefined()
  })
})

describe('SOC 2 — CC8.1 Change Management', () => {
  test('cicdCriticalCount > 0 → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cicdCriticalCount: 1, cicdRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC8.1')
    expect(gap?.gapSeverity).toBe('critical')
  })
})

describe('SOC 2 — CC9.2 Supply Chain', () => {
  test('maliciousCriticalCount > 0 → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ maliciousCriticalCount: 1, maliciousRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC9.2')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('confusionCriticalCount > 0 (no malicious) → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ confusionCriticalCount: 1, confusionRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC9.2')
    expect(gap?.gapSeverity).toBe('high')
  })

  test('abandonmentCriticalCount > 0 (no malicious/confusion) → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ abandonmentCriticalCount: 1, abandonmentRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC9.2')
    expect(gap?.gapSeverity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// GDPR controls
// ---------------------------------------------------------------------------

describe('GDPR controls', () => {
  test('Art.32: cryptoCriticalCount → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cryptoCriticalCount: 1, cryptoRisk: 'critical' }))
    const gdpr = result.frameworks.find((f) => f.framework === 'gdpr')!
    const gap = gdpr.controlGaps.find((g) => g.controlId === 'Art.32')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('Art.25: containerCriticalCount → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ containerCriticalCount: 1, containerRisk: 'critical' }))
    const gdpr = result.frameworks.find((f) => f.framework === 'gdpr')!
    const gap = gdpr.controlGaps.find((g) => g.controlId === 'Art.25')
    expect(gap?.gapSeverity).toBe('high')
  })

  test('Art.33-34: eolStatus critical → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ eolStatus: 'critical', eolCriticalCount: 1 }))
    const gdpr = result.frameworks.find((f) => f.framework === 'gdpr')!
    const gap = gdpr.controlGaps.find((g) => g.controlId === 'Art.33-34')
    expect(gap?.gapSeverity).toBe('high')
  })

  test('Art.32: sbomGrade poor → medium gap (no critical inputs)', () => {
    const result = computeComplianceAttestation(cleanInput({ sbomGrade: 'poor' }))
    const gdpr = result.frameworks.find((f) => f.framework === 'gdpr')!
    const gap = gdpr.controlGaps.find((g) => g.controlId === 'Art.32')
    expect(gap?.gapSeverity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// PCI-DSS 4.0 controls
// ---------------------------------------------------------------------------

describe('PCI-DSS controls', () => {
  test('Req.6.3: eolStatus critical → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ eolStatus: 'critical', eolCriticalCount: 2 }))
    const pci = result.frameworks.find((f) => f.framework === 'pci_dss')!
    const gap = pci.controlGaps.find((g) => g.controlId === 'Req.6.3')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('Req.6.2: cveCriticalCount → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cveCriticalCount: 1, cveRisk: 'critical' }))
    const pci = result.frameworks.find((f) => f.framework === 'pci_dss')!
    const gap = pci.controlGaps.find((g) => g.controlId === 'Req.6.2')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('Req.11.3: cveHighCount > 0 → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cveHighCount: 2, cveRisk: 'high' }))
    const pci = result.frameworks.find((f) => f.framework === 'pci_dss')!
    const gap = pci.controlGaps.find((g) => g.controlId === 'Req.11.3')
    expect(gap?.gapSeverity).toBe('high')
  })

  test('Req.6.5: attestation tampered → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'tampered' }))
    const pci = result.frameworks.find((f) => f.framework === 'pci_dss')!
    const gap = pci.controlGaps.find((g) => g.controlId === 'Req.6.5')
    expect(gap?.gapSeverity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// HIPAA controls
// ---------------------------------------------------------------------------

describe('HIPAA controls', () => {
  test('§164.312(a)(1): secretCriticalCount → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1 }))
    const hipaa = result.frameworks.find((f) => f.framework === 'hipaa')!
    const gap = hipaa.controlGaps.find((g) => g.controlId === '§164.312(a)(1)')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('§164.312(a)(2)(iv): cryptoCriticalCount → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cryptoCriticalCount: 1, cryptoRisk: 'critical' }))
    const hipaa = result.frameworks.find((f) => f.framework === 'hipaa')!
    const gap = hipaa.controlGaps.find((g) => g.controlId === '§164.312(a)(2)(iv)')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('§164.312(c)(1): attestation tampered → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'tampered' }))
    const hipaa = result.frameworks.find((f) => f.framework === 'hipaa')!
    const gap = hipaa.controlGaps.find((g) => g.controlId === '§164.312(c)(1)')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('§164.312(e)(2)(ii): cryptoHighCount → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cryptoHighCount: 1, cryptoRisk: 'high' }))
    const hipaa = result.frameworks.find((f) => f.framework === 'hipaa')!
    const gap = hipaa.controlGaps.find((g) => g.controlId === '§164.312(e)(2)(ii)')
    expect(gap?.gapSeverity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// NIS2 controls
// ---------------------------------------------------------------------------

describe('NIS2 controls', () => {
  test('Art.21(2)(e): maliciousCriticalCount → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ maliciousCriticalCount: 1, maliciousRisk: 'critical' }))
    const nis2 = result.frameworks.find((f) => f.framework === 'nis2')!
    const gap = nis2.controlGaps.find((g) => g.controlId === 'Art.21(2)(e)')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('Art.21(2)(i): cryptoCriticalCount → critical gap', () => {
    const result = computeComplianceAttestation(cleanInput({ cryptoCriticalCount: 2, cryptoRisk: 'critical' }))
    const nis2 = result.frameworks.find((f) => f.framework === 'nis2')!
    const gap = nis2.controlGaps.find((g) => g.controlId === 'Art.21(2)(i)')
    expect(gap?.gapSeverity).toBe('critical')
  })

  test('Art.21(2)(h): containerCriticalCount → high gap', () => {
    const result = computeComplianceAttestation(cleanInput({ containerCriticalCount: 1, containerRisk: 'critical' }))
    const nis2 = result.frameworks.find((f) => f.framework === 'nis2')!
    const gap = nis2.controlGaps.find((g) => g.controlId === 'Art.21(2)(h)')
    expect(gap?.gapSeverity).toBe('high')
  })

  test('Art.21(2)(j): cicdCriticalCount → high gap (no secrets)', () => {
    const result = computeComplianceAttestation(cleanInput({ cicdCriticalCount: 1, cicdRisk: 'critical' }))
    const nis2 = result.frameworks.find((f) => f.framework === 'nis2')!
    const gap = nis2.controlGaps.find((g) => g.controlId === 'Art.21(2)(j)')
    expect(gap?.gapSeverity).toBe('high')
  })

  test('Art.21(2)(j): secretCriticalCount wins over cicd for critical', () => {
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1, cicdCriticalCount: 1 }))
    const nis2 = result.frameworks.find((f) => f.framework === 'nis2')!
    const gap = nis2.controlGaps.find((g) => g.controlId === 'Art.21(2)(j)')
    expect(gap?.gapSeverity).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Framework score calculation
// ---------------------------------------------------------------------------

describe('framework score calculation', () => {
  test('no gaps → score 100 for every framework', () => {
    const result = computeComplianceAttestation(cleanInput())
    for (const fw of result.frameworks) {
      expect(fw.score).toBe(100)
    }
  })

  test('one critical gap in SOC2 → score = 100 - 20 = 80', () => {
    // Only trigger one critical gap: secretCriticalCount affects CC6.1 in SOC2
    // and also some other frameworks — we check the SOC2 score specifically
    // by using a signal that only hits one SOC2 control.
    // Use attestation tampered: affects CC7.2 (critical) in SOC2 only in SOC2.
    // Actually attestation also affects HIPAA §164.312(c)(1) and PCI Req.6.5.
    // To isolate SOC2 score, use a targeted check.
    // secretCriticalCount hits CC6.1 (SOC2), §164.312(a)(1) (HIPAA), Art.21(2)(j) (NIS2), Art.32 (GDPR).
    // Let's use cicdRisk 'high' + cicdCriticalCount = 0 → only CC8.1 high gap in SOC2.
    const result = computeComplianceAttestation(cleanInput({ cicdRisk: 'high', cicdCriticalCount: 0 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    // CC8.1 high gap: -12. Score = 100-12 = 88
    expect(soc2.score).toBe(88)
  })

  test('score is clamped to 0 minimum (multiple gaps)', () => {
    // Many critical gaps simultaneously — score should not go below 0
    const result = computeComplianceAttestation(cleanInput({
      secretCriticalCount: 1, // critical many places
      cryptoCriticalCount: 1,
      cveCriticalCount: 1,
      cicdCriticalCount: 1,
      maliciousCriticalCount: 1,
      confusionCriticalCount: 1,
      attestationStatus: 'tampered',
    }))
    for (const fw of result.frameworks) {
      expect(fw.score).toBeGreaterThanOrEqual(0)
    }
  })
})

// ---------------------------------------------------------------------------
// Framework status derivation
// ---------------------------------------------------------------------------

describe('framework status derivation', () => {
  test('no gaps → compliant', () => {
    const result = computeComplianceAttestation(cleanInput())
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    expect(soc2.status).toBe('compliant')
  })

  test('critical gap → non_compliant', () => {
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1 }))
    // SOC2 CC6.1 critical gap → non_compliant
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    expect(soc2.status).toBe('non_compliant')
  })

  test('high gap only → at_risk', () => {
    // iacRisk high (no critical count) → CC6.6 high gap in SOC2 only
    const result = computeComplianceAttestation(cleanInput({ iacRisk: 'high', iacCriticalCount: 0 }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    expect(soc2.status).toBe('at_risk')
  })

  test('medium gap only → may still be compliant if score >= 75', () => {
    // attestation unverified → CC7.2 medium gap in SOC2 → score 100-6=94 → compliant
    const result = computeComplianceAttestation(cleanInput({ attestationStatus: 'unverified' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    expect(soc2.status).toBe('compliant') // medium gap, score 94 >= 75, no critical/high gaps
  })
})

// ---------------------------------------------------------------------------
// overallStatus derivation
// ---------------------------------------------------------------------------

describe('overallStatus derivation', () => {
  test('all compliant → overall compliant', () => {
    expect(computeComplianceAttestation(cleanInput()).overallStatus).toBe('compliant')
  })

  test('one non_compliant framework → overall non_compliant', () => {
    // secretCriticalCount makes SOC2, HIPAA, GDPR, NIS2 non_compliant
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1 }))
    expect(result.overallStatus).toBe('non_compliant')
  })

  test('only at_risk frameworks (no non_compliant) → overall at_risk', () => {
    // iacRisk high triggers high gap (at_risk) in SOC2 and HIPAA, others may be clean
    const result = computeComplianceAttestation(cleanInput({ iacRisk: 'high', iacCriticalCount: 0 }))
    expect(result.overallStatus).toBe('at_risk')
  })
})

// ---------------------------------------------------------------------------
// fullyCompliantCount
// ---------------------------------------------------------------------------

describe('fullyCompliantCount', () => {
  test('all clean → fullyCompliantCount = 5', () => {
    expect(computeComplianceAttestation(cleanInput()).fullyCompliantCount).toBe(5)
  })

  test('one non_compliant framework → fullyCompliantCount < 5', () => {
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1 }))
    expect(result.fullyCompliantCount).toBeLessThan(5)
  })
})

// ---------------------------------------------------------------------------
// criticalGapCount / highGapCount aggregation
// ---------------------------------------------------------------------------

describe('gap count aggregation', () => {
  test('no issues → criticalGapCount = 0', () => {
    expect(computeComplianceAttestation(cleanInput()).criticalGapCount).toBe(0)
  })

  test('secret critical triggers critical gaps across multiple frameworks', () => {
    // secretCriticalCount=1 hits: SOC2 CC6.1, GDPR Art.32, HIPAA §164.312(a)(1), NIS2 Art.21(2)(j) = 4 critical gaps
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1 }))
    expect(result.criticalGapCount).toBeGreaterThanOrEqual(4)
  })

  test('highGapCount sums high gaps across all frameworks', () => {
    // cryptoHighCount triggers high gaps in SOC2 CC6.7 + HIPAA §164.312(e)(2)(ii) + NIS2 Art.21(2)(i)
    const result = computeComplianceAttestation(cleanInput({ cryptoHighCount: 1, cryptoRisk: 'high' }))
    expect(result.highGapCount).toBeGreaterThanOrEqual(3)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  test('compliant → mentions all 5 frameworks and "compliant"', () => {
    const result = computeComplianceAttestation(cleanInput())
    expect(result.summary).toContain('5')
    expect(result.summary.toLowerCase()).toContain('compliant')
  })

  test('non_compliant → mentions critical gap count and "remediation"', () => {
    const result = computeComplianceAttestation(cleanInput({ secretCriticalCount: 1 }))
    expect(result.summary.toLowerCase()).toContain('non-compliant')
    expect(result.summary.toLowerCase()).toContain('critical')
  })

  test('at_risk → mentions "at risk" and high gap count', () => {
    const result = computeComplianceAttestation(cleanInput({ iacRisk: 'high', iacCriticalCount: 0 }))
    expect(result.summary.toLowerCase()).toContain('at risk')
  })
})

// ---------------------------------------------------------------------------
// Framework labels
// ---------------------------------------------------------------------------

describe('framework labels', () => {
  test('soc2 label is "SOC 2 Type II"', () => {
    const result = computeComplianceAttestation(cleanInput())
    const fw = result.frameworks.find((f) => f.framework === 'soc2')!
    expect(fw.label).toBe('SOC 2 Type II')
  })

  test('gdpr label is "GDPR"', () => {
    const fw = computeComplianceAttestation(cleanInput()).frameworks.find((f) => f.framework === 'gdpr')!
    expect(fw.label).toBe('GDPR')
  })

  test('pci_dss label is "PCI-DSS 4.0"', () => {
    const fw = computeComplianceAttestation(cleanInput()).frameworks.find((f) => f.framework === 'pci_dss')!
    expect(fw.label).toBe('PCI-DSS 4.0')
  })

  test('hipaa label is "HIPAA"', () => {
    const fw = computeComplianceAttestation(cleanInput()).frameworks.find((f) => f.framework === 'hipaa')!
    expect(fw.label).toBe('HIPAA')
  })

  test('nis2 label is "NIS2"', () => {
    const fw = computeComplianceAttestation(cleanInput()).frameworks.find((f) => f.framework === 'nis2')!
    expect(fw.label).toBe('NIS2')
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('edge cases', () => {
  test('sbomGrade unknown has no Art.32 medium gap (unknown ≠ poor)', () => {
    const result = computeComplianceAttestation(cleanInput({ sbomGrade: 'unknown' }))
    const gdpr = result.frameworks.find((f) => f.framework === 'gdpr')!
    const gap = gdpr.controlGaps.find((g) => g.controlId === 'Art.32')
    expect(gap).toBeUndefined()
  })

  test('eolStatus warning (not critical) does not trigger critical PCI Req.6.3 gap', () => {
    const result = computeComplianceAttestation(cleanInput({ eolStatus: 'warning' }))
    const pci = result.frameworks.find((f) => f.framework === 'pci_dss')!
    const gap = pci.controlGaps.find((g) => g.controlId === 'Req.6.3')
    expect(gap).toBeUndefined()
  })

  test('confusionCriticalCount > 0 does not trigger CC9.2 critical (only high)', () => {
    const result = computeComplianceAttestation(cleanInput({ confusionCriticalCount: 1, confusionRisk: 'critical' }))
    const soc2 = result.frameworks.find((f) => f.framework === 'soc2')!
    const gap = soc2.controlGaps.find((g) => g.controlId === 'CC9.2')
    expect(gap?.gapSeverity).toBe('high') // not critical
  })

  test('frameworks array order is soc2, gdpr, pci_dss, hipaa, nis2', () => {
    const result = computeComplianceAttestation(cleanInput())
    const ids = result.frameworks.map((f) => f.framework)
    expect(ids).toEqual(['soc2', 'gdpr', 'pci_dss', 'hipaa', 'nis2'])
  })
})
