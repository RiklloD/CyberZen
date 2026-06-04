/// <reference types="vite/client" />
// WS-44 — Supply Chain Posture Score: unit tests.

import { describe, expect, test } from 'vitest'
import {
  ABANDONMENT_CAP,
  ABANDONMENT_CRITICAL_PENALTY,
  ABANDONMENT_HIGH_PENALTY,
  ATTESTATION_TAMPERED_PENALTY,
  ATTESTATION_UNVERIFIED_PENALTY,
  CONFUSION_CAP,
  CONFUSION_CRITICAL_PENALTY,
  CONFUSION_HIGH_PENALTY,
  CVE_CAP,
  CVE_CRITICAL_PENALTY,
  CVE_HIGH_PENALTY,
  CVE_MEDIUM_PENALTY,
  EOL_CAP,
  EOL_EOL_PENALTY,
  EOL_NEAR_EOL_PENALTY,
  MALICIOUS_CAP,
  MALICIOUS_CRITICAL_PENALTY,
  MALICIOUS_HIGH_PENALTY,
  computeSupplyChainPosture,
  scoreToGrade,
  scoreToRiskLevel,
} from './supplyChainPostureScorer'
import type { SupplyChainPostureInput } from './supplyChainPostureScorer'

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

function cleanInput(overrides: Partial<SupplyChainPostureInput> = {}): SupplyChainPostureInput {
  return {
    componentCount: 50,
    cve: { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'none' },
    malicious: { criticalCount: 0, highCount: 0, overallRisk: 'none' },
    confusion: { criticalCount: 0, highCount: 0, overallRisk: 'none' },
    abandonment: { criticalCount: 0, highCount: 0, overallRisk: 'none' },
    eol: { eolCount: 0, nearEolCount: 0, overallStatus: 'ok' },
    attestationStatus: 'valid',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// scoreToGrade
// ---------------------------------------------------------------------------

describe('scoreToGrade', () => {
  test('100 → A', () => expect(scoreToGrade(100)).toBe('A'))
  test('90 → A', () => expect(scoreToGrade(90)).toBe('A'))
  test('89 → B', () => expect(scoreToGrade(89)).toBe('B'))
  test('75 → B', () => expect(scoreToGrade(75)).toBe('B'))
  test('74 → C', () => expect(scoreToGrade(74)).toBe('C'))
  test('55 → C', () => expect(scoreToGrade(55)).toBe('C'))
  test('54 → D', () => expect(scoreToGrade(54)).toBe('D'))
  test('35 → D', () => expect(scoreToGrade(35)).toBe('D'))
  test('34 → F', () => expect(scoreToGrade(34)).toBe('F'))
  test('0 → F', () => expect(scoreToGrade(0)).toBe('F'))
})

// ---------------------------------------------------------------------------
// scoreToRiskLevel
// ---------------------------------------------------------------------------

describe('scoreToRiskLevel', () => {
  test('hasCritical forces critical regardless of score', () => {
    expect(scoreToRiskLevel(95, true, false)).toBe('critical')
  })

  test('score < 40 forces critical even without critical finding', () => {
    expect(scoreToRiskLevel(39, false, false)).toBe('critical')
  })

  test('hasHigh forces high when no critical present', () => {
    expect(scoreToRiskLevel(80, false, true)).toBe('high')
  })

  test('score < 60 forces high even without high finding', () => {
    expect(scoreToRiskLevel(59, false, false)).toBe('high')
  })

  test('score 60-74 with no flags → medium', () => {
    expect(scoreToRiskLevel(70, false, false)).toBe('medium')
  })

  test('score 75-89 with no flags → low', () => {
    expect(scoreToRiskLevel(82, false, false)).toBe('low')
  })

  test('score ≥ 90 with no flags → clean', () => {
    expect(scoreToRiskLevel(90, false, false)).toBe('clean')
    expect(scoreToRiskLevel(100, false, false)).toBe('clean')
  })
})

// ---------------------------------------------------------------------------
// computeSupplyChainPosture — clean baseline
// ---------------------------------------------------------------------------

describe('computeSupplyChainPosture — clean baseline', () => {
  test('score is 100 when all inputs are zero with valid attestation', () => {
    const result = computeSupplyChainPosture(cleanInput())
    expect(result.score).toBe(100)
  })

  test('grade is A for clean input', () => {
    expect(computeSupplyChainPosture(cleanInput()).grade).toBe('A')
  })

  test('riskLevel is clean for clean input', () => {
    expect(computeSupplyChainPosture(cleanInput()).riskLevel).toBe('clean')
  })

  test('breakdown is empty for clean input', () => {
    expect(computeSupplyChainPosture(cleanInput()).breakdown).toHaveLength(0)
  })

  test('summary mentions grade A and no risks for clean input', () => {
    const result = computeSupplyChainPosture(cleanInput())
    expect(result.summary).toMatch(/grade A/)
    expect(result.summary).toMatch(/No significant risks/)
  })
})

// ---------------------------------------------------------------------------
// CVE penalty
// ---------------------------------------------------------------------------

describe('CVE penalty', () => {
  test('applies critical CVE penalty correctly', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - CVE_CRITICAL_PENALTY)
  })

  test('applies high CVE penalty correctly', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, overallRisk: 'high' } }),
    )
    expect(result.score).toBe(100 - CVE_HIGH_PENALTY)
  })

  test('applies medium CVE penalty correctly', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 0, highCount: 0, mediumCount: 1, lowCount: 0, overallRisk: 'medium' } }),
    )
    expect(result.score).toBe(100 - CVE_MEDIUM_PENALTY)
  })

  test('CVE penalty is capped at CVE_CAP', () => {
    // 10 critical × 15 = 150 > cap of 50
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 10, highCount: 10, mediumCount: 10, lowCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - CVE_CAP)
  })

  test('CVE breakdown entry added when penalty is positive', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'critical' } }),
    )
    const entry = result.breakdown.find((b) => b.category === 'cve')
    expect(entry).toBeDefined()
    expect(entry!.penalty).toBe(CVE_CRITICAL_PENALTY)
  })
})

// ---------------------------------------------------------------------------
// Malicious package penalty
// ---------------------------------------------------------------------------

describe('malicious package penalty', () => {
  test('applies critical malicious penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ malicious: { criticalCount: 1, highCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - MALICIOUS_CRITICAL_PENALTY)
  })

  test('applies high malicious penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ malicious: { criticalCount: 0, highCount: 1, overallRisk: 'high' } }),
    )
    expect(result.score).toBe(100 - MALICIOUS_HIGH_PENALTY)
  })

  test('malicious penalty is capped at MALICIOUS_CAP', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ malicious: { criticalCount: 10, highCount: 10, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - MALICIOUS_CAP)
  })

  test('critical malicious escalates riskLevel to critical', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ malicious: { criticalCount: 1, highCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Dependency confusion penalty
// ---------------------------------------------------------------------------

describe('dependency confusion penalty', () => {
  test('applies critical confusion penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ confusion: { criticalCount: 1, highCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - CONFUSION_CRITICAL_PENALTY)
  })

  test('applies high confusion penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ confusion: { criticalCount: 0, highCount: 1, overallRisk: 'high' } }),
    )
    expect(result.score).toBe(100 - CONFUSION_HIGH_PENALTY)
  })

  test('confusion penalty is capped at CONFUSION_CAP', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ confusion: { criticalCount: 10, highCount: 10, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - CONFUSION_CAP)
  })
})

// ---------------------------------------------------------------------------
// Abandonment penalty
// ---------------------------------------------------------------------------

describe('abandonment penalty', () => {
  test('applies critical abandonment penalty (supply-chain-compromised)', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ abandonment: { criticalCount: 1, highCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - ABANDONMENT_CRITICAL_PENALTY)
  })

  test('applies high abandonment penalty (archived)', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ abandonment: { criticalCount: 0, highCount: 1, overallRisk: 'high' } }),
    )
    expect(result.score).toBe(100 - ABANDONMENT_HIGH_PENALTY)
  })

  test('abandonment penalty is capped at ABANDONMENT_CAP', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ abandonment: { criticalCount: 10, highCount: 10, overallRisk: 'critical' } }),
    )
    expect(result.score).toBe(100 - ABANDONMENT_CAP)
  })
})

// ---------------------------------------------------------------------------
// EOL penalty
// ---------------------------------------------------------------------------

describe('EOL penalty', () => {
  test('applies EOL component penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ eol: { eolCount: 1, nearEolCount: 0, overallStatus: 'critical' } }),
    )
    expect(result.score).toBe(100 - EOL_EOL_PENALTY)
  })

  test('applies near-EOL penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ eol: { eolCount: 0, nearEolCount: 1, overallStatus: 'warning' } }),
    )
    expect(result.score).toBe(100 - EOL_NEAR_EOL_PENALTY)
  })

  test('EOL penalty is capped at EOL_CAP', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ eol: { eolCount: 20, nearEolCount: 20, overallStatus: 'critical' } }),
    )
    expect(result.score).toBe(100 - EOL_CAP)
  })

  test('eolRisk pass-through from overallStatus', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ eol: { eolCount: 1, nearEolCount: 0, overallStatus: 'critical' } }),
    )
    expect(result.eolRisk).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Attestation penalty
// ---------------------------------------------------------------------------

describe('attestation penalty', () => {
  test('tampered attestation applies ATTESTATION_TAMPERED_PENALTY', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ attestationStatus: 'tampered' }),
    )
    expect(result.score).toBe(100 - ATTESTATION_TAMPERED_PENALTY)
  })

  test('unverified attestation applies ATTESTATION_UNVERIFIED_PENALTY', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ attestationStatus: 'unverified' }),
    )
    expect(result.score).toBe(100 - ATTESTATION_UNVERIFIED_PENALTY)
  })

  test('none attestation applies ATTESTATION_UNVERIFIED_PENALTY', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ attestationStatus: 'none' }),
    )
    expect(result.score).toBe(100 - ATTESTATION_UNVERIFIED_PENALTY)
  })

  test('valid attestation applies no penalty', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ attestationStatus: 'valid' }),
    )
    expect(result.score).toBe(100)
  })

  test('tampered attestation appears in breakdown', () => {
    const result = computeSupplyChainPosture(cleanInput({ attestationStatus: 'tampered' }))
    const entry = result.breakdown.find((b) => b.category === 'attestation')
    expect(entry).toBeDefined()
    expect(entry!.detail).toMatch(/tampering/)
  })

  test('unverified attestation detail mentions not yet verified', () => {
    const result = computeSupplyChainPosture(cleanInput({ attestationStatus: 'unverified' }))
    const entry = result.breakdown.find((b) => b.category === 'attestation')
    expect(entry!.detail).toMatch(/not yet verified/)
  })
})

// ---------------------------------------------------------------------------
// Score clamping and compound penalties
// ---------------------------------------------------------------------------

describe('score clamping and compound penalties', () => {
  test('score never goes below 0', () => {
    const result = computeSupplyChainPosture(
      cleanInput({
        cve: { criticalCount: 10, highCount: 10, mediumCount: 10, lowCount: 0, overallRisk: 'critical' },
        malicious: { criticalCount: 10, highCount: 10, overallRisk: 'critical' },
        confusion: { criticalCount: 10, highCount: 10, overallRisk: 'critical' },
        abandonment: { criticalCount: 10, highCount: 10, overallRisk: 'critical' },
        eol: { eolCount: 20, nearEolCount: 20, overallStatus: 'critical' },
        attestationStatus: 'tampered',
      }),
    )
    expect(result.score).toBe(0)
    expect(result.grade).toBe('F')
    expect(result.riskLevel).toBe('critical')
  })

  test('compound penalties from two categories accumulate', () => {
    // 1 critical CVE (–15) + 1 critical malicious (–25) = –40 → score 60
    const result = computeSupplyChainPosture(
      cleanInput({
        cve: { criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'critical' },
        malicious: { criticalCount: 1, highCount: 0, overallRisk: 'critical' },
      }),
    )
    expect(result.score).toBe(100 - CVE_CRITICAL_PENALTY - MALICIOUS_CRITICAL_PENALTY)
  })

  test('breakdown has one entry per affected category', () => {
    const result = computeSupplyChainPosture(
      cleanInput({
        cve: { criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'critical' },
        eol: { eolCount: 2, nearEolCount: 0, overallStatus: 'critical' },
      }),
    )
    expect(result.breakdown).toHaveLength(2)
    const categories = result.breakdown.map((b) => b.category)
    expect(categories).toContain('cve')
    expect(categories).toContain('eol')
  })

  test('breakdown is empty when all counts are zero', () => {
    const result = computeSupplyChainPosture(cleanInput())
    expect(result.breakdown).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  test('clean summary mentions grade A and no risks', () => {
    const result = computeSupplyChainPosture(cleanInput())
    expect(result.summary).toMatch(/grade A/)
    expect(result.summary).toMatch(/No significant risks/)
  })

  test('summary mentions score as X/100', () => {
    const result = computeSupplyChainPosture(cleanInput())
    expect(result.summary).toMatch(/100\/100/)
  })

  test('degraded summary mentions critical CVEs', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 2, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.summary).toMatch(/critical CVEs/)
  })

  test('degraded summary mentions confirmed malicious packages', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ malicious: { criticalCount: 1, highCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.summary).toMatch(/confirmed malicious package/)
  })

  test('degraded summary mentions EOL components', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ eol: { eolCount: 3, nearEolCount: 0, overallStatus: 'critical' } }),
    )
    expect(result.summary).toMatch(/EOL component/)
  })

  test('degraded summary mentions SBOM tampering', () => {
    const result = computeSupplyChainPosture(cleanInput({ attestationStatus: 'tampered' }))
    // tampered attestation alone doesn't push score below 80, grade is still B, summary won't be "clean"
    expect(result.summary).toMatch(/SBOM tampering/)
  })
})

// ---------------------------------------------------------------------------
// Pass-through risk fields
// ---------------------------------------------------------------------------

describe('pass-through risk fields', () => {
  test('cveRisk reflects input overallRisk', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ cve: { criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, overallRisk: 'critical' } }),
    )
    expect(result.cveRisk).toBe('critical')
  })

  test('maliciousRisk reflects input overallRisk', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ malicious: { criticalCount: 0, highCount: 1, overallRisk: 'high' } }),
    )
    expect(result.maliciousRisk).toBe('high')
  })

  test('confusionRisk reflects input overallRisk', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ confusion: { criticalCount: 0, highCount: 0, overallRisk: 'none' } }),
    )
    expect(result.confusionRisk).toBe('none')
  })

  test('abandonmentRisk reflects input overallRisk', () => {
    const result = computeSupplyChainPosture(
      cleanInput({ abandonment: { criticalCount: 0, highCount: 1, overallRisk: 'high' } }),
    )
    expect(result.abandonmentRisk).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Penalty constants integrity
// ---------------------------------------------------------------------------

describe('penalty constants integrity', () => {
  test('CVE_CAP >= individual CVE penalties', () => {
    expect(CVE_CAP).toBeGreaterThanOrEqual(CVE_CRITICAL_PENALTY)
    expect(CVE_CAP).toBeGreaterThanOrEqual(CVE_HIGH_PENALTY)
    expect(CVE_CAP).toBeGreaterThanOrEqual(CVE_MEDIUM_PENALTY)
  })

  test('MALICIOUS_CAP >= individual malicious penalties', () => {
    expect(MALICIOUS_CAP).toBeGreaterThanOrEqual(MALICIOUS_CRITICAL_PENALTY)
    expect(MALICIOUS_CAP).toBeGreaterThanOrEqual(MALICIOUS_HIGH_PENALTY)
  })

  test('CONFUSION_CAP >= individual confusion penalties', () => {
    expect(CONFUSION_CAP).toBeGreaterThanOrEqual(CONFUSION_CRITICAL_PENALTY)
    expect(CONFUSION_CAP).toBeGreaterThanOrEqual(CONFUSION_HIGH_PENALTY)
  })

  test('ABANDONMENT_CAP >= individual abandonment penalties', () => {
    expect(ABANDONMENT_CAP).toBeGreaterThanOrEqual(ABANDONMENT_CRITICAL_PENALTY)
    expect(ABANDONMENT_CAP).toBeGreaterThanOrEqual(ABANDONMENT_HIGH_PENALTY)
  })

  test('EOL_CAP >= individual EOL penalties', () => {
    expect(EOL_CAP).toBeGreaterThanOrEqual(EOL_EOL_PENALTY)
    expect(EOL_CAP).toBeGreaterThanOrEqual(EOL_NEAR_EOL_PENALTY)
  })

  test('ATTESTATION_TAMPERED_PENALTY > ATTESTATION_UNVERIFIED_PENALTY', () => {
    expect(ATTESTATION_TAMPERED_PENALTY).toBeGreaterThan(ATTESTATION_UNVERIFIED_PENALTY)
  })
})
