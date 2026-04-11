/// <reference types="vite/client" />
import { describe, it, expect } from 'vitest'
import {
  computeRegulatoryDrift,
  FRAMEWORK_LABELS,
  type FindingForDriftInput,
  type RegulatoryDriftInput,
} from './regulatoryDrift'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_INPUT: RegulatoryDriftInput = {
  findings: [],
  repositoryName: 'acme/api',
}

function finding(
  overrides: Partial<FindingForDriftInput> = {},
): FindingForDriftInput {
  return {
    vulnClass: 'injection',
    severity: 'high',
    status: 'open',
    validationStatus: 'pending',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Empty / clean state
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — no findings', () => {
  it('returns score=100 for every framework when there are no findings', () => {
    const result = computeRegulatoryDrift(BASE_INPUT)
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(100)
    }
  })

  it('returns compliant drift level when there are no findings', () => {
    expect(computeRegulatoryDrift(BASE_INPUT).overallDriftLevel).toBe('compliant')
  })

  it('returns zero openGapCount when there are no findings', () => {
    expect(computeRegulatoryDrift(BASE_INPUT).openGapCount).toBe(0)
  })

  it('returns empty affectedFrameworks when there are no findings', () => {
    expect(computeRegulatoryDrift(BASE_INPUT).affectedFrameworks).toHaveLength(0)
  })

  it('summary mentions repository name', () => {
    const result = computeRegulatoryDrift(BASE_INPUT)
    expect(result.summary).toContain('acme/api')
  })
})

// ---------------------------------------------------------------------------
// Resolved / inactive findings do not contribute
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — resolved findings', () => {
  it('resolved findings do not affect scores', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ status: 'resolved' })],
    })
    expect(result.openGapCount).toBe(0)
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(100)
    }
  })

  it('merged findings do not affect scores', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ status: 'merged' })],
    })
    expect(result.openGapCount).toBe(0)
  })

  it('accepted_risk findings do not affect scores', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ status: 'accepted_risk' })],
    })
    expect(result.openGapCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Severity penalties
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — severity penalties', () => {
  it('critical open injection finding lowers all framework scores by 20', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'critical', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(80)
    }
  })

  it('high open finding lowers affected framework scores by 12', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'high', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(88)
    }
  })

  it('medium open finding lowers affected framework scores by 6', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'medium', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(94)
    }
  })

  it('low open finding lowers affected framework scores by 2', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'low', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(98)
    }
  })

  it('informational finding contributes zero penalty', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'informational', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(100)
    }
  })
})

// ---------------------------------------------------------------------------
// Validation multipliers
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — validation multipliers', () => {
  it('validated finding applies 1.5× multiplier (critical=30 penalty → score 70)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'critical', validationStatus: 'validated' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(70)
    }
  })

  it('likely_exploitable finding applies 1.2× multiplier (critical=24 penalty → score 76)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'critical', validationStatus: 'likely_exploitable' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(76)
    }
  })

  it('pending validation applies 1× multiplier (no amplification)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'critical', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(80)
    }
  })
})

// ---------------------------------------------------------------------------
// pr_opened half-penalty
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — pr_opened status', () => {
  it('pr_opened finding applies 0.5× status multiplier (critical unvalidated = 10 penalty → score 90)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'critical', status: 'pr_opened', validationStatus: 'pending' })],
    })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBe(90)
    }
  })

  it('pr_opened finding still counts toward openGapCount', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ status: 'pr_opened' })],
    })
    expect(result.openGapCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Score floor
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — score floor', () => {
  it('score is floored at 0 even with many critical findings', () => {
    const manyFindings = Array.from({ length: 10 }, () =>
      finding({ severity: 'critical', validationStatus: 'validated' }),
    )
    const result = computeRegulatoryDrift({ ...BASE_INPUT, findings: manyFindings })
    for (const fs of result.frameworkScores) {
      expect(fs.score).toBeGreaterThanOrEqual(0)
    }
  })
})

// ---------------------------------------------------------------------------
// Framework-specific mapping
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — framework mapping', () => {
  it('xss finding does NOT affect hipaa score', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'xss' })],
    })
    const hipaa = result.frameworkScores.find((f) => f.framework === 'hipaa')!
    expect(hipaa.score).toBe(100)
    expect(hipaa.openGaps).toBe(0)
  })

  it('xss finding DOES affect soc2, gdpr, pci_dss, nis2 scores', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'xss', severity: 'high', validationStatus: 'pending' })],
    })
    const affected = result.frameworkScores.filter(
      (f) => ['soc2', 'gdpr', 'pci_dss', 'nis2'].includes(f.framework),
    )
    for (const fs of affected) {
      expect(fs.score).toBe(88)
    }
  })

  it('insecure_configuration finding affects only soc2, pci_dss, nis2', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'insecure_configuration', severity: 'high' })],
    })
    const notAffected = result.frameworkScores.filter(
      (f) => ['gdpr', 'hipaa'].includes(f.framework),
    )
    for (const fs of notAffected) {
      expect(fs.score).toBe(100)
    }
    const affected = result.frameworkScores.filter(
      (f) => ['soc2', 'pci_dss', 'nis2'].includes(f.framework),
    )
    for (const fs of affected) {
      expect(fs.score).toBeLessThan(100)
    }
  })

  it('unknown vuln class falls back to soc2, gdpr, nis2', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'totally_unknown_class', severity: 'high' })],
    })
    const notAffected = result.frameworkScores.filter(
      (f) => ['hipaa', 'pci_dss'].includes(f.framework),
    )
    for (const fs of notAffected) {
      expect(fs.score).toBe(100)
    }
    const affected = result.frameworkScores.filter(
      (f) => ['soc2', 'gdpr', 'nis2'].includes(f.framework),
    )
    for (const fs of affected) {
      expect(fs.score).toBeLessThan(100)
    }
  })

  it('vuln class matching is case- and separator-insensitive', () => {
    const dash = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'SQL-Injection', severity: 'high' })],
    })
    const underscore = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'sql_injection', severity: 'high' })],
    })
    expect(dash.frameworkScores.map((f) => f.score)).toEqual(
      underscore.frameworkScores.map((f) => f.score),
    )
  })
})

// ---------------------------------------------------------------------------
// Drift level thresholds
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — drift levels', () => {
  it('score ≥ 80 → compliant', () => {
    // One low unvalidated finding = 2 points penalty → score 98
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'low', validationStatus: 'pending' })],
    })
    expect(result.overallDriftLevel).toBe('compliant')
  })

  it('score 60–79 → drifting (two critical unvalidated = 40 penalty → score 60)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [
        finding({ severity: 'critical', validationStatus: 'pending' }),
        finding({ severity: 'critical', validationStatus: 'pending' }),
      ],
    })
    expect(result.overallDriftLevel).toBe('drifting')
  })

  it('score 40–59 → at_risk (three critical unvalidated = 60 penalty → score 40)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: Array.from({ length: 3 }, () =>
        finding({ severity: 'critical', validationStatus: 'pending' }),
      ),
    })
    expect(result.overallDriftLevel).toBe('at_risk')
  })

  it('score < 40 → non_compliant (five critical unvalidated = 100 penalty → score 0)', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: Array.from({ length: 5 }, () =>
        finding({ severity: 'critical', validationStatus: 'pending' }),
      ),
    })
    expect(result.overallDriftLevel).toBe('non_compliant')
  })
})

// ---------------------------------------------------------------------------
// Counts and metadata
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — counts and metadata', () => {
  it('openGapCount counts distinct open findings that map to any framework', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [
        finding({ severity: 'critical' }),
        finding({ severity: 'high' }),
        finding({ status: 'resolved' }), // not counted
      ],
    })
    expect(result.openGapCount).toBe(2)
  })

  it('criticalGapCount counts only open critical findings', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [
        finding({ severity: 'critical' }),
        finding({ severity: 'critical', status: 'resolved' }), // not counted
        finding({ severity: 'high' }),
      ],
    })
    expect(result.criticalGapCount).toBe(1)
  })

  it('affectedFrameworks contains framework labels for frameworks with gaps', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ vulnClass: 'xss' })], // affects soc2, gdpr, pci_dss, nis2
    })
    expect(result.affectedFrameworks).toContain(FRAMEWORK_LABELS.soc2)
    expect(result.affectedFrameworks).not.toContain(FRAMEWORK_LABELS.hipaa)
  })

  it('returns all 5 framework score entries always', () => {
    const result = computeRegulatoryDrift(BASE_INPUT)
    expect(result.frameworkScores).toHaveLength(5)
  })

  it('framework score entries have correct labels', () => {
    const result = computeRegulatoryDrift(BASE_INPUT)
    const labels = result.frameworkScores.map((f) => f.label)
    expect(labels).toContain('SOC 2 Type II')
    expect(labels).toContain('GDPR Art. 32')
    expect(labels).toContain('HIPAA Technical Safeguards')
    expect(labels).toContain('PCI-DSS v4.0')
    expect(labels).toContain('NIS2 Art. 21')
  })
})

// ---------------------------------------------------------------------------
// Summary content
// ---------------------------------------------------------------------------

describe('computeRegulatoryDrift — summary', () => {
  it('mentions repository name in summary', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding()],
      repositoryName: 'my-org/backend',
    })
    expect(result.summary).toContain('my-org/backend')
  })

  it('clean summary mentions no compliance gaps', () => {
    expect(computeRegulatoryDrift(BASE_INPUT).summary).toContain('no open regulatory compliance gaps')
  })

  it('summary mentions critical count when criticals present', () => {
    const result = computeRegulatoryDrift({
      ...BASE_INPUT,
      findings: [finding({ severity: 'critical' })],
    })
    expect(result.summary).toMatch(/1 critical finding/)
  })
})
