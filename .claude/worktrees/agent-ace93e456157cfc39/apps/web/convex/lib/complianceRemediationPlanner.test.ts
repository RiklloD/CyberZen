/**
 * WS-47 — Compliance Gap Remediation Planner: test suite.
 */
import { describe, it, expect } from 'vitest'
import {
  REMEDIATION_CATALOG,
  CONTROL_ROOT_CAUSE,
  computeRemediationPlan,
} from './complianceRemediationPlanner'
import type { ControlGap } from './complianceAttestationReport'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** All 22 WS-46 control IDs */
const ALL_CONTROL_IDS = [
  // SOC 2
  'CC6.1', 'CC6.6', 'CC6.7', 'CC7.1', 'CC7.2', 'CC8.1', 'CC9.2',
  // GDPR
  'Art.25', 'Art.32', 'Art.33-34',
  // PCI-DSS
  'Req.6.2', 'Req.6.3', 'Req.6.5', 'Req.11.3',
  // HIPAA
  '§164.312(a)(1)', '§164.312(a)(2)(iv)', '§164.312(c)(1)', '§164.312(e)(2)(ii)',
  // NIS2
  'Art.21(2)(e)', 'Art.21(2)(h)', 'Art.21(2)(i)', 'Art.21(2)(j)',
]

function gap(
  controlId: string,
  controlName: string,
  gapSeverity: ControlGap['gapSeverity'],
  description = 'test gap',
): ControlGap {
  return { controlId, controlName, gapSeverity, description }
}

// ---------------------------------------------------------------------------
// REMEDIATION_CATALOG integrity
// ---------------------------------------------------------------------------

describe('REMEDIATION_CATALOG integrity', () => {
  it('has exactly 22 entries', () => {
    expect(Object.keys(REMEDIATION_CATALOG).length).toBe(22)
  })

  it('contains all 22 WS-46 control IDs', () => {
    for (const id of ALL_CONTROL_IDS) {
      expect(REMEDIATION_CATALOG[id], `Missing entry for ${id}`).toBeDefined()
    }
  })

  it('has no duplicate controlIds', () => {
    const ids = Object.values(REMEDIATION_CATALOG).map((e) => e.controlId)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('every entry has at least one step', () => {
    for (const [id, entry] of Object.entries(REMEDIATION_CATALOG)) {
      expect(entry.steps.length, `${id} has no steps`).toBeGreaterThan(0)
    }
  })

  it('every entry has non-empty evidenceNeeded', () => {
    for (const [id, entry] of Object.entries(REMEDIATION_CATALOG)) {
      expect(entry.evidenceNeeded.length, `${id} has empty evidenceNeeded`).toBeGreaterThan(0)
    }
  })

  it('every step has sequential 1-based order', () => {
    for (const [id, entry] of Object.entries(REMEDIATION_CATALOG)) {
      for (let i = 0; i < entry.steps.length; i++) {
        expect(entry.steps[i].order, `${id} step ${i} order`).toBe(i + 1)
      }
    }
  })

  it('every entry has a valid effort level', () => {
    const valid = new Set(['low', 'medium', 'high'])
    for (const [id, entry] of Object.entries(REMEDIATION_CATALOG)) {
      expect(valid.has(entry.effort), `${id} effort: ${entry.effort}`).toBe(true)
    }
  })

  it('every entry has estimatedDays ≥ 1', () => {
    for (const [id, entry] of Object.entries(REMEDIATION_CATALOG)) {
      expect(entry.estimatedDays, `${id} estimatedDays`).toBeGreaterThanOrEqual(1)
    }
  })

  it('CONTROL_ROOT_CAUSE covers all 22 control IDs', () => {
    for (const id of ALL_CONTROL_IDS) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((CONTROL_ROOT_CAUSE as any)[id], `Missing root cause for ${id}`).toBeDefined()
    }
  })
})

// ---------------------------------------------------------------------------
// Clean / empty input
// ---------------------------------------------------------------------------

describe('clean input (no gaps)', () => {
  const plan = computeRemediationPlan([])

  it('actions is empty', () => {
    expect(plan.actions).toHaveLength(0)
  })

  it('totalActions = 0', () => {
    expect(plan.totalActions).toBe(0)
  })

  it('estimatedTotalDays = 0', () => {
    expect(plan.estimatedTotalDays).toBe(0)
  })

  it('all counts = 0', () => {
    expect(plan.criticalActions).toBe(0)
    expect(plan.highActions).toBe(0)
    expect(plan.mediumActions).toBe(0)
    expect(plan.lowActions).toBe(0)
    expect(plan.automatableActions).toBe(0)
    expect(plan.requiresPolicyDocCount).toBe(0)
  })

  it('summary says no issues', () => {
    expect(plan.summary.toLowerCase()).toMatch(/no remediation|satisfied/)
  })
})

// ---------------------------------------------------------------------------
// Single-gap actions
// ---------------------------------------------------------------------------

describe('CC6.1 — secret exposure gap', () => {
  const plan = computeRemediationPlan([gap('CC6.1', 'Logical Access Controls', 'critical')])

  it('produces one action', () => {
    expect(plan.actions).toHaveLength(1)
  })

  it('action has correct controlId', () => {
    expect(plan.actions[0].controlId).toBe('CC6.1')
  })

  it('action title is about rotating credentials', () => {
    expect(plan.actions[0].title.toLowerCase()).toMatch(/rotate|credential/)
  })

  it('framework is soc2', () => {
    expect(plan.actions[0].framework).toBe('soc2')
  })

  it('gap severity is preserved', () => {
    expect(plan.actions[0].gapSeverity).toBe('critical')
  })

  it('requiresPolicyDoc is true', () => {
    expect(plan.actions[0].requiresPolicyDoc).toBe(true)
  })

  it('at least one step is automatable (pre-commit hook)', () => {
    expect(plan.actions[0].automatable).toBe(true)
  })
})

describe('CC6.7 — crypto weakness gap', () => {
  const plan = computeRemediationPlan([gap('CC6.7', 'Encryption', 'critical')])

  it('produces one action', () => {
    expect(plan.actions).toHaveLength(1)
  })

  it('action is about replacing algorithms', () => {
    expect(plan.actions[0].title.toLowerCase()).toMatch(/replac|crypt/)
  })

  it('requiresPolicyDoc is false (code fix, no policy required)', () => {
    expect(plan.actions[0].requiresPolicyDoc).toBe(false)
  })
})

describe('CC7.1 — EOL/CVE gap', () => {
  const plan = computeRemediationPlan([gap('CC7.1', 'Vulnerability Monitoring', 'high')])

  it('action title mentions patching or upgrading', () => {
    expect(plan.actions[0].title.toLowerCase()).toMatch(/patch|upgrade|cve|end-of-life/)
  })

  it('has automatable step (Dependabot/Renovate setup)', () => {
    expect(plan.actions[0].automatable).toBe(true)
  })
})

describe('CC7.2 — attestation gap', () => {
  const plan = computeRemediationPlan([gap('CC7.2', 'Integrity', 'medium')])

  it('effort is low', () => {
    expect(plan.actions[0].effort).toBe('low')
  })

  it('has automatable step (re-attestation)', () => {
    expect(plan.actions[0].automatable).toBe(true)
  })
})

describe('CC8.1 — CI/CD gap', () => {
  const plan = computeRemediationPlan([gap('CC8.1', 'Change Management', 'high')])

  it('action title mentions CI/CD', () => {
    expect(plan.actions[0].title.toLowerCase()).toMatch(/ci\/cd|pipeline/)
  })
})

describe('Art.25 — container gap', () => {
  const plan = computeRemediationPlan([gap('Art.25', 'Data Protection by Design', 'high')])

  it('framework is gdpr', () => {
    expect(plan.actions[0].framework).toBe('gdpr')
  })

  it('action title mentions containers or images', () => {
    expect(plan.actions[0].title.toLowerCase()).toMatch(/container|base image/)
  })
})

describe('Art.21(2)(e) — malicious package gap', () => {
  const plan = computeRemediationPlan([gap('Art.21(2)(e)', 'Supply Chain Security', 'critical')])

  it('framework is nis2', () => {
    expect(plan.actions[0].framework).toBe('nis2')
  })

  it('action title mentions malicious or supply chain', () => {
    expect(plan.actions[0].title.toLowerCase()).toMatch(/malicious|supply chain/)
  })
})

describe('§164.312(a)(1) — HIPAA access control gap', () => {
  const plan = computeRemediationPlan([gap('§164.312(a)(1)', 'Access Control', 'critical')])

  it('framework is hipaa', () => {
    expect(plan.actions[0].framework).toBe('hipaa')
  })

  it('steps mention ePHI', () => {
    const allInstructions = plan.actions[0].steps.map((s) => s.instruction).join(' ')
    expect(allInstructions.toLowerCase()).toMatch(/ephi/)
  })
})

describe('Req.6.3 — PCI EOL gap', () => {
  const plan = computeRemediationPlan([gap('Req.6.3', 'Security Vulnerabilities', 'critical')])

  it('framework is pci_dss', () => {
    expect(plan.actions[0].framework).toBe('pci_dss')
  })

  it('has a policy_doc step', () => {
    const hasPolicy = plan.actions[0].steps.some((s) => s.category === 'policy_doc')
    expect(hasPolicy).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Unknown controlId
// ---------------------------------------------------------------------------

describe('unknown controlId', () => {
  it('is silently skipped', () => {
    const plan = computeRemediationPlan([gap('UNKNOWN-999', 'Unknown Control', 'critical')])
    expect(plan.actions).toHaveLength(0)
  })

  it('known gap is still included when mixed with unknown', () => {
    const plan = computeRemediationPlan([
      gap('UNKNOWN-999', 'Unknown Control', 'critical'),
      gap('CC6.1', 'Logical Access Controls', 'high'),
    ])
    expect(plan.actions).toHaveLength(1)
    expect(plan.actions[0].controlId).toBe('CC6.1')
  })
})

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

describe('sorting by gap severity', () => {
  const plan = computeRemediationPlan([
    gap('CC7.1', 'Vulnerability Monitoring', 'medium'),
    gap('CC6.1', 'Logical Access Controls', 'critical'),
    gap('CC7.2', 'Integrity', 'low'),
    gap('CC6.6', 'Infrastructure Security', 'high'),
  ])

  it('first action is critical', () => {
    expect(plan.actions[0].gapSeverity).toBe('critical')
  })

  it('second action is high', () => {
    expect(plan.actions[1].gapSeverity).toBe('high')
  })

  it('third action is medium', () => {
    expect(plan.actions[2].gapSeverity).toBe('medium')
  })

  it('fourth action is low', () => {
    expect(plan.actions[3].gapSeverity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Aggregate counts
// ---------------------------------------------------------------------------

describe('aggregate counts', () => {
  it('criticalActions counts correctly', () => {
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
      gap('CC6.7', 'Encryption', 'critical'),
      gap('CC7.1', 'Vulnerability Monitoring', 'high'),
    ])
    expect(plan.criticalActions).toBe(2)
    expect(plan.highActions).toBe(1)
  })

  it('automatableActions counts actions with ≥ 1 automatable step', () => {
    // CC6.1 has an automatable step (pre-commit hook)
    // CC6.7 has an automatable step (Sentinel gate)
    // CC6.6 has an automatable step (CI/CD gate)
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
      gap('CC6.7', 'Encryption', 'high'),
      gap('CC6.6', 'Infrastructure Security', 'medium'),
    ])
    expect(plan.automatableActions).toBe(3)
  })

  it('requiresPolicyDocCount counts correctly', () => {
    // CC6.1 = requiresPolicyDoc true, CC6.7 = false
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
      gap('CC6.7', 'Encryption', 'critical'),
    ])
    expect(plan.requiresPolicyDocCount).toBe(1)
  })

  it('totalActions equals actions.length', () => {
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
      gap('CC7.2', 'Integrity', 'medium'),
    ])
    expect(plan.totalActions).toBe(plan.actions.length)
  })
})

// ---------------------------------------------------------------------------
// estimatedTotalDays root-cause deduplication
// ---------------------------------------------------------------------------

describe('estimatedTotalDays root-cause deduplication', () => {
  it('same root cause across frameworks counts once (max)', () => {
    // CC6.7 (5 days), Art.32 (5 days), §164.312(a)(2)(iv) (5 days) all → crypto_weakness
    // estimatedTotalDays should be 5 (not 15)
    const plan = computeRemediationPlan([
      gap('CC6.7', 'Encryption', 'critical'),
      gap('Art.32', 'Security of Processing', 'critical'),
      gap('§164.312(a)(2)(iv)', 'Encryption and Decryption', 'critical'),
    ])
    expect(plan.estimatedTotalDays).toBe(5)
  })

  it('CC6.1 and §164.312(a)(1) both secret_exposure → max(3, 5) = 5', () => {
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
      gap('§164.312(a)(1)', 'Access Control', 'critical'),
    ])
    expect(plan.estimatedTotalDays).toBe(5)
  })

  it('different root causes sum independently', () => {
    // CC6.7 (crypto_weakness, 5 days) + CC7.2 (sbom_integrity, 1 day) = 6
    const plan = computeRemediationPlan([
      gap('CC6.7', 'Encryption', 'critical'),
      gap('CC7.2', 'Integrity', 'medium'),
    ])
    expect(plan.estimatedTotalDays).toBe(6)
  })

  it('multiple EOL/CVE controls count as one root cause', () => {
    // CC7.1 (2), Req.6.2 (2), Req.6.3 (3), Art.33-34 (3), Req.11.3 (2) → eol_or_cve → max=3
    const plan = computeRemediationPlan([
      gap('CC7.1', 'Vulnerability Monitoring', 'critical'),
      gap('Req.6.2', 'Protect System Components', 'critical'),
      gap('Req.6.3', 'Security Vulnerabilities', 'critical'),
      gap('Art.33-34', 'Breach Notification', 'high'),
      gap('Req.11.3', 'Penetration Testing', 'high'),
    ])
    expect(plan.estimatedTotalDays).toBe(3)
  })

  it('Art.25 and Art.21(2)(h) both container_risk → max days', () => {
    // Art.25 = 2 days, Art.21(2)(h) = 2 days → still 2 total
    const plan = computeRemediationPlan([
      gap('Art.25', 'Data Protection by Design', 'high'),
      gap('Art.21(2)(h)', 'Network Security', 'high'),
    ])
    expect(plan.estimatedTotalDays).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('no gaps → clean summary', () => {
    const plan = computeRemediationPlan([])
    expect(plan.summary.toLowerCase()).toMatch(/no remediation|satisfied/)
  })

  it('critical gaps → mentions "critical" and "immediate"', () => {
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
    ])
    expect(plan.summary.toLowerCase()).toMatch(/critical/)
    expect(plan.summary.toLowerCase()).toMatch(/immediate/)
  })

  it('high-only gaps → mentions "high-priority"', () => {
    const plan = computeRemediationPlan([
      gap('CC7.1', 'Vulnerability Monitoring', 'high'),
    ])
    expect(plan.summary.toLowerCase()).toMatch(/high/)
  })

  it('automatable action → summary mentions automation', () => {
    const plan = computeRemediationPlan([
      gap('CC6.1', 'Logical Access Controls', 'critical'),
    ])
    expect(plan.summary.toLowerCase()).toMatch(/automat/)
  })

  it('mentions estimated days in summary', () => {
    const plan = computeRemediationPlan([
      gap('CC6.7', 'Encryption', 'critical'),
    ])
    expect(plan.summary).toMatch(/\d+ working day/)
  })
})

// ---------------------------------------------------------------------------
// All 22 controls produce a valid action
// ---------------------------------------------------------------------------

describe('all 22 controls produce a valid action', () => {
  for (const controlId of ALL_CONTROL_IDS) {
    it(`${controlId} produces a non-empty action`, () => {
      const plan = computeRemediationPlan([gap(controlId, 'Test Control', 'high')])
      expect(plan.actions).toHaveLength(1)
      expect(plan.actions[0].steps.length).toBeGreaterThan(0)
      expect(plan.actions[0].evidenceNeeded.length).toBeGreaterThan(0)
    })
  }
})
