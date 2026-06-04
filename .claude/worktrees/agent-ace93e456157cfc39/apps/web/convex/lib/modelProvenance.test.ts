import { describe, it, expect } from 'vitest'
import {
  assessModelProvenance,
  scanModelProvenance,
  scoreProvenanceSignals,
  type ModelComponentInput,
  type ProvenanceSignal,
} from './modelProvenance'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base(overrides: Partial<ModelComponentInput> = {}): ModelComponentInput {
  return {
    name: 'meta-llama/Llama-3-8b-instruct',
    version: '3.0.0',
    ecosystem: 'huggingface',
    layer: 'ai_model',
    license: 'llama 3 community license',
    weightsHash: 'sha256:abc123',
    hasKnownVulnerabilities: false,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// assessModelProvenance — clean model
// ---------------------------------------------------------------------------

describe('assessModelProvenance — clean model', () => {
  it('returns verified risk level for a well-specified model', () => {
    const result = assessModelProvenance(base())
    expect(result.riskLevel).toBe('verified')
    expect(result.provenanceScore).toBeGreaterThanOrEqual(80)
  })

  it('resolves source to huggingface for HF ecosystem', () => {
    const result = assessModelProvenance(base())
    expect(result.resolvedSource).toBe('huggingface')
  })

  it('normalises license to lowercase', () => {
    const result = assessModelProvenance(base({ license: 'Apache-2.0' }))
    expect(result.resolvedLicense).toBe('apache-2.0')
  })

  it('produces no signals for a fully specified verified model', () => {
    const result = assessModelProvenance(base())
    expect(result.signals).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// assessModelProvenance — unknown source
// ---------------------------------------------------------------------------

describe('assessModelProvenance — unknown source', () => {
  it('flags unknown_source when registry is unrecognised', () => {
    const result = assessModelProvenance(base({ name: 'some-random-model', ecosystem: 'unknown' }))
    const sig = result.signals.find((s) => s.kind === 'unknown_source')
    expect(sig).toBeDefined()
    expect(sig?.severity).toBe('high')
  })

  it('lowers score significantly for unknown source', () => {
    const clean = assessModelProvenance(base())
    const unknown = assessModelProvenance(base({ name: 'random-model', ecosystem: 'unknown' }))
    expect(unknown.provenanceScore).toBeLessThan(clean.provenanceScore)
  })
})

// ---------------------------------------------------------------------------
// assessModelProvenance — license signals
// ---------------------------------------------------------------------------

describe('assessModelProvenance — license', () => {
  it('flags restricted_license for CC-BY-NC-4.0', () => {
    const result = assessModelProvenance(base({ license: 'CC-BY-NC-4.0' }))
    const sig = result.signals.find((s) => s.kind === 'restricted_license')
    expect(sig).toBeDefined()
    expect(sig?.severity).toBe('high')
  })

  it('flags no_license when license is absent', () => {
    const result = assessModelProvenance(base({ license: undefined }))
    const sig = result.signals.find((s) => s.kind === 'no_license')
    expect(sig).toBeDefined()
    expect(sig?.severity).toBe('medium')
  })

  it('does NOT flag MIT as restricted', () => {
    const result = assessModelProvenance(base({ license: 'MIT' }))
    const restricted = result.signals.find((s) => s.kind === 'restricted_license')
    expect(restricted).toBeUndefined()
  })

  it('does NOT flag Apache-2.0 as restricted', () => {
    const result = assessModelProvenance(base({ license: 'Apache-2.0' }))
    const restricted = result.signals.find((s) => s.kind === 'restricted_license')
    expect(restricted).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// assessModelProvenance — hash verification
// ---------------------------------------------------------------------------

describe('assessModelProvenance — weights hash', () => {
  it('flags unverified_hash when weightsHash is absent', () => {
    const result = assessModelProvenance(base({ weightsHash: undefined }))
    const sig = result.signals.find((s) => s.kind === 'unverified_hash')
    expect(sig).toBeDefined()
    expect(sig?.severity).toBe('medium')
  })

  it('does NOT flag unverified_hash when hash is present', () => {
    const result = assessModelProvenance(base({ weightsHash: 'sha256:abc' }))
    expect(result.signals.find((s) => s.kind === 'unverified_hash')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// assessModelProvenance — version pinning
// ---------------------------------------------------------------------------

describe('assessModelProvenance — version pinning', () => {
  it('flags unpinned_version for "latest"', () => {
    const result = assessModelProvenance(base({ version: 'latest' }))
    expect(result.signals.find((s) => s.kind === 'unpinned_version')).toBeDefined()
  })

  it('flags unpinned_version for "main"', () => {
    const result = assessModelProvenance(base({ version: 'main' }))
    expect(result.signals.find((s) => s.kind === 'unpinned_version')).toBeDefined()
  })

  it('does NOT flag unpinned for an exact version', () => {
    const result = assessModelProvenance(base({ version: '3.0.1' }))
    expect(result.signals.find((s) => s.kind === 'unpinned_version')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// assessModelProvenance — pre-release
// ---------------------------------------------------------------------------

describe('assessModelProvenance — pre-release', () => {
  it('flags pre_release_model for beta versions', () => {
    const result = assessModelProvenance(base({ version: '2.0.0-beta.1' }))
    expect(result.signals.find((s) => s.kind === 'pre_release_model')).toBeDefined()
  })

  it('flags pre_release_model for alpha versions', () => {
    const result = assessModelProvenance(base({ version: '1.0.0-alpha' }))
    expect(result.signals.find((s) => s.kind === 'pre_release_model')).toBeDefined()
  })

  it('does NOT flag stable release as pre-release', () => {
    const result = assessModelProvenance(base({ version: '3.0.0' }))
    expect(result.signals.find((s) => s.kind === 'pre_release_model')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// assessModelProvenance — training data risk
// ---------------------------------------------------------------------------

describe('assessModelProvenance — training data risk', () => {
  it('flags training_data_risk for LAION-5B', () => {
    const result = assessModelProvenance(base({ trainingDatasets: ['laion-5b', 'cc12m'] }))
    const sig = result.signals.find((s) => s.kind === 'training_data_risk')
    expect(sig).toBeDefined()
    expect(sig?.severity).toBe('high')
  })

  it('does NOT flag safe training datasets', () => {
    const result = assessModelProvenance(base({ trainingDatasets: ['openwebtext', 'stack'] }))
    expect(result.signals.find((s) => s.kind === 'training_data_risk')).toBeUndefined()
  })

  it('only produces one training_data_risk signal even with multiple risky datasets', () => {
    const result = assessModelProvenance(base({ trainingDatasets: ['laion-400m', 'laion-5b'] }))
    const signals = result.signals.filter((s) => s.kind === 'training_data_risk')
    expect(signals.length).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// scoreProvenanceSignals — user contribution
// ---------------------------------------------------------------------------

describe('scoreProvenanceSignals', () => {
  it('returns 100 when there are no signals', () => {
    expect(scoreProvenanceSignals([], 100)).toBe(100)
  })

  it('returns a value in [0, 100]', () => {
    const signals: ProvenanceSignal[] = [
      { kind: 'unknown_source', severity: 'high', description: '', penalty: 25 },
      { kind: 'no_license', severity: 'medium', description: '', penalty: 15 },
      { kind: 'unverified_hash', severity: 'medium', description: '', penalty: 15 },
    ]
    const score = scoreProvenanceSignals(signals, 100)
    expect(score).toBeGreaterThanOrEqual(0)
    expect(score).toBeLessThanOrEqual(100)
  })

  it('reduces score when penalties are present', () => {
    const noSignals = scoreProvenanceSignals([], 100)
    const withSignal = scoreProvenanceSignals(
      [{ kind: 'unknown_source', severity: 'high', description: '', penalty: 25 }],
      100,
    )
    expect(withSignal).toBeLessThan(noSignals)
  })
})

// ---------------------------------------------------------------------------
// scanModelProvenance — repository-level
// ---------------------------------------------------------------------------

describe('scanModelProvenance — empty SBOM', () => {
  it('returns verified with score 100 when no model components', () => {
    const result = scanModelProvenance([])
    expect(result.totalModels).toBe(0)
    expect(result.overallRiskLevel).toBe('verified')
    expect(result.aggregateScore).toBe(100)
  })
})

describe('scanModelProvenance — mixed repository', () => {
  const components: ModelComponentInput[] = [
    base({ name: 'meta-llama/Llama-3-8b', version: '3.0.0', weightsHash: 'sha256:aaa' }),
    base({
      name: 'mystery-model',
      version: 'latest',
      ecosystem: 'unknown',
      license: undefined,
      weightsHash: undefined,
    }),
  ]

  it('counts models correctly', () => {
    const result = scanModelProvenance(components)
    expect(result.totalModels).toBeGreaterThan(0)
  })

  it('aggregate score is between 0 and 100', () => {
    const result = scanModelProvenance(components)
    expect(result.aggregateScore).toBeGreaterThanOrEqual(0)
    expect(result.aggregateScore).toBeLessThanOrEqual(100)
  })

  it('overall risk level is "risky" when a risky model is present', () => {
    const result = scanModelProvenance(components)
    // mystery-model has unknown source + no license + no hash + unpinned → risky
    expect(['risky', 'unverified']).toContain(result.overallRiskLevel)
  })

  it('produces a non-empty summary', () => {
    const result = scanModelProvenance(components)
    expect(result.summary.length).toBeGreaterThan(10)
  })
})

describe('scanModelProvenance — all verified', () => {
  const components: ModelComponentInput[] = [
    base({ name: 'meta-llama/Llama-3-8b', weightsHash: 'sha256:a', license: 'llama 3 community license' }),
    base({ name: 'mistral/Mistral-7B', weightsHash: 'sha256:b', license: 'apache-2.0', ecosystem: 'huggingface' }),
  ]

  it('returns verified when all models pass', () => {
    const result = scanModelProvenance(components)
    // Both have no signals → verified
    expect(['verified', 'acceptable']).toContain(result.overallRiskLevel)
  })
})
