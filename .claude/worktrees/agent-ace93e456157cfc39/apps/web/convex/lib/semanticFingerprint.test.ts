import { describe, expect, it } from 'vitest'
import { matchSemanticFingerprints } from './semanticFingerprint'

describe('matchSemanticFingerprints', () => {
  it('matches auth-sensitive file paths against the auth fingerprint', () => {
    const matches = matchSemanticFingerprints({
      repositoryName: 'payments-api',
      changedFiles: ['services/auth/jwt.py', 'services/auth/token_router.py'],
      inventoryComponents: [
        {
          name: 'pyjwt',
          sourceFile: 'requirements.txt',
          dependents: ['auth-gateway'],
        },
      ],
    })

    expect(matches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          fingerprintId: 'SVF-AUTH-001',
          vulnClass: 'jwt_validation_bypass',
          affectedPackages: ['pyjwt'],
          affectedServices: ['auth-gateway'],
        }),
      ]),
    )
  })

  it('matches prompt-oriented changes against the llm fingerprint', () => {
    const matches = matchSemanticFingerprints({
      repositoryName: 'operator-console',
      changedFiles: ['src/lib/prompt-builder.ts', 'src/lib/agent-runner.ts'],
      inventoryComponents: [
        {
          name: 'openai',
          sourceFile: 'package.json',
          dependents: [],
        },
      ],
    })

    expect(matches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          fingerprintId: 'SVF-LLM-001',
          vulnClass: 'llm_prompt_boundary',
          affectedPackages: ['openai'],
          affectedServices: ['operator-console'],
        }),
      ]),
    )
  })

  it('returns no matches for documentation-only changes', () => {
    expect(
      matchSemanticFingerprints({
        repositoryName: 'operator-console',
        changedFiles: ['README.md', 'docs/rollout-notes.md'],
        inventoryComponents: [],
      }),
    ).toEqual([])
  })
})
