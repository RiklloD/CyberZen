import { describe, expect, it } from 'vitest'
import { computeCloudBlastRadius } from './cloudBlastRadius'

// ---------------------------------------------------------------------------
// Fixture helper
// ---------------------------------------------------------------------------

function component(name: string) {
  return { name, ecosystem: 'npm', layer: 'runtime' }
}

// ---------------------------------------------------------------------------
// Empty input
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — empty components', () => {
  it('returns minimal risk and cloudBlastScore=0 when component list is empty', () => {
    const result = computeCloudBlastRadius({ components: [], repositoryName: 'my-repo' })
    expect(result.cloudRiskTier).toBe('minimal')
    expect(result.cloudBlastScore).toBe(0)
    expect(result.providers).toHaveLength(0)
    expect(result.reachableCloudResources).toHaveLength(0)
  })

  it('sets all risk flags to false when component list is empty', () => {
    const result = computeCloudBlastRadius({ components: [], repositoryName: 'my-repo' })
    expect(result.iamEscalationRisk).toBe(false)
    expect(result.dataExfiltrationRisk).toBe(false)
    expect(result.secretsAccessRisk).toBe(false)
    expect(result.lateralMovementRisk).toBe(false)
  })

  it('summary says "No cloud SDK" when component list is empty', () => {
    const result = computeCloudBlastRadius({ components: [], repositoryName: 'my-repo' })
    expect(result.cloudSummary).toContain('No cloud SDK')
    expect(result.cloudSummary).toContain('my-repo')
  })
})

// ---------------------------------------------------------------------------
// AWS IAM
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — @aws-sdk/client-iam', () => {
  it('detects AWS provider and sets iamEscalationRisk=true', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-iam')],
      repositoryName: 'repo',
    })
    expect(result.providers).toContain('aws')
    expect(result.iamEscalationRisk).toBe(true)
  })

  it('cloudBlastScore is capped at 100 (iam=100 base + 15 IAM bonus = 115 → clamped)', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-iam')],
      repositoryName: 'repo',
    })
    expect(result.cloudBlastScore).toBe(100)
    expect(result.cloudRiskTier).toBe('critical')
  })

  it('summary mentions "IAM privilege escalation" when iamEscalationRisk is true', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-iam')],
      repositoryName: 'repo',
    })
    expect(result.cloudSummary).toContain('IAM privilege escalation')
  })
})

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — secrets', () => {
  it('@aws-sdk/client-secrets-manager → secretsAccessRisk=true', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-secrets-manager')],
      repositoryName: 'repo',
    })
    expect(result.secretsAccessRisk).toBe(true)
  })

  it('@azure/keyvault-secrets → key_vault → secretsAccessRisk=true, azure provider', () => {
    const result = computeCloudBlastRadius({
      components: [component('@azure/keyvault-secrets')],
      repositoryName: 'repo',
    })
    expect(result.secretsAccessRisk).toBe(true)
    expect(result.providers).toContain('azure')
  })

  it('@google-cloud/secret-manager → secret_manager → secretsAccessRisk=true, gcp provider', () => {
    const result = computeCloudBlastRadius({
      components: [component('@google-cloud/secret-manager')],
      repositoryName: 'repo',
    })
    expect(result.secretsAccessRisk).toBe(true)
    expect(result.providers).toContain('gcp')
  })
})

// ---------------------------------------------------------------------------
// boto3 (comprehensive AWS SDK)
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — boto3', () => {
  it('detects all boto3 AWS resource types', () => {
    const result = computeCloudBlastRadius({
      components: [component('boto3')],
      repositoryName: 'repo',
    })
    const types = result.reachableCloudResources.map((r) => r.resourceType)
    expect(types).toContain('s3')
    expect(types).toContain('ec2')
    expect(types).toContain('rds')
    expect(types).toContain('lambda')
    expect(types).toContain('iam')
    expect(types).toContain('sqs')
    expect(types).toContain('sns')
    expect(types).toContain('dynamodb')
    expect(types).toContain('secrets_manager')
  })

  it('boto3 sets all four risk flags to true', () => {
    const result = computeCloudBlastRadius({
      components: [component('boto3')],
      repositoryName: 'repo',
    })
    expect(result.iamEscalationRisk).toBe(true)
    expect(result.secretsAccessRisk).toBe(true)
    expect(result.dataExfiltrationRisk).toBe(true)
    expect(result.lateralMovementRisk).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — GCP', () => {
  it('@google-cloud/storage → gcp provider and gcs resource', () => {
    const result = computeCloudBlastRadius({
      components: [component('@google-cloud/storage')],
      repositoryName: 'repo',
    })
    expect(result.providers).toContain('gcp')
    expect(result.reachableCloudResources.map((r) => r.resourceType)).toContain('gcs')
  })

  it('firebase-admin → firestore, firebase_storage, firebase_auth all detected', () => {
    const result = computeCloudBlastRadius({
      components: [component('firebase-admin')],
      repositoryName: 'repo',
    })
    const types = result.reachableCloudResources.map((r) => r.resourceType)
    expect(types).toContain('firestore')
    expect(types).toContain('firebase_storage')
    expect(types).toContain('firebase_auth')
  })
})

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — Azure', () => {
  it('@azure/identity → azure provider, managed_identity, iamEscalationRisk=true', () => {
    const result = computeCloudBlastRadius({
      components: [component('@azure/identity')],
      repositoryName: 'repo',
    })
    expect(result.providers).toContain('azure')
    expect(result.iamEscalationRisk).toBe(true)
    expect(result.reachableCloudResources.map((r) => r.resourceType)).toContain('managed_identity')
  })
})

// ---------------------------------------------------------------------------
// Multi-cloud
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — multi-cloud', () => {
  it('AWS + GCP → providers.length=2, score gets +10 multi-provider bonus', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-s3'), component('@google-cloud/storage')],
      repositoryName: 'repo',
    })
    expect(result.providers).toHaveLength(2)
    expect(result.providers).toContain('aws')
    expect(result.providers).toContain('gcp')
    // base=max(s3=75, gcs=75)=75, +10 multi, +5 dataExfil = 90
    expect(result.cloudBlastScore).toBe(90)
  })

  it('providers array has no duplicates with multiple AWS packages', () => {
    const result = computeCloudBlastRadius({
      components: [
        component('@aws-sdk/client-s3'),
        component('@aws-sdk/client-lambda'),
        component('@aws-sdk/client-rds'),
      ],
      repositoryName: 'repo',
    })
    expect(result.providers.filter((p) => p === 'aws')).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// Lateral movement
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — lateralMovementRisk', () => {
  it('@aws-sdk/client-lambda → lambda resource → lateralMovementRisk=true', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-lambda')],
      repositoryName: 'repo',
    })
    expect(result.lateralMovementRisk).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// criticalResourceCount
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — criticalResourceCount', () => {
  it('counts only resources with sensitivityScore >= 80', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-iam'), component('@aws-sdk/client-s3')],
      repositoryName: 'repo',
    })
    // iam=100 (≥80 → counts), s3=75 (<80 → does not count)
    expect(result.criticalResourceCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Score capping
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — score capping', () => {
  it('cloudBlastScore is capped at 100 even with all bonuses', () => {
    // boto3 (iam=100 base) + gcs (multi-provider) → 100 + 10 + 15 + 10 + 5 = 140 → clamped to 100
    const result = computeCloudBlastRadius({
      components: [component('boto3'), component('@google-cloud/storage')],
      repositoryName: 'repo',
    })
    expect(result.cloudBlastScore).toBe(100)
  })
})

// ---------------------------------------------------------------------------
// Risk tier boundaries
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — risk tier boundaries', () => {
  it('score >= 80 → critical tier (rds=85 + 5 dataExfil = 90)', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-rds')],
      repositoryName: 'repo',
    })
    expect(result.cloudRiskTier).toBe('critical')
    expect(result.cloudBlastScore).toBeGreaterThanOrEqual(80)
  })

  it('sns alone → score 60 → severe tier', () => {
    // sns=60, no multi, no iam, no secrets, no dataExfil → 60 → severe
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-sns')],
      repositoryName: 'repo',
    })
    expect(result.cloudBlastScore).toBe(60)
    expect(result.cloudRiskTier).toBe('severe')
  })

  it('empty → score 0 → minimal tier', () => {
    const result = computeCloudBlastRadius({ components: [], repositoryName: 'repo' })
    expect(result.cloudRiskTier).toBe('minimal')
    expect(result.cloudBlastScore).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Prefix-based detection
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — prefix-based detection', () => {
  it('@aws-sdk/client-ecr (no exact match) → aws provider detected via prefix', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-ecr')],
      repositoryName: 'repo',
    })
    expect(result.providers).toContain('aws')
  })

  it('unknown packages (lodash, express) → no providers and no resources', () => {
    const result = computeCloudBlastRadius({
      components: [component('lodash'), component('express')],
      repositoryName: 'repo',
    })
    expect(result.providers).toHaveLength(0)
    expect(result.reachableCloudResources).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Summary content
// ---------------------------------------------------------------------------

describe('computeCloudBlastRadius — summary content', () => {
  it('summary includes "AWS" when aws provider detected', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-s3')],
      repositoryName: 'repo',
    })
    expect(result.cloudSummary).toContain('AWS')
  })

  it('summary includes "GCP" when gcp provider detected', () => {
    const result = computeCloudBlastRadius({
      components: [component('@google-cloud/bigquery')],
      repositoryName: 'repo',
    })
    expect(result.cloudSummary).toContain('GCP')
  })

  it('summary includes "secrets access" when secretsAccessRisk is true', () => {
    const result = computeCloudBlastRadius({
      components: [component('@aws-sdk/client-secrets-manager')],
      repositoryName: 'repo',
    })
    expect(result.cloudSummary).toContain('secrets access')
  })
})
