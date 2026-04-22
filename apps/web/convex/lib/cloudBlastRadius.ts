// Multi-Cloud Blast Radius — pure computation library.
//
// Infers cloud resource exposure from SBOM package names alone — no cloud API
// calls needed. Maps SDK package names to cloud resource types and sensitivity
// scores, then computes a composite cloud blast score + risk tier.
//
// Score formula:
//   cloudBlastScore = max sensitivity score across all detected resources
//   + (providers.length > 1 ? +10 : 0)   — multi-provider bonus
//   + (iamEscalationRisk ? +15 : 0)
//   + (secretsAccessRisk ? +10 : 0)
//   + (dataExfiltrationRisk ? +5 : 0)
//   clamped to [0, 100]
//
// Risk tiers: critical (≥80), severe (≥60), moderate (≥35), minimal (<35)

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

export type CloudBlastRadiusInput = {
  components: Array<{ name: string; ecosystem: string; layer: string }>
  repositoryName: string
}

export type CloudRiskTier = 'critical' | 'severe' | 'moderate' | 'minimal'

export type CloudResourceResult = {
  provider: 'aws' | 'gcp' | 'azure'
  resourceType: string
  sensitivityScore: number
  label: string
}

export type CloudBlastRadiusResult = {
  providers: Array<'aws' | 'gcp' | 'azure'>
  reachableCloudResources: CloudResourceResult[]
  /** Count of resources with sensitivityScore >= 80. */
  criticalResourceCount: number
  iamEscalationRisk: boolean
  dataExfiltrationRisk: boolean
  secretsAccessRisk: boolean
  lateralMovementRisk: boolean
  /** 0–100 composite cloud blast score. */
  cloudBlastScore: number
  cloudRiskTier: CloudRiskTier
  cloudSummary: string
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type Provider = 'aws' | 'gcp' | 'azure'

type SdkEntry = {
  provider: Provider
  resources: string[]
}

// ---------------------------------------------------------------------------
// SDK → resource mapping (exact package names)
// ---------------------------------------------------------------------------

const SDK_MAP: Record<string, SdkEntry> = {
  // AWS — broad SDKs
  boto3: { provider: 'aws', resources: ['s3', 'ec2', 'rds', 'lambda', 'iam', 'sqs', 'sns', 'dynamodb', 'secrets_manager'] },
  botocore: { provider: 'aws', resources: ['s3', 'ec2', 'rds', 'lambda', 'iam'] },
  'aws-sdk': { provider: 'aws', resources: ['s3', 'ec2', 'rds', 'lambda', 'iam', 'sqs', 'sns', 'dynamodb'] },
  // AWS — service-specific clients
  '@aws-sdk/client-s3': { provider: 'aws', resources: ['s3'] },
  '@aws-sdk/client-rds': { provider: 'aws', resources: ['rds'] },
  '@aws-sdk/client-lambda': { provider: 'aws', resources: ['lambda'] },
  '@aws-sdk/client-iam': { provider: 'aws', resources: ['iam'] },
  '@aws-sdk/client-sqs': { provider: 'aws', resources: ['sqs'] },
  '@aws-sdk/client-sns': { provider: 'aws', resources: ['sns'] },
  '@aws-sdk/client-dynamodb': { provider: 'aws', resources: ['dynamodb'] },
  '@aws-sdk/client-secrets-manager': { provider: 'aws', resources: ['secrets_manager'] },
  '@aws-sdk/client-kms': { provider: 'aws', resources: ['kms'] },
  // GCP
  '@google-cloud/storage': { provider: 'gcp', resources: ['gcs'] },
  '@google-cloud/pubsub': { provider: 'gcp', resources: ['pubsub'] },
  '@google-cloud/bigquery': { provider: 'gcp', resources: ['bigquery'] },
  '@google-cloud/spanner': { provider: 'gcp', resources: ['spanner'] },
  '@google-cloud/firestore': { provider: 'gcp', resources: ['firestore'] },
  '@google-cloud/secret-manager': { provider: 'gcp', resources: ['secret_manager'] },
  'google-cloud-storage': { provider: 'gcp', resources: ['gcs'] },
  'google-cloud-pubsub': { provider: 'gcp', resources: ['pubsub'] },
  'firebase-admin': { provider: 'gcp', resources: ['firestore', 'firebase_storage', 'firebase_auth'] },
  // Azure
  '@azure/storage-blob': { provider: 'azure', resources: ['blob_storage'] },
  '@azure/cosmos': { provider: 'azure', resources: ['cosmosdb'] },
  '@azure/service-bus': { provider: 'azure', resources: ['service_bus'] },
  '@azure/keyvault-secrets': { provider: 'azure', resources: ['key_vault'] },
  '@azure/identity': { provider: 'azure', resources: ['managed_identity', 'entra_id'] },
  '@azure/storage-queue': { provider: 'azure', resources: ['queue_storage'] },
  'azure-storage': { provider: 'azure', resources: ['blob_storage', 'table_storage', 'queue_storage'] },
}

// ---------------------------------------------------------------------------
// Resource sensitivity scores
// ---------------------------------------------------------------------------

const SENSITIVITY_SCORE: Record<string, number> = {
  iam: 100,
  managed_identity: 100,
  entra_id: 95,
  secrets_manager: 95,
  kms: 95,
  secret_manager: 95,
  key_vault: 95,
  firebase_auth: 90,
  rds: 85,
  spanner: 85,
  bigquery: 80,
  dynamodb: 80,
  cosmosdb: 80,
  firestore: 75,
  s3: 75,
  gcs: 75,
  blob_storage: 75,
  firebase_storage: 70,
  lambda: 70,
  table_storage: 65,
  sqs: 65,
  pubsub: 65,
  service_bus: 65,
  ec2: 65,
  sns: 60,
  queue_storage: 55,
}

// ---------------------------------------------------------------------------
// Human-readable resource labels
// ---------------------------------------------------------------------------

const RESOURCE_LABELS: Record<string, string> = {
  iam: 'IAM',
  managed_identity: 'Managed Identity',
  entra_id: 'Entra ID',
  secrets_manager: 'Secrets Manager',
  kms: 'KMS',
  secret_manager: 'Secret Manager',
  key_vault: 'Key Vault',
  firebase_auth: 'Firebase Auth',
  rds: 'RDS',
  spanner: 'Spanner',
  bigquery: 'BigQuery',
  dynamodb: 'DynamoDB',
  cosmosdb: 'Cosmos DB',
  firestore: 'Firestore',
  s3: 'S3',
  gcs: 'GCS',
  blob_storage: 'Blob Storage',
  firebase_storage: 'Firebase Storage',
  lambda: 'Lambda',
  table_storage: 'Table Storage',
  sqs: 'SQS',
  pubsub: 'Pub/Sub',
  service_bus: 'Service Bus',
  ec2: 'EC2',
  sns: 'SNS',
  queue_storage: 'Queue Storage',
}

function resourceLabel(resourceType: string): string {
  return RESOURCE_LABELS[resourceType] ?? resourceType
}

// ---------------------------------------------------------------------------
// Prefix-based provider detection (fallback when no exact SDK match)
// ---------------------------------------------------------------------------

function detectProviderByPrefix(name: string): Provider | null {
  if (name.startsWith('@aws-sdk/') || name.startsWith('aws-cdk')) return 'aws'
  if (
    name.startsWith('@google-cloud/') ||
    name.startsWith('google-cloud-') ||
    name.startsWith('firebase')
  )
    return 'gcp'
  if (name.startsWith('@azure/') || name.startsWith('azure-')) return 'azure'
  return null
}

// ---------------------------------------------------------------------------
// Risk tier
// ---------------------------------------------------------------------------

function scoreToCloudRiskTier(score: number): CloudRiskTier {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'severe'
  if (score >= 35) return 'moderate'
  return 'minimal'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

function buildCloudSummary(args: {
  repositoryName: string
  providers: Provider[]
  iamEscalationRisk: boolean
  secretsAccessRisk: boolean
  cloudBlastScore: number
  cloudRiskTier: CloudRiskTier
}): string {
  const {
    repositoryName,
    providers,
    iamEscalationRisk,
    secretsAccessRisk,
    cloudBlastScore,
    cloudRiskTier,
  } = args

  if (providers.length === 0) {
    return `No cloud SDK detected in ${repositoryName}; no cloud blast radius inferred.`
  }

  const providerLabels: Record<Provider, string> = { aws: 'AWS', gcp: 'GCP', azure: 'Azure' }
  const providerPhrase = providers.map((p) => providerLabels[p]).join(', ')

  const riskParts: string[] = []
  if (iamEscalationRisk) riskParts.push('IAM privilege escalation')
  if (secretsAccessRisk) riskParts.push('secrets access')

  const riskPhrase =
    riskParts.length > 0
      ? ` with elevated risks: ${riskParts.join(' and ')}.`
      : '.'

  return `${repositoryName} accesses ${providerPhrase} resources (score ${cloudBlastScore}/100, ${cloudRiskTier})${riskPhrase}`
}

// ---------------------------------------------------------------------------
// Core computation
// ---------------------------------------------------------------------------

/**
 * Compute the multi-cloud blast radius from an SBOM component list.
 * Pure function — no async, no DB calls, O(n) where n = components.length.
 */
export function computeCloudBlastRadius(input: CloudBlastRadiusInput): CloudBlastRadiusResult {
  const { components, repositoryName } = input

  // Deduplicated resource map: "provider:resourceType" → CloudResourceResult
  const resourceMap = new Map<string, CloudResourceResult>()
  // Detected providers (deduplicated)
  const providerSet = new Set<Provider>()

  for (const component of components) {
    const name = component.name.trim()

    // Try exact SDK match first — provides both provider and resource hints
    const sdkEntry = SDK_MAP[name]
    if (sdkEntry) {
      providerSet.add(sdkEntry.provider)
      for (const resourceType of sdkEntry.resources) {
        const key = `${sdkEntry.provider}:${resourceType}`
        if (!resourceMap.has(key)) {
          resourceMap.set(key, {
            provider: sdkEntry.provider,
            resourceType,
            sensitivityScore: SENSITIVITY_SCORE[resourceType] ?? 0,
            label: resourceLabel(resourceType),
          })
        }
      }
      continue
    }

    // Fallback: prefix-based provider detection (provider only, no resource hints)
    const prefixProvider = detectProviderByPrefix(name)
    if (prefixProvider) {
      providerSet.add(prefixProvider)
    }
  }

  const providers = [...providerSet] as Provider[]
  const reachableCloudResources = [...resourceMap.values()]

  // Critical resource count: sensitivityScore >= 80
  const criticalResourceCount = reachableCloudResources.filter(
    (r) => r.sensitivityScore >= 80,
  ).length

  // Risk flags derived from detected resource types
  const resourceTypes = new Set(reachableCloudResources.map((r) => r.resourceType))

  const iamEscalationRisk =
    resourceTypes.has('iam') ||
    resourceTypes.has('managed_identity') ||
    resourceTypes.has('entra_id')

  const secretsAccessRisk =
    resourceTypes.has('secrets_manager') ||
    resourceTypes.has('kms') ||
    resourceTypes.has('secret_manager') ||
    resourceTypes.has('key_vault')

  const dataExfiltrationRisk =
    resourceTypes.has('rds') ||
    resourceTypes.has('spanner') ||
    resourceTypes.has('bigquery') ||
    resourceTypes.has('dynamodb') ||
    resourceTypes.has('cosmosdb') ||
    resourceTypes.has('firestore') ||
    resourceTypes.has('s3') ||
    resourceTypes.has('gcs') ||
    resourceTypes.has('blob_storage')

  const lateralMovementRisk =
    resourceTypes.has('lambda') ||
    resourceTypes.has('ec2') ||
    resourceTypes.has('sqs') ||
    resourceTypes.has('pubsub') ||
    resourceTypes.has('service_bus') ||
    resourceTypes.has('queue_storage') ||
    resourceTypes.has('sns')

  // Base score: max sensitivity across all detected resources
  const maxSensitivity =
    reachableCloudResources.length > 0
      ? Math.max(...reachableCloudResources.map((r) => r.sensitivityScore))
      : 0

  // Apply bonus modifiers
  let cloudBlastScore = maxSensitivity
  if (providers.length > 1) cloudBlastScore += 10
  if (iamEscalationRisk) cloudBlastScore += 15
  if (secretsAccessRisk) cloudBlastScore += 10
  if (dataExfiltrationRisk) cloudBlastScore += 5

  cloudBlastScore = Math.min(Math.max(cloudBlastScore, 0), 100)

  const cloudRiskTier = scoreToCloudRiskTier(cloudBlastScore)

  const cloudSummary = buildCloudSummary({
    repositoryName,
    providers,
    iamEscalationRisk,
    secretsAccessRisk,
    cloudBlastScore,
    cloudRiskTier,
  })

  return {
    providers,
    reachableCloudResources,
    criticalResourceCount,
    iamEscalationRisk,
    dataExfiltrationRisk,
    secretsAccessRisk,
    lateralMovementRisk,
    cloudBlastScore,
    cloudRiskTier,
    cloudSummary,
  }
}
