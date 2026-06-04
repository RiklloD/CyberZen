import { normalizePackageName, uniqueStrings } from './breachMatching'

export type SemanticFingerprintInventoryComponent = {
  name: string
  sourceFile: string
  dependents: string[]
}

export type SemanticFingerprintMatch = {
  fingerprintId: string
  vulnClass: string
  title: string
  summary: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  confidence: number
  matchedFiles: string[]
  affectedPackages: string[]
  affectedServices: string[]
  blastRadiusSummary: string
}

type FingerprintDefinition = {
  fingerprintId: string
  vulnClass: string
  severity: SemanticFingerprintMatch['severity']
  confidence: number
  fileMatchers: RegExp[]
  packageMatchers: RegExp[]
  title: (repositoryName: string) => string
  summary: (args: {
    repositoryName: string
    matchedFiles: string[]
    affectedPackages: string[]
  }) => string
  blastRadiusSummary: (args: {
    repositoryName: string
    matchedFiles: string[]
    affectedServices: string[]
  }) => string
}

const fingerprints: FingerprintDefinition[] = [
  {
    fingerprintId: 'SVF-AUTH-001',
    vulnClass: 'jwt_validation_bypass',
    severity: 'high',
    confidence: 0.82,
    fileMatchers: [/(^|\/)(auth|security)\//i, /(jwt|token|oauth|session|credential)/i],
    packageMatchers: [/(jwt|jose|oauth|authlib|passport)/i],
    title: (repositoryName) =>
      `Authentication flow drift may need semantic validation in ${repositoryName}`,
    summary: ({ repositoryName, matchedFiles, affectedPackages }) =>
      `${repositoryName} changed authentication-sensitive paths (${matchedFiles.join(', ')}), which can recreate known token-validation failure patterns.${affectedPackages.length > 0 ? ` Tracked auth packages in scope: ${affectedPackages.join(', ')}.` : ''}`,
    blastRadiusSummary: ({ repositoryName, matchedFiles, affectedServices }) =>
      `${repositoryName} exposed ${matchedFiles.length} authentication-sensitive file path(s).${affectedServices.length > 0 ? ` Downstream services in scope: ${affectedServices.join(', ')}.` : ''}`,
  },
  {
    fingerprintId: 'SVF-LLM-001',
    vulnClass: 'llm_prompt_boundary',
    severity: 'medium',
    confidence: 0.74,
    fileMatchers: [/(prompt|llm|agent|rag|openai|anthropic|completion|chat)/i],
    packageMatchers: [/(openai|anthropic|langchain|llamaindex|ai)/i],
    title: (repositoryName) =>
      `Prompt-boundary drift may require LLM security review in ${repositoryName}`,
    summary: ({ repositoryName, matchedFiles, affectedPackages }) =>
      `${repositoryName} touched prompt or agent-facing paths (${matchedFiles.join(', ')}), which may reintroduce prompt-boundary weaknesses.${affectedPackages.length > 0 ? ` Related AI packages: ${affectedPackages.join(', ')}.` : ''}`,
    blastRadiusSummary: ({ repositoryName, affectedServices }) =>
      `${repositoryName} changed LLM-adjacent code that can affect prompt construction and tool routing.${affectedServices.length > 0 ? ` Impacted services: ${affectedServices.join(', ')}.` : ''}`,
  },
  {
    fingerprintId: 'SVF-DATA-001',
    vulnClass: 'unsafe_deserialization_surface',
    severity: 'high',
    confidence: 0.76,
    fileMatchers: [/(serialize|deserialize|marshal|unmarshal|pickle|yaml|parser)/i],
    packageMatchers: [/(pyyaml|ruamel|pickle|marshal|serde)/i],
    title: (repositoryName) =>
      `Parser and deserialization drift may need review in ${repositoryName}`,
    summary: ({ repositoryName, matchedFiles, affectedPackages }) =>
      `${repositoryName} changed parser or deserialization-sensitive paths (${matchedFiles.join(', ')}), which overlap with known unsafe parsing fingerprints.${affectedPackages.length > 0 ? ` Parser packages in scope: ${affectedPackages.join(', ')}.` : ''}`,
    blastRadiusSummary: ({ repositoryName, matchedFiles }) =>
      `${repositoryName} changed ${matchedFiles.length} parser-oriented file path(s), increasing the chance of unsafe input handling reaching runtime code paths.`,
  },
]

function findAffectedPackages(
  packageMatchers: RegExp[],
  inventoryComponents: SemanticFingerprintInventoryComponent[],
) {
  return uniqueStrings(
    inventoryComponents
      .map((component) => component.name)
      .filter((name) =>
        packageMatchers.some((matcher) => matcher.test(normalizePackageName(name))),
      ),
  )
}

function findAffectedServices(
  packageMatchers: RegExp[],
  inventoryComponents: SemanticFingerprintInventoryComponent[],
  repositoryName: string,
) {
  const dependentServices = uniqueStrings(
    inventoryComponents
      .filter((component) =>
        packageMatchers.some((matcher) => matcher.test(normalizePackageName(component.name))),
      )
      .flatMap((component) => component.dependents),
  )

  return dependentServices.length > 0 ? dependentServices : [repositoryName]
}

export function matchSemanticFingerprints(args: {
  repositoryName: string
  changedFiles: string[]
  inventoryComponents: SemanticFingerprintInventoryComponent[]
}) {
  const uniqueFiles = uniqueStrings(args.changedFiles)
  const matches: SemanticFingerprintMatch[] = []

  for (const fingerprint of fingerprints) {
    const matchedFiles = uniqueFiles.filter((file) =>
      fingerprint.fileMatchers.some((matcher) => matcher.test(file)),
    )

    if (matchedFiles.length === 0) {
      continue
    }

    const affectedPackages = findAffectedPackages(
      fingerprint.packageMatchers,
      args.inventoryComponents,
    )
    const affectedServices = findAffectedServices(
      fingerprint.packageMatchers,
      args.inventoryComponents,
      args.repositoryName,
    )

    matches.push({
      fingerprintId: fingerprint.fingerprintId,
      vulnClass: fingerprint.vulnClass,
      title: fingerprint.title(args.repositoryName),
      summary: fingerprint.summary({
        repositoryName: args.repositoryName,
        matchedFiles,
        affectedPackages,
      }),
      severity: fingerprint.severity,
      confidence: fingerprint.confidence,
      matchedFiles,
      affectedPackages,
      affectedServices,
      blastRadiusSummary: fingerprint.blastRadiusSummary({
        repositoryName: args.repositoryName,
        matchedFiles,
        affectedServices,
      }),
    })
  }

  return matches
}
