// WS-109 — Supply Chain Build Integrity & Attestation Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to supply chain build integrity and attestation configuration:
// SLSA provenance verification configs and builder definitions, Sigstore/Cosign
// signing key configs and policy files, in-toto layout and link files,
// supply chain build policy documents, artifact release signing configs,
// SBOM attestation files (separate from the SBOM itself), Rekor transparency
// log server configs, and build provenance exception or override records.
//
// Distinct from:
//   WS-66  (cert & PKI: CA configs, certificate lifecycle, ACME/STEP)
//   WS-73  (CI/CD pipeline: GitHub Actions YAML, Tekton, SLSA provenance
//           generation steps in pipeline — this module covers the *attestation
//           verification policy* side, not the build steps themselves)
//   WS-82  (artifact registry: Nexus/Artifactory/Harbor server configs)
//   WS-105 (secret management: vault.hcl, SOPS encryption rules — not signing)
//   WS-107 (K8s admission: cosign-policy.yaml at deploy-time image gate —
//           this module covers upstream key management and policy docs)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '')
}

const VENDOR_DIRS = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '.cache/',
  'target/', '__pycache__/', '.venv/', 'venv/',
]

function isVendorPath(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Rule 1: SLSA_PROVENANCE_DRIFT (high)
// ---------------------------------------------------------------------------
// SLSA provenance attestation and builder configuration define how build
// artefacts are verified against SLSA levels 1–4.  A weakened SLSA
// verification policy can silently lower the effective supply chain assurance
// without any deployment-side change.

const SLSA_UNGATED = new Set([
  'slsa-verifier-config.yaml', 'slsa-verifier-config.yml',
  'slsa-framework.yaml', 'slsa-framework.yml',
  '.slsa-goreleaser.yml', '.slsa-goreleaser.yaml',
  'slsa-policy.yaml', 'slsa-policy.yml',
  'slsa-verification.yaml', 'slsa-verification.yml',
])

const SLSA_DIRS = [
  'slsa/', '.slsa/', 'slsa-framework/', 'supply-chain/slsa/',
  'attestation/slsa/', 'provenance/', '.github/slsa/',
]

function isSlsaProvenanceConfig(path: string, base: string): boolean {
  if (SLSA_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('slsa-') ||
    base.startsWith('.slsa-') ||
    base.startsWith('provenance-policy-')
  ) {
    return /\.(yaml|yml|json|toml)$/.test(base)
  }

  return SLSA_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: SIGSTORE_COSIGN_DRIFT (high)
// ---------------------------------------------------------------------------
// Sigstore/Cosign signing key policies and public key material define which
// keys are trusted to sign artefacts.  Replacing or adding a cosign public
// key silently changes the trust anchor for every image that references it;
// a weakened policy.yaml can allow unsigned images to pass the gate.

const COSIGN_UNGATED = new Set([
  'cosign.pub', 'cosign.key',
  'cosign-policy.yaml', 'cosign-policy.yml',
  '.cosign-policy.yaml', '.cosign-policy.yml',
  'sigstore-config.yaml', 'sigstore-config.yml',
  'fulcio_v1.crt.pem', 'fulcio-root.pem',
  'ctfe.pub',
])

const COSIGN_DIRS = [
  'cosign/', '.cosign/', 'sigstore/', 'signing-keys/',
  'supply-chain/cosign/', 'attestation/cosign/', '.github/cosign/',
]

function isSigstoreCosignConfig(path: string, base: string): boolean {
  if (COSIGN_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('cosign-') ||
    base.startsWith('sigstore-') ||
    base.startsWith('fulcio-') ||
    base.startsWith('rekor-root-')
  ) {
    return /\.(yaml|yml|json|pem|pub|key|crt)$/.test(base)
  }

  return COSIGN_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|pem|pub|key|crt|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: IN_TOTO_ATTESTATION_DRIFT (high)
// ---------------------------------------------------------------------------
// in-toto root.layout and link metadata files define the supply chain steps
// that must be carried out by authorised functionaries.  Modifying a layout
// can drop required steps (e.g. remove the lint or sign step) or change the
// set of trusted functionary keys, undermining end-to-end provenance.

const INTOTO_UNGATED = new Set([
  'root.layout',
  'root.layout.template',
  'in-toto.yaml', 'in-toto.yml',
  'in-toto-policy.yaml', 'in-toto-policy.yml',
])

const INTOTO_DIRS = [
  'in-toto/', '.in-toto/', 'in_toto/', 'attestation/in-toto/',
  'supply-chain/in-toto/', 'provenance/in-toto/',
]

function isInTotoAttestationConfig(path: string, base: string): boolean {
  if (INTOTO_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('in-toto-') ||
    base.startsWith('intoto-') ||
    base.endsWith('.link') ||
    base.endsWith('.layout')
  ) {
    return /\.(yaml|yml|json|link|layout)$/.test(base) ||
      base.endsWith('.link') || base.endsWith('.layout')
  }

  return INTOTO_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|link|layout)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: SUPPLY_CHAIN_BUILD_POLICY_DRIFT (high)
// ---------------------------------------------------------------------------
// Supply chain security policy documents define the organisational requirements
// for build integrity, provenance, and artefact verification.  These include
// NIST SSDF policy mapping files, OpenSSF Scorecard enforcement configs, and
// custom supply chain security requirement documents.

const SC_POLICY_UNGATED = new Set([
  'supply-chain-policy.yaml', 'supply-chain-policy.yml',
  'ssdf-policy.yaml', 'ssdf-policy.yml',
  'scorecard-policy.yaml', 'scorecard-policy.yml',
  'openssf-policy.yaml', 'openssf-policy.yml',
  'build-integrity-policy.yaml', 'build-integrity-policy.yml',
  'artifact-policy.yaml', 'artifact-policy.yml',
])

const SC_POLICY_DIRS = [
  'supply-chain/', 'supply-chain-security/', 'ssdf/', 'openssf/',
  'build-policy/', 'artifact-policy/', 'security-policy/',
]

function isSupplyChainBuildPolicy(path: string, base: string): boolean {
  if (SC_POLICY_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('supply-chain-') ||
    base.startsWith('ssdf-') ||
    base.startsWith('scorecard-') ||
    base.startsWith('build-integrity-') ||
    base.startsWith('artifact-policy-')
  ) {
    return /\.(yaml|yml|json|toml)$/.test(base)
  }

  return SC_POLICY_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: ARTIFACT_SIGNING_DRIFT (medium)
// ---------------------------------------------------------------------------
// Release signing configurations govern which GPG/PGP keys sign published
// packages, Maven release keys, and npm publish signatures.  Rotating to an
// untrusted key or disabling signing on a release pipeline removes the
// integrity guarantee for downstream consumers.

const SIGNING_UNGATED = new Set([
  '.gnupg-config', 'signing-config.yaml', 'signing-config.yml',
  'gpg-signing-key.asc', 'release-signing.yaml', 'release-signing.yml',
  'npm-signing.json', 'maven-signing.xml',
])

const SIGNING_DIRS = [
  'signing/', 'release-signing/', 'gpg-keys/', '.gnupg/',
  'pgp-keys/', 'artifact-signing/', 'release-keys/',
]

function isArtifactSigningConfig(path: string, base: string): boolean {
  if (SIGNING_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('signing-config-') ||
    base.startsWith('release-signing-') ||
    base.startsWith('gpg-signing-') ||
    base.startsWith('artifact-signing-')
  ) {
    return /\.(yaml|yml|json|xml|asc|gpg)$/.test(base)
  }

  return SIGNING_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|xml|asc|gpg|toml|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: SBOM_ATTESTATION_DRIFT (medium)
// ---------------------------------------------------------------------------
// SBOM attestation files (CycloneDX/SPDX attestation envelopes, Syft/Grype
// SBOM output committed to the repo as a provenance artefact) record the
// components that were present at build time.  Modifying or replacing the
// committed SBOM breaks the verifiable chain from build to deployment.

const SBOM_ATTEST_UNGATED = new Set([
  'sbom-attestation.json', 'sbom-attestation.yaml', 'sbom-attestation.yml',
  'sbom.spdx', 'sbom.cdx.json', 'sbom.cyclonedx.json',
  'syft-sbom.json', 'grype-report.json',
  'sbom.spdx.json', 'sbom.spdx.yaml',
])

const SBOM_ATTEST_DIRS = [
  'sbom/', 'sbom-attestations/', 'attestations/', 'provenance/sbom/',
  'supply-chain/sbom/', 'build-attestations/',
]

function isSbomAttestationFile(path: string, base: string): boolean {
  if (SBOM_ATTEST_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('sbom-') ||
    base.startsWith('syft-') ||
    base.startsWith('grype-') ||
    base.startsWith('cyclonedx-') ||
    base.startsWith('spdx-')
  ) {
    return /\.(json|yaml|yml|xml|spdx)$/.test(base)
  }

  return SBOM_ATTEST_DIRS.some((d) => low.includes(d)) &&
    /\.(json|yaml|yml|xml|spdx)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: REKOR_TRANSPARENCY_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------
// Rekor is the Sigstore transparency log; its server configuration defines
// the log shards, signing keys, and acceptable entry types.  A private or
// modified Rekor instance can silently accept invalid provenance records
// without anyone noticing, breaking append-only audit guarantees.

const REKOR_UNGATED = new Set([
  'rekor.yaml', 'rekor.yml', 'rekor-config.yaml', 'rekor-config.yml',
  'rekor_config.yaml', 'rekor_config.yml',
  'transparency-log.yaml', 'transparency-log.yml',
])

const REKOR_DIRS = [
  'rekor/', '.rekor/', 'transparency-log/', 'sigstore/rekor/',
  'supply-chain/rekor/', 'attestation/rekor/',
]

function isRekorTransparencyConfig(path: string, base: string): boolean {
  if (REKOR_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('rekor-') ||
    base.startsWith('rekor_') ||
    base.startsWith('transparency-log-') ||
    base.startsWith('tlog-')
  ) {
    return /\.(yaml|yml|json|toml)$/.test(base)
  }

  return REKOR_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json|toml|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: BUILD_PROVENANCE_EXCEPTION_DRIFT (low) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures a build provenance exception, bypass,
// or allowlist override: SLSA policy exceptions, cosign verification skips,
// in-toto step bypasses, or supply chain policy override documents.
// Exceptions exist to handle legitimate cases but drift here can silently
// extend bypasses to additional artefacts or pipelines.
//
// Trade-offs to consider:
//   - "exceptions/" dir is shared with K8s admission (WS-107) and other
//     tools — require a build-provenance-specific dir or a specific filename
//   - "attestation-skip" is fairly distinctive
//   - Generic "bypass.yaml" or "exception.yaml" require directory context

const PROV_EXCEPTION_UNGATED = new Set([
  'provenance-exception.yaml', 'provenance-exception.yml',
  'attestation-skip.yaml', 'attestation-skip.yml',
  'slsa-bypass.yaml', 'slsa-bypass.yml',
  'cosign-skip.yaml', 'cosign-skip.yml',
  'supply-chain-exception.yaml', 'supply-chain-exception.yml',
  'build-attestation-exception.yaml', 'build-attestation-exception.yml',
])

const PROV_EXCEPTION_DIRS = [
  'provenance-exceptions/', 'attestation-exceptions/', 'slsa-exceptions/',
  'supply-chain/exceptions/', 'build-exceptions/', 'signing-exceptions/',
]

export function isBuildProvenanceException(path: string, base: string): boolean {
  if (PROV_EXCEPTION_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('provenance-exception-') ||
    base.startsWith('attestation-skip-') ||
    base.startsWith('slsa-bypass-') ||
    base.startsWith('cosign-skip-') ||
    base.startsWith('supply-chain-exception-') ||
    base.startsWith('build-provenance-exception-')
  ) {
    return /\.(yaml|yml|json)$/.test(base)
  }

  return PROV_EXCEPTION_DIRS.some((d) => low.includes(d)) &&
    /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type SupplyChainAttestationDriftRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: SupplyChainAttestationDriftRule[] = [
  {
    id: 'SLSA_PROVENANCE_DRIFT',
    severity: 'high',
    description: 'SLSA provenance verification configuration or builder policy modified.',
    recommendation: 'Confirm the SLSA level requirement has not been downgraded; verify that builder signing keys and expected digests have not changed; check that the verification policy still requires provenance for all production artefacts and not only a subset.',
    match: isSlsaProvenanceConfig,
  },
  {
    id: 'SIGSTORE_COSIGN_DRIFT',
    severity: 'high',
    description: 'Sigstore/Cosign signing key or policy file modified.',
    recommendation: 'Audit which cosign public keys were added or replaced; a new key silently trusts any image signed by the corresponding private key; verify fulcio root certificate and ctfe public key changes against the official Sigstore TUF root; ensure policy still requires signature for all production namespaces.',
    match: isSigstoreCosignConfig,
  },
  {
    id: 'IN_TOTO_ATTESTATION_DRIFT',
    severity: 'high',
    description: 'in-toto root layout or attestation link file modified.',
    recommendation: 'Diff the layout for removed or weakened steps; confirm that functionary key thresholds have not been lowered; verify that all required supply chain steps (source fetch, lint, build, sign, deploy) are still present and ordered correctly.',
    match: isInTotoAttestationConfig,
  },
  {
    id: 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT',
    severity: 'high',
    description: 'Supply chain build integrity or SSDF/OpenSSF policy document modified.',
    recommendation: 'Review changes for any reduction in required SLSA level, new artefact exclusions, or relaxed provenance requirements; validate OpenSSF Scorecard thresholds remain at or above policy baseline; confirm that updated policy has been approved through the security review process.',
    match: isSupplyChainBuildPolicy,
  },
  {
    id: 'ARTIFACT_SIGNING_DRIFT',
    severity: 'medium',
    description: 'Artifact release signing configuration or GPG key reference modified.',
    recommendation: 'Verify the signing key used for published packages has not been changed without a documented key rotation event; confirm the new key appears in the project\'s published keyring; check that signing is not disabled for any release pipeline that pushes to public package registries.',
    match: isArtifactSigningConfig,
  },
  {
    id: 'SBOM_ATTESTATION_DRIFT',
    severity: 'medium',
    description: 'Committed SBOM attestation or CycloneDX/SPDX artefact file modified.',
    recommendation: 'Compare the modified SBOM against the last known-good version for unexpected package additions, version downgrades, or hash mismatches; a modified committed SBOM breaks the verifiable chain between build and deployment; confirm re-generation was triggered by a legitimate dependency update.',
    match: isSbomAttestationFile,
  },
  {
    id: 'REKOR_TRANSPARENCY_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Rekor transparency log server configuration modified.',
    recommendation: 'Verify the Rekor instance URL still points to the public or approved private log; check that shard signing keys have not changed; confirm that the log entry types accepted by the policy still include the required intoto/hashedrekord/cosign types.',
    match: isRekorTransparencyConfig,
  },
  {
    id: 'BUILD_PROVENANCE_EXCEPTION_DRIFT',
    severity: 'low',
    description: 'Build provenance exception, attestation bypass, or supply chain policy override modified.',
    recommendation: 'Audit which artefacts, pipelines, or namespaces were added to the exception list; confirm each exception is time-bounded and has a documented justification; verify that SLSA bypass scope is limited to development builds and does not cover production release pipelines.',
    match: isBuildProvenanceException,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP: Record<Severity, number>     = { high: 45, medium: 25, low: 15 }

function computeRiskLevel(score: number): SupplyChainAttestationDriftResult['riskLevel'] {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type SupplyChainAttestationDriftFinding = {
  ruleId: string
  severity: Severity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type SupplyChainAttestationDriftResult = {
  riskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none'
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: SupplyChainAttestationDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// scanSupplyChainAttestationDrift
// ---------------------------------------------------------------------------

export function scanSupplyChainAttestationDrift(
  changedFiles: string[],
): SupplyChainAttestationDriftResult {
  const normalised = changedFiles
    .map(normalise)
    .filter((p) => !isVendorPath(p))

  const findings: SupplyChainAttestationDriftFinding[] = []
  const perRuleScore: Record<string, number> = {}

  for (const rule of RULES) {
    const matched: string[] = []

    for (const p of normalised) {
      const base = p.split('/').pop() ?? p
      if (rule.match(p, base)) {
        matched.push(p)
      }
    }

    if (matched.length === 0) continue

    const penalty = SEVERITY_PENALTY[rule.severity]
    const cap     = SEVERITY_CAP[rule.severity]
    perRuleScore[rule.id] = Math.min(penalty, cap)

    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    matched[0],
      matchCount:     matched.length,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  const totalScore = Math.min(
    Object.values(perRuleScore).reduce((a, b) => a + b, 0),
    100,
  )

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const riskLevel = computeRiskLevel(totalScore)

  let summary: string
  if (findings.length === 0) {
    summary = 'No supply chain build integrity or attestation configuration drift detected.'
  } else {
    const parts: string[] = []
    if (highCount > 0)   parts.push(`${highCount} high`)
    if (mediumCount > 0) parts.push(`${mediumCount} medium`)
    if (lowCount > 0)    parts.push(`${lowCount} low`)
    summary = `Supply chain attestation drift detected: ${parts.join(', ')} severity finding${findings.length > 1 ? 's' : ''}. Risk score ${totalScore}/100 (${riskLevel}).`
  }

  return {
    riskScore:     totalScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
