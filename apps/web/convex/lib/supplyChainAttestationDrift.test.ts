/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  isBuildProvenanceException,
  scanSupplyChainAttestationDrift,
} from './supplyChainAttestationDrift'

// ---------------------------------------------------------------------------
// Rule 1: SLSA_PROVENANCE_DRIFT
// ---------------------------------------------------------------------------

describe('SLSA_PROVENANCE_DRIFT detection', () => {
  it('detects slsa-policy.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects .slsa-goreleaser.yml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['.slsa-goreleaser.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects slsa-verifier-config.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-verifier-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects slsa-verification.yml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-verification.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects slsa-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-l3-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects .slsa-*.yml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['.slsa-goreleaser-production.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects yaml in slsa/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['slsa/level3-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects yaml in provenance/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['provenance/verify.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('detects json in .github/slsa/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['.github/slsa/policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('ignores generic policy.yaml outside slsa dirs', () => {
    const r = scanSupplyChainAttestationDrift(['config/policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: SIGSTORE_COSIGN_DRIFT
// ---------------------------------------------------------------------------

describe('SIGSTORE_COSIGN_DRIFT detection', () => {
  it('detects cosign.pub ungated', () => {
    const r = scanSupplyChainAttestationDrift(['cosign.pub'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects cosign.key ungated', () => {
    const r = scanSupplyChainAttestationDrift(['cosign.key'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects cosign-policy.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['cosign-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects fulcio_v1.crt.pem ungated', () => {
    const r = scanSupplyChainAttestationDrift(['fulcio_v1.crt.pem'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects ctfe.pub ungated', () => {
    const r = scanSupplyChainAttestationDrift(['ctfe.pub'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects cosign-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['cosign-prod-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects sigstore-*.json prefix', () => {
    const r = scanSupplyChainAttestationDrift(['sigstore-config-staging.json'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects fulcio-*.pem prefix', () => {
    const r = scanSupplyChainAttestationDrift(['fulcio-root-prod.pem'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects .pem in cosign/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['cosign/trust-root.pem'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('detects yaml in signing-keys/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['signing-keys/policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })

  it('ignores generic key.pub outside cosign dirs', () => {
    const r = scanSupplyChainAttestationDrift(['config/key.pub'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: IN_TOTO_ATTESTATION_DRIFT
// ---------------------------------------------------------------------------

describe('IN_TOTO_ATTESTATION_DRIFT detection', () => {
  it('detects root.layout ungated', () => {
    const r = scanSupplyChainAttestationDrift(['root.layout'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects root.layout.template ungated', () => {
    const r = scanSupplyChainAttestationDrift(['root.layout.template'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects in-toto-policy.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['in-toto-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects in-toto-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['in-toto-verify-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects *.link files', () => {
    const r = scanSupplyChainAttestationDrift(['build_step.776a00ab.link'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects *.layout files', () => {
    const r = scanSupplyChainAttestationDrift(['root-layout-v2.layout'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects json in in-toto/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['in-toto/metadata.json'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects yaml in .in-toto/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['.in-toto/policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'IN_TOTO_ATTESTATION_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: SUPPLY_CHAIN_BUILD_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('SUPPLY_CHAIN_BUILD_POLICY_DRIFT detection', () => {
  it('detects supply-chain-policy.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['supply-chain-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects ssdf-policy.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['ssdf-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects scorecard-policy.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['scorecard-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects build-integrity-policy.yml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['build-integrity-policy.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects supply-chain-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['supply-chain-requirements.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects ssdf-*.json prefix', () => {
    const r = scanSupplyChainAttestationDrift(['ssdf-compliance.json'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects yaml in supply-chain/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['supply-chain/requirements.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })

  it('detects json in openssf/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['openssf/scorecard.json'])
    expect(r.findings.some((f) => f.ruleId === 'SUPPLY_CHAIN_BUILD_POLICY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: ARTIFACT_SIGNING_DRIFT
// ---------------------------------------------------------------------------

describe('ARTIFACT_SIGNING_DRIFT detection', () => {
  it('detects signing-config.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['signing-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })

  it('detects release-signing.yml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['release-signing.yml'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })

  it('detects gpg-signing-key.asc ungated', () => {
    const r = scanSupplyChainAttestationDrift(['gpg-signing-key.asc'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })

  it('detects signing-config-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['signing-config-prod.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })

  it('detects release-signing-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['release-signing-npm.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })

  it('detects asc files in signing/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['signing/release.asc'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })

  it('detects xml in release-signing/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['release-signing/maven.xml'])
    expect(r.findings.some((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: SBOM_ATTESTATION_DRIFT
// ---------------------------------------------------------------------------

describe('SBOM_ATTESTATION_DRIFT detection', () => {
  it('detects sbom-attestation.json ungated', () => {
    const r = scanSupplyChainAttestationDrift(['sbom-attestation.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects sbom.cdx.json ungated', () => {
    const r = scanSupplyChainAttestationDrift(['sbom.cdx.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects sbom.spdx ungated', () => {
    const r = scanSupplyChainAttestationDrift(['sbom.spdx'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects syft-sbom.json ungated', () => {
    const r = scanSupplyChainAttestationDrift(['syft-sbom.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects sbom-*.json prefix', () => {
    const r = scanSupplyChainAttestationDrift(['sbom-release-1.0.0.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects cyclonedx-*.json prefix', () => {
    const r = scanSupplyChainAttestationDrift(['cyclonedx-bom.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects spdx-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['spdx-bom.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects json in sbom/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['sbom/release.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })

  it('detects json in attestations/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['attestations/sbom-v1.2.json'])
    expect(r.findings.some((f) => f.ruleId === 'SBOM_ATTESTATION_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: REKOR_TRANSPARENCY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('REKOR_TRANSPARENCY_CONFIG_DRIFT detection', () => {
  it('detects rekor.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['rekor.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })

  it('detects rekor-config.yml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['rekor-config.yml'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })

  it('detects transparency-log.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['transparency-log.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })

  it('detects rekor-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['rekor-private-instance.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })

  it('detects tlog-*.json prefix', () => {
    const r = scanSupplyChainAttestationDrift(['tlog-config.json'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })

  it('detects yaml in rekor/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['rekor/shard-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })

  it('detects yaml in transparency-log/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['transparency-log/config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'REKOR_TRANSPARENCY_CONFIG_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: BUILD_PROVENANCE_EXCEPTION_DRIFT — exported
// ---------------------------------------------------------------------------

describe('BUILD_PROVENANCE_EXCEPTION_DRIFT detection', () => {
  it('detects provenance-exception.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['provenance-exception.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects attestation-skip.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['attestation-skip.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects slsa-bypass.yml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-bypass.yml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects cosign-skip.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['cosign-skip.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects supply-chain-exception.yaml ungated', () => {
    const r = scanSupplyChainAttestationDrift(['supply-chain-exception.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects provenance-exception-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['provenance-exception-legacy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects slsa-bypass-*.yaml prefix', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-bypass-dev-builds.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects yaml in provenance-exceptions/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['provenance-exceptions/legacy-pipeline.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('detects json in supply-chain/exceptions/ directory', () => {
    const r = scanSupplyChainAttestationDrift(['supply-chain/exceptions/nightly.json'])
    expect(r.findings.some((f) => f.ruleId === 'BUILD_PROVENANCE_EXCEPTION_DRIFT')).toBe(true)
  })

  it('isBuildProvenanceException: matches ungated slsa-bypass.yaml', () => {
    expect(isBuildProvenanceException('slsa-bypass.yaml', 'slsa-bypass.yaml')).toBe(true)
  })

  it('isBuildProvenanceException: matches cosign-skip-*.yaml prefix', () => {
    expect(isBuildProvenanceException('cosign-skip-test.yaml', 'cosign-skip-test.yaml')).toBe(true)
  })

  it('isBuildProvenanceException: matches yaml in attestation-exceptions/ dir', () => {
    expect(isBuildProvenanceException('attestation-exceptions/nightly.yaml', 'nightly.yaml')).toBe(true)
  })

  it('isBuildProvenanceException: rejects generic exception.yaml outside exception dirs', () => {
    expect(isBuildProvenanceException('config/exception.yaml', 'exception.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns riskLevel=none and riskScore=0 for empty input', () => {
    const r = scanSupplyChainAttestationDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('single high finding scores 15 → riskLevel=medium', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-policy.yaml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('single medium finding scores 8 → riskLevel=low', () => {
    const r = scanSupplyChainAttestationDrift(['signing-config.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('single low finding scores 4 → riskLevel=low', () => {
    const r = scanSupplyChainAttestationDrift(['provenance-exception.yaml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('two high findings score 30 → riskLevel=medium', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-policy.yaml', 'cosign.pub'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('three high findings score 45 → riskLevel=high', () => {
    const r = scanSupplyChainAttestationDrift([
      'slsa-policy.yaml',
      'cosign.pub',
      'root.layout',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('all 8 rules triggered scores 88 → riskLevel=critical', () => {
    const r = scanSupplyChainAttestationDrift([
      'slsa-policy.yaml',          // SLSA_PROVENANCE_DRIFT              H +15
      'cosign.pub',                // SIGSTORE_COSIGN_DRIFT              H +15
      'root.layout',               // IN_TOTO_ATTESTATION_DRIFT          H +15
      'supply-chain-policy.yaml',  // SUPPLY_CHAIN_BUILD_POLICY_DRIFT    H +15
      'signing-config.yaml',       // ARTIFACT_SIGNING_DRIFT             M +8
      'sbom-attestation.json',     // SBOM_ATTESTATION_DRIFT             M +8
      'rekor.yaml',                // REKOR_TRANSPARENCY_CONFIG_DRIFT    M +8
      'provenance-exception.yaml', // BUILD_PROVENANCE_EXCEPTION_DRIFT   L +4
    ])
    expect(r.riskScore).toBe(88)
    expect(r.riskLevel).toBe('critical')
  })

  it('riskScore is capped at 100 when total exceeds 100', () => {
    const many = Array.from({ length: 20 }, (_, i) => `slsa-policy-${i}.yaml`)
    const r = scanSupplyChainAttestationDrift(many)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Per-rule deduplication
// ---------------------------------------------------------------------------

describe('per-rule deduplication', () => {
  it('multiple SLSA files still score only 15 for that rule', () => {
    const r = scanSupplyChainAttestationDrift([
      'slsa-policy.yaml',
      'slsa-l3-policy.yaml',
      '.slsa-goreleaser.yml',
    ])
    const finding = r.findings.find((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')
    expect(finding?.matchCount).toBe(3)
    expect(r.riskScore).toBe(15)
  })

  it('multiple cosign files still score only 15 for that rule', () => {
    const r = scanSupplyChainAttestationDrift([
      'cosign.pub',
      'cosign.key',
      'cosign-policy.yaml',
    ])
    const finding = r.findings.find((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')
    expect(finding?.matchCount).toBe(3)
    expect(r.riskScore).toBe(15)
  })

  it('matchedPath is the first matched file', () => {
    const r = scanSupplyChainAttestationDrift([
      'signing-config.yaml',
      'signing-config-prod.yaml',
    ])
    const finding = r.findings.find((f) => f.ruleId === 'ARTIFACT_SIGNING_DRIFT')
    expect(finding?.matchedPath).toBe('signing-config.yaml')
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('vendor path exclusion', () => {
  it('ignores SLSA config under node_modules/', () => {
    const r = scanSupplyChainAttestationDrift(['node_modules/pkg/slsa-policy.yaml'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores cosign.pub under vendor/', () => {
    const r = scanSupplyChainAttestationDrift(['vendor/cosign/cosign.pub'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores sbom files under dist/', () => {
    const r = scanSupplyChainAttestationDrift(['dist/sbom-attestation.json'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('path normalisation', () => {
  it('normalises Windows backslashes', () => {
    const r = scanSupplyChainAttestationDrift(['slsa\\level3-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SLSA_PROVENANCE_DRIFT')).toBe(true)
  })

  it('normalises leading ./', () => {
    const r = scanSupplyChainAttestationDrift(['./cosign.pub'])
    expect(r.findings.some((f) => f.ruleId === 'SIGSTORE_COSIGN_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('returns clean summary for no findings', () => {
    const r = scanSupplyChainAttestationDrift([])
    expect(r.summary).toBe('No supply chain build integrity or attestation configuration drift detected.')
  })

  it('summary mentions risk score and level for findings', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-policy.yaml'])
    expect(r.summary).toContain('15/100')
    expect(r.summary).toContain('medium')
  })

  it('summary uses plural "findings" when multiple rules fire', () => {
    const r = scanSupplyChainAttestationDrift(['slsa-policy.yaml', 'cosign.pub'])
    expect(r.summary).toContain('findings')
  })

  it('counts are correct for mixed-severity batch', () => {
    const r = scanSupplyChainAttestationDrift([
      'slsa-policy.yaml',
      'signing-config.yaml',
      'provenance-exception.yaml',
    ])
    expect(r.highCount).toBe(1)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(3)
  })
})
