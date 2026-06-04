/**
 * WS-46 — Compliance Attestation Report: pure computation library.
 *
 * Maps outputs from all Sentinel supply-chain and security scanners to
 * per-framework regulatory control checks across:
 *   SOC 2 Trust Services Criteria (CC6.1 / CC6.6 / CC6.7 / CC7.1 / CC7.2 / CC8.1 / CC9.2)
 *   GDPR (Art. 25 / Art. 32 / Art. 33-34)
 *   PCI-DSS 4.0 (Req 6.2 / 6.3 / 6.5 / 11.3)
 *   HIPAA Technical Safeguards (§164.312 a/c/e)
 *   NIS2 Art. 21 (sub-provisions b/e/h/i/j)
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const COMPLIANCE_FRAMEWORKS = ['soc2', 'gdpr', 'pci_dss', 'hipaa', 'nis2'] as const
export type ComplianceFramework = (typeof COMPLIANCE_FRAMEWORKS)[number]

export const FRAMEWORK_LABELS: Record<ComplianceFramework, string> = {
  soc2: 'SOC 2 Type II',
  gdpr: 'GDPR',
  pci_dss: 'PCI-DSS 4.0',
  hipaa: 'HIPAA',
  nis2: 'NIS2',
}

export type GapSeverity = 'critical' | 'high' | 'medium' | 'low'
export type FrameworkStatus = 'compliant' | 'at_risk' | 'non_compliant'

/** Score penalty per gap severity (subtracted from 100). */
export const GAP_PENALTIES: Record<GapSeverity, number> = {
  critical: 20,
  high: 12,
  medium: 6,
  low: 3,
}

/**
 * A framework is 'compliant' when score >= this AND no critical/high gaps.
 * Below this threshold (but no critical gaps) = 'at_risk'.
 */
export const COMPLIANT_SCORE_THRESHOLD = 75

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ComplianceAttestationInput = {
  // WS-30 — Secret Detection (push-event scanner)
  secretCriticalCount: number
  secretHighCount: number
  // WS-37 — Cryptography Weakness Detector
  cryptoRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  cryptoCriticalCount: number
  cryptoHighCount: number
  // WS-38 — Dependency & Runtime EOL Detection
  eolStatus: 'critical' | 'warning' | 'ok' | 'none'
  eolCriticalCount: number // = eolCount (components past EOL)
  // WS-39 — Open-Source Package Abandonment Detector
  abandonmentRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  abandonmentCriticalCount: number
  // WS-40 — SBOM Attestation
  attestationStatus: 'valid' | 'tampered' | 'unverified' | 'none'
  // WS-41 — Dependency Confusion Attack Detector
  confusionRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  confusionCriticalCount: number
  // WS-42 — Malicious Package Detection
  maliciousRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  maliciousCriticalCount: number
  // WS-43 — Known CVE Version Range Scanner
  cveRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  cveCriticalCount: number
  cveHighCount: number
  // WS-32 — SBOM Quality & Completeness Scoring
  sbomGrade: 'excellent' | 'good' | 'fair' | 'poor' | 'unknown'
  // WS-33 — IaC Security Scanner
  iacRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  iacCriticalCount: number
  // WS-35 — CI/CD Pipeline Security Scanner
  cicdRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  cicdCriticalCount: number
  // WS-45 — Container Image Security Analyzer
  containerRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  containerCriticalCount: number
}

export type ControlGap = {
  controlId: string
  controlName: string
  gapSeverity: GapSeverity
  description: string
}

export type FrameworkAttestation = {
  framework: ComplianceFramework
  label: string
  status: FrameworkStatus
  score: number
  criticalGaps: number
  highGaps: number
  controlGaps: ControlGap[]
  summary: string
}

export type ComplianceAttestationResult = {
  frameworks: FrameworkAttestation[]
  overallStatus: FrameworkStatus
  criticalGapCount: number
  highGapCount: number
  fullyCompliantCount: number
  summary: string
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type ControlCheckFn = (input: ComplianceAttestationInput) => ControlGap | null

type ControlDef = {
  controlId: string
  controlName: string
  check: ControlCheckFn
}

function buildGap(
  controlId: string,
  controlName: string,
  gapSeverity: GapSeverity,
  description: string,
): ControlGap {
  return { controlId, controlName, gapSeverity, description }
}

function computeFrameworkScore(gaps: ControlGap[]): number {
  const penalty = gaps.reduce((sum, g) => sum + GAP_PENALTIES[g.gapSeverity], 0)
  return Math.max(0, 100 - penalty)
}

function deriveFrameworkStatus(score: number, criticalGaps: number, highGaps: number): FrameworkStatus {
  if (criticalGaps > 0) return 'non_compliant'
  if (highGaps > 0 || score < COMPLIANT_SCORE_THRESHOLD) return 'at_risk'
  return 'compliant'
}

function buildFrameworkSummary(status: FrameworkStatus, gaps: ControlGap[]): string {
  if (status === 'compliant') return 'All controls assessed — no violations found.'
  const criticals = gaps.filter((g) => g.gapSeverity === 'critical').length
  const highs = gaps.filter((g) => g.gapSeverity === 'high').length
  if (status === 'non_compliant') {
    return `${criticals} critical violation${criticals > 1 ? 's' : ''} require immediate remediation.`
  }
  return `${highs} control${highs > 1 ? 's' : ''} require attention before this framework can be considered compliant.`
}

function evaluateFramework(
  framework: ComplianceFramework,
  controls: ControlDef[],
  input: ComplianceAttestationInput,
): FrameworkAttestation {
  const controlGaps: ControlGap[] = []
  for (const ctrl of controls) {
    const gap = ctrl.check(input)
    if (gap) controlGaps.push(gap)
  }

  const score = computeFrameworkScore(controlGaps)
  const criticalGaps = controlGaps.filter((g) => g.gapSeverity === 'critical').length
  const highGaps = controlGaps.filter((g) => g.gapSeverity === 'high').length
  const status = deriveFrameworkStatus(score, criticalGaps, highGaps)

  return {
    framework,
    label: FRAMEWORK_LABELS[framework],
    status,
    score,
    criticalGaps,
    highGaps,
    controlGaps,
    summary: buildFrameworkSummary(status, controlGaps),
  }
}

// ---------------------------------------------------------------------------
// SOC 2 Trust Services Criteria controls
// ---------------------------------------------------------------------------

const SOC2_CONTROLS: ControlDef[] = [
  {
    controlId: 'CC6.1',
    controlName: 'Logical Access Controls',
    check: (inp) => {
      if (inp.secretCriticalCount > 0)
        return buildGap('CC6.1', 'Logical Access Controls', 'critical',
          'Hardcoded credentials expose logical access controls to bypass.')
      if (inp.secretHighCount > 0)
        return buildGap('CC6.1', 'Logical Access Controls', 'high',
          'High-risk secrets in codebase — review logical access configurations.')
      return null
    },
  },
  {
    controlId: 'CC6.6',
    controlName: 'Logical and Physical Access Security',
    check: (inp) => {
      if (inp.iacCriticalCount > 0)
        return buildGap('CC6.6', 'Logical and Physical Access Security', 'critical',
          'Critical IaC misconfigurations leave the infrastructure security boundary unprotected.')
      if (inp.iacRisk === 'high')
        return buildGap('CC6.6', 'Logical and Physical Access Security', 'high',
          'High-severity IaC vulnerabilities weaken system boundary controls.')
      return null
    },
  },
  {
    controlId: 'CC6.7',
    controlName: 'Encryption and Key Management',
    check: (inp) => {
      if (inp.cryptoCriticalCount > 0)
        return buildGap('CC6.7', 'Encryption and Key Management', 'critical',
          'Broken or deprecated cryptographic algorithms undermine data-at-rest and in-transit protection.')
      if (inp.cryptoHighCount > 0)
        return buildGap('CC6.7', 'Encryption and Key Management', 'high',
          'High-severity cryptographic weaknesses require remediation.')
      return null
    },
  },
  {
    controlId: 'CC7.1',
    controlName: 'System Operations and Vulnerability Management',
    check: (inp) => {
      if (inp.cveCriticalCount > 0)
        return buildGap('CC7.1', 'System Operations and Vulnerability Management', 'critical',
          'Critical known CVEs in production dependencies — active exploitation risk.')
      if (inp.eolStatus === 'critical')
        return buildGap('CC7.1', 'System Operations and Vulnerability Management', 'high',
          'End-of-life runtime components no longer receive security patches.')
      return null
    },
  },
  {
    controlId: 'CC7.2',
    controlName: 'Integrity Monitoring and Non-Conformance Detection',
    check: (inp) => {
      if (inp.attestationStatus === 'tampered')
        return buildGap('CC7.2', 'Integrity Monitoring and Non-Conformance Detection', 'critical',
          'SBOM integrity check failed — build artifact tampered.')
      if (inp.attestationStatus === 'unverified' || inp.attestationStatus === 'none')
        return buildGap('CC7.2', 'Integrity Monitoring and Non-Conformance Detection', 'medium',
          'SBOM attestation not established — artifact integrity unverifiable.')
      return null
    },
  },
  {
    controlId: 'CC8.1',
    controlName: 'Change Management Controls',
    check: (inp) => {
      if (inp.cicdCriticalCount > 0)
        return buildGap('CC8.1', 'Change Management Controls', 'critical',
          'Critical CI/CD pipeline misconfigurations allow unauthorized code changes in the SDLC.')
      if (inp.cicdRisk === 'high')
        return buildGap('CC8.1', 'Change Management Controls', 'high',
          'High-risk CI/CD vulnerabilities in change management pipeline.')
      return null
    },
  },
  {
    controlId: 'CC9.2',
    controlName: 'Risk Management — Vendor and Supply Chain',
    check: (inp) => {
      if (inp.maliciousCriticalCount > 0)
        return buildGap('CC9.2', 'Risk Management — Vendor and Supply Chain', 'critical',
          'Confirmed malicious or backdoored packages in dependency tree.')
      if (inp.confusionCriticalCount > 0)
        return buildGap('CC9.2', 'Risk Management — Vendor and Supply Chain', 'high',
          'Dependency confusion attack vectors detected in package namespacing.')
      if (inp.abandonmentCriticalCount > 0)
        return buildGap('CC9.2', 'Risk Management — Vendor and Supply Chain', 'high',
          'Supply-chain-compromised abandoned packages introduce unresolved security risk.')
      return null
    },
  },
]

// ---------------------------------------------------------------------------
// GDPR controls
// ---------------------------------------------------------------------------

const GDPR_CONTROLS: ControlDef[] = [
  {
    controlId: 'Art.25',
    controlName: 'Data Protection by Design and by Default',
    check: (inp) => {
      if (inp.containerCriticalCount > 0)
        return buildGap('Art.25', 'Data Protection by Design and by Default', 'high',
          'EOL container base images may lack security patches protecting personal data processing.')
      if (inp.cveRisk === 'critical' || inp.cveRisk === 'high')
        return buildGap('Art.25', 'Data Protection by Design and by Default', 'high',
          'Known CVEs in data processing components undermine privacy-by-design obligations.')
      return null
    },
  },
  {
    controlId: 'Art.32',
    controlName: 'Security of Processing',
    check: (inp) => {
      if (inp.cryptoCriticalCount > 0)
        return buildGap('Art.32', 'Security of Processing', 'critical',
          'Broken cryptographic controls violate Art. 32(1)(a) — personal data protection insufficient.')
      if (inp.secretCriticalCount > 0)
        return buildGap('Art.32', 'Security of Processing', 'critical',
          'Hardcoded credentials create direct personal data breach risk under Art. 32.')
      if (inp.cveCriticalCount > 0)
        return buildGap('Art.32', 'Security of Processing', 'critical',
          'Critical vulnerabilities in data processing components violate Art. 32 security measures.')
      if (inp.sbomGrade === 'poor')
        return buildGap('Art.32', 'Security of Processing', 'medium',
          'Poor SBOM quality limits visibility into component security posture for Art. 32 compliance.')
      return null
    },
  },
  {
    controlId: 'Art.33-34',
    controlName: 'Breach Notification Readiness',
    check: (inp) => {
      if (inp.eolStatus === 'critical')
        return buildGap('Art.33-34', 'Breach Notification Readiness', 'high',
          'EOL components with no security patches increase breach probability and Art. 33 notification risk.')
      if (inp.sbomGrade === 'poor' || inp.sbomGrade === 'fair')
        return buildGap('Art.33-34', 'Breach Notification Readiness', 'medium',
          'Incomplete dependency inventory slows breach impact assessment under Art. 33.')
      return null
    },
  },
]

// ---------------------------------------------------------------------------
// PCI-DSS 4.0 controls
// ---------------------------------------------------------------------------

const PCI_DSS_CONTROLS: ControlDef[] = [
  {
    controlId: 'Req.6.2',
    controlName: 'Protect Bespoke and Custom Software',
    check: (inp) => {
      if (inp.cveCriticalCount > 0)
        return buildGap('Req.6.2', 'Protect Bespoke and Custom Software', 'critical',
          'Critical CVEs in application dependencies violate Req 6.2.4 (attack-pattern protection).')
      if (inp.cryptoCriticalCount > 0)
        return buildGap('Req.6.2', 'Protect Bespoke and Custom Software', 'high',
          'Broken cryptographic algorithms violate Req 6.2.4 security requirements.')
      return null
    },
  },
  {
    controlId: 'Req.6.3',
    controlName: 'Protect All System Components from Vulnerabilities',
    check: (inp) => {
      if (inp.eolStatus === 'critical')
        return buildGap('Req.6.3', 'Protect All System Components from Vulnerabilities', 'critical',
          'EOL runtime components cannot receive security patches — violates Req 6.3.3 (patching SLA).')
      if (inp.containerCriticalCount > 0)
        return buildGap('Req.6.3', 'Protect All System Components from Vulnerabilities', 'critical',
          'EOL container images with unpatched OS vulnerabilities — violates Req 6.3.')
      return null
    },
  },
  {
    controlId: 'Req.6.5',
    controlName: 'Security in the Software Development Lifecycle',
    check: (inp) => {
      if (inp.cicdCriticalCount > 0)
        return buildGap('Req.6.5', 'Security in the Software Development Lifecycle', 'high',
          'Critical CI/CD misconfigurations allow unauthorized pipeline changes — violates Req 6.5.')
      if (inp.attestationStatus === 'tampered')
        return buildGap('Req.6.5', 'Security in the Software Development Lifecycle', 'high',
          'SBOM tampering detected — software supply chain integrity compromised under Req 6.5.')
      return null
    },
  },
  {
    controlId: 'Req.11.3',
    controlName: 'Vulnerability Identification and Correction',
    check: (inp) => {
      if (inp.cveHighCount > 0)
        return buildGap('Req.11.3', 'Vulnerability Identification and Correction', 'high',
          'High-severity CVEs require timely remediation per Req 11.3.1.')
      if (inp.sbomGrade === 'poor')
        return buildGap('Req.11.3', 'Vulnerability Identification and Correction', 'medium',
          'Poor SBOM quality limits vulnerability scan coverage per Req 11.3.')
      return null
    },
  },
]

// ---------------------------------------------------------------------------
// HIPAA Technical Safeguards controls
// ---------------------------------------------------------------------------

const HIPAA_CONTROLS: ControlDef[] = [
  {
    controlId: '§164.312(a)(1)',
    controlName: 'Access Control',
    check: (inp) => {
      if (inp.secretCriticalCount > 0)
        return buildGap('§164.312(a)(1)', 'Access Control', 'critical',
          'Hardcoded credentials violate HIPAA Technical Safeguards — Access Control §164.312(a)(1).')
      if (inp.iacCriticalCount > 0)
        return buildGap('§164.312(a)(1)', 'Access Control', 'high',
          'Critical IaC misconfigurations may expose PHI-handling systems to unauthorized access.')
      return null
    },
  },
  {
    controlId: '§164.312(a)(2)(iv)',
    controlName: 'Encryption and Decryption of PHI',
    check: (inp) => {
      if (inp.cryptoCriticalCount > 0)
        return buildGap('§164.312(a)(2)(iv)', 'Encryption and Decryption of PHI', 'critical',
          'Broken cryptographic algorithms violate PHI encryption safeguards §164.312(a)(2)(iv).')
      return null
    },
  },
  {
    controlId: '§164.312(c)(1)',
    controlName: 'Integrity Controls',
    check: (inp) => {
      if (inp.attestationStatus === 'tampered')
        return buildGap('§164.312(c)(1)', 'Integrity Controls', 'critical',
          'SBOM tampering violates HIPAA integrity safeguards §164.312(c)(1).')
      if (inp.sbomGrade === 'poor')
        return buildGap('§164.312(c)(1)', 'Integrity Controls', 'medium',
          'Poor SBOM quality undermines software integrity verification capability.')
      return null
    },
  },
  {
    controlId: '§164.312(e)(2)(ii)',
    controlName: 'Encryption of PHI in Transmission',
    check: (inp) => {
      if (inp.cryptoHighCount > 0)
        return buildGap('§164.312(e)(2)(ii)', 'Encryption of PHI in Transmission', 'high',
          'High-severity crypto weaknesses may compromise PHI transmission security §164.312(e)(2)(ii).')
      if (inp.containerCriticalCount > 0)
        return buildGap('§164.312(e)(2)(ii)', 'Encryption of PHI in Transmission', 'medium',
          'EOL container images may expose unpatched TLS/transport vulnerabilities.')
      return null
    },
  },
]

// ---------------------------------------------------------------------------
// NIS2 Art. 21 controls
// ---------------------------------------------------------------------------

const NIS2_CONTROLS: ControlDef[] = [
  {
    controlId: 'Art.21(2)(e)',
    controlName: 'Supply Chain Security',
    check: (inp) => {
      if (inp.maliciousCriticalCount > 0)
        return buildGap('Art.21(2)(e)', 'Supply Chain Security', 'critical',
          'Malicious/backdoored packages violate NIS2 supply chain security obligations Art. 21(2)(e).')
      if (inp.confusionCriticalCount > 0)
        return buildGap('Art.21(2)(e)', 'Supply Chain Security', 'high',
          'Dependency confusion attack vectors undermine NIS2 supply chain security requirements.')
      if (inp.abandonmentCriticalCount > 0)
        return buildGap('Art.21(2)(e)', 'Supply Chain Security', 'high',
          'Supply-chain-compromised abandoned packages remain unaddressed under Art. 21(2)(e).')
      return null
    },
  },
  {
    controlId: 'Art.21(2)(h)',
    controlName: 'Supply Chain and Procurement Policies',
    check: (inp) => {
      if (inp.containerCriticalCount > 0)
        return buildGap('Art.21(2)(h)', 'Supply Chain and Procurement Policies', 'high',
          'EOL container images violate NIS2 secure procurement obligations Art. 21(2)(h).')
      if (inp.sbomGrade === 'poor')
        return buildGap('Art.21(2)(h)', 'Supply Chain and Procurement Policies', 'medium',
          'Poor SBOM quality insufficient for NIS2 supply chain transparency requirements.')
      return null
    },
  },
  {
    controlId: 'Art.21(2)(i)',
    controlName: 'Cryptographic Policies',
    check: (inp) => {
      if (inp.cryptoCriticalCount > 0)
        return buildGap('Art.21(2)(i)', 'Cryptographic Policies', 'critical',
          'Broken cryptographic algorithms violate NIS2 cryptographic policy requirements Art. 21(2)(i).')
      if (inp.cryptoHighCount > 0)
        return buildGap('Art.21(2)(i)', 'Cryptographic Policies', 'high',
          'High-risk cryptographic weaknesses require remediation under Art. 21(2)(i).')
      return null
    },
  },
  {
    controlId: 'Art.21(2)(j)',
    controlName: 'Access Control and Identity Management',
    check: (inp) => {
      if (inp.secretCriticalCount > 0)
        return buildGap('Art.21(2)(j)', 'Access Control and Identity Management', 'critical',
          'Hardcoded credentials violate NIS2 access control requirements Art. 21(2)(j).')
      if (inp.cicdCriticalCount > 0)
        return buildGap('Art.21(2)(j)', 'Access Control and Identity Management', 'high',
          'Critical CI/CD misconfigurations represent access control failure in the development pipeline.')
      return null
    },
  },
]

// ---------------------------------------------------------------------------
// computeComplianceAttestation — main entry point
// ---------------------------------------------------------------------------

export function computeComplianceAttestation(
  input: ComplianceAttestationInput,
): ComplianceAttestationResult {
  const frameworks: FrameworkAttestation[] = [
    evaluateFramework('soc2', SOC2_CONTROLS, input),
    evaluateFramework('gdpr', GDPR_CONTROLS, input),
    evaluateFramework('pci_dss', PCI_DSS_CONTROLS, input),
    evaluateFramework('hipaa', HIPAA_CONTROLS, input),
    evaluateFramework('nis2', NIS2_CONTROLS, input),
  ]

  const criticalGapCount = frameworks.reduce((s, f) => s + f.criticalGaps, 0)
  const highGapCount = frameworks.reduce((s, f) => s + f.highGaps, 0)
  const fullyCompliantCount = frameworks.filter((f) => f.status === 'compliant').length

  // Overall status = worst status across all frameworks.
  const overallStatus: FrameworkStatus = frameworks.some((f) => f.status === 'non_compliant')
    ? 'non_compliant'
    : frameworks.some((f) => f.status === 'at_risk')
      ? 'at_risk'
      : 'compliant'

  const summary =
    overallStatus === 'compliant'
      ? `All ${frameworks.length} regulatory frameworks fully compliant.`
      : overallStatus === 'non_compliant'
        ? `${frameworks.filter((f) => f.status === 'non_compliant').length} framework(s) non-compliant — ${criticalGapCount} critical gap${criticalGapCount > 1 ? 's' : ''} require immediate remediation.`
        : `${frameworks.filter((f) => f.status === 'at_risk').length} framework(s) at risk — ${highGapCount} high-severity gap${highGapCount > 1 ? 's' : ''} require attention.`

  return {
    frameworks,
    overallStatus,
    criticalGapCount,
    highGapCount,
    fullyCompliantCount,
    summary,
  }
}
