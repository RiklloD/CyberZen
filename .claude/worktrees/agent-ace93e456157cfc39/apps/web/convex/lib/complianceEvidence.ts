// SOC 2 Automated Evidence Collection — pure computation library (spec §10.1).
//
// Transforms existing finding, gate-decision, and PR-proposal data into
// concrete audit evidence artifacts that can be exported to an auditor.
//
// Evidence philosophy:
//   Each regulatory framework defines controls. Sentinel maps findings to
//   specific control IDs, then produces per-control evidence items describing
//   whether the control is being met, what gaps exist, and what remediation
//   evidence is available.
//
// Supported frameworks + representative controls:
//   soc2    — CC6 (Logical Access), CC7 (System Operations), CC8 (Change Mgmt)
//   gdpr    — Art.32 (Technical Measures), Art.33 (Breach Notification)
//   hipaa   — §164.312(a) Access, §164.312(b) Audit, §164.312(e) Transmission Security
//   pci_dss — Req 6 (Secure Systems), Req 7 (Access Control), Req 10 (Logging)
//   nis2    — Art.21 (Risk Measures), Art.23 (Incident Reporting)
//
// Output: `ComplianceEvidenceReport` with per-control evidence items ready for
// dashboard display and `/api/compliance/evidence` API export.

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type EvidenceFinding = {
  id: string
  vulnClass: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  status: 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk' | 'false_positive' | 'ignored'
  validationStatus: 'pending' | 'validated' | 'likely_exploitable' | 'unexploitable' | 'dismissed'
  affectedPackages: string[]
  createdAt: number
  resolvedAt?: number
  prUrl?: string
}

export type EvidenceGateDecision = {
  findingId: string
  decision: 'approved' | 'blocked' | 'overridden'
  reason?: string
  decidedAt: number
  expiresAt?: number
}

export type ComplianceEvidenceInput = {
  framework: 'soc2' | 'gdpr' | 'hipaa' | 'pci_dss' | 'nis2'
  findings: EvidenceFinding[]
  gateDecisions: EvidenceGateDecision[]
  repositoryName: string
  scanTimestamp: number
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export type EvidenceStatus = 'compliant' | 'gap' | 'remediated' | 'risk_accepted'
export type EvidenceType =
  | 'finding_log'
  | 'remediation_timeline'
  | 'gate_enforcement'
  | 'risk_acceptance'
  | 'pr_audit_trail'

export type EvidenceItem = {
  controlId: string
  controlName: string
  evidenceType: EvidenceType
  status: EvidenceStatus
  description: string
  findingCount: number
  lastUpdatedAt: number
}

export type ComplianceEvidenceReport = {
  framework: 'soc2' | 'gdpr' | 'hipaa' | 'pci_dss' | 'nis2'
  frameworkLabel: string
  /** 0–100: percentage of controls with compliant or remediated evidence. */
  evidenceScore: number
  coveredControlCount: number
  openGapControlCount: number
  totalEvidenceItems: number
  evidenceItems: EvidenceItem[]
  summary: string
}

// ---------------------------------------------------------------------------
// Control catalogues per framework
//
// Each control maps to one or more vulnerability class prefixes.
// Prefix matching allows broad coverage without exhaustively listing every
// CVE category — "injection" catches SQLi, CMDi, LDAP injection, etc.
// ---------------------------------------------------------------------------

type ControlDef = {
  id: string
  name: string
  /** Vuln-class prefixes that affect this control. */
  vulnClassPrefixes: string[]
  /** Severity levels that are mandatory reporters for this control. */
  mandatorySeverities: Array<'critical' | 'high' | 'medium' | 'low'>
}

const SOC2_CONTROLS: ControlDef[] = [
  {
    id: 'CC6.1',
    name: 'Logical and Physical Access Controls — Restriction',
    vulnClassPrefixes: ['auth', 'iam', 'privilege', 'session', 'broken_access'],
    // TODO: adjust whether 'medium' auth findings should trigger a CC6.1 gap
    // for your audit requirements — stricter = more evidence, but more noise.
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'CC6.6',
    name: 'Logical and Physical Access Controls — Boundary Protection',
    vulnClassPrefixes: ['injection', 'xss', 'ssrf', 'deserialization', 'rce'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: 'CC7.1',
    name: 'System Operations — Monitoring',
    vulnClassPrefixes: ['exposure', 'info_disclosure', 'misconfiguration', 'supply_chain'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'CC7.2',
    name: 'System Operations — Security Events Detection',
    vulnClassPrefixes: ['anomaly', 'zero_day', 'exploit'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: 'CC8.1',
    name: 'Change Management — Authorised and Tested Changes',
    vulnClassPrefixes: ['dependency', 'sbom', 'supply_chain', 'outdated'],
    mandatorySeverities: ['critical', 'high'],
  },
]

const GDPR_CONTROLS: ControlDef[] = [
  {
    id: 'Art.32.1a',
    name: 'Pseudonymisation and Encryption of Personal Data',
    vulnClassPrefixes: ['pii', 'crypto', 'plaintext', 'unencrypted', 'data_exposure'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'Art.32.1b',
    name: 'Confidentiality, Integrity, Availability of Processing Systems',
    vulnClassPrefixes: ['injection', 'rce', 'dos', 'deserialization', 'auth'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: 'Art.32.1d',
    name: 'Regular Testing of Security Measures',
    vulnClassPrefixes: ['dependency', 'supply_chain', 'sbom', 'outdated'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'Art.33',
    name: 'Breach Notification Procedures',
    vulnClassPrefixes: ['credential', 'data_breach', 'pii', 'exposure'],
    mandatorySeverities: ['critical', 'high'],
  },
]

const HIPAA_CONTROLS: ControlDef[] = [
  {
    id: '§164.312(a)',
    name: 'Access Control — Unique User Identification',
    vulnClassPrefixes: ['auth', 'iam', 'session', 'broken_access', 'privilege'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: '§164.312(b)',
    name: 'Audit Controls — Hardware and Software Activity',
    vulnClassPrefixes: ['anomaly', 'exposure', 'info_disclosure', 'misconfiguration'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: '§164.312(c)',
    name: 'Integrity Controls — Data Alteration Protection',
    vulnClassPrefixes: ['injection', 'deserialization', 'tampering', 'supply_chain'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: '§164.312(e)',
    name: 'Transmission Security — Encryption in Transit',
    vulnClassPrefixes: ['crypto', 'tls', 'unencrypted', 'mitm', 'weak_cipher'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
]

const PCI_DSS_CONTROLS: ControlDef[] = [
  {
    id: 'Req6.3',
    name: 'Secure Systems — Vulnerability Management',
    vulnClassPrefixes: ['dependency', 'outdated', 'supply_chain', 'sbom'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'Req6.4',
    name: 'Secure Systems — Web Application Security',
    vulnClassPrefixes: ['injection', 'xss', 'ssrf', 'rce', 'deserialization'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: 'Req7.1',
    name: 'Access Control — Least Privilege',
    vulnClassPrefixes: ['privilege', 'iam', 'auth', 'broken_access', 'session'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'Req10.2',
    name: 'Audit Logging — Security Events',
    vulnClassPrefixes: ['anomaly', 'exploit', 'zero_day', 'credential'],
    mandatorySeverities: ['critical', 'high'],
  },
]

const NIS2_CONTROLS: ControlDef[] = [
  {
    id: 'Art.21(2a)',
    name: 'Risk Analysis and Security Policies',
    vulnClassPrefixes: ['dependency', 'supply_chain', 'sbom', 'misconfiguration'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: 'Art.21(2b)',
    name: 'Incident Handling Procedures',
    vulnClassPrefixes: ['exploit', 'rce', 'anomaly', 'zero_day', 'credential'],
    mandatorySeverities: ['critical', 'high'],
  },
  {
    id: 'Art.21(2e)',
    name: 'Supply Chain Security',
    vulnClassPrefixes: ['supply_chain', 'dependency', 'sbom', 'typosquat'],
    mandatorySeverities: ['critical', 'high', 'medium'],
  },
  {
    id: 'Art.21(2h)',
    name: 'Secure Acquisition and Development',
    vulnClassPrefixes: ['injection', 'xss', 'deserialization', 'auth', 'crypto'],
    mandatorySeverities: ['critical', 'high'],
  },
]

const FRAMEWORK_CONTROLS: Record<string, ControlDef[]> = {
  soc2: SOC2_CONTROLS,
  gdpr: GDPR_CONTROLS,
  hipaa: HIPAA_CONTROLS,
  pci_dss: PCI_DSS_CONTROLS,
  nis2: NIS2_CONTROLS,
}

const FRAMEWORK_LABELS: Record<string, string> = {
  soc2: 'SOC 2 Type II',
  gdpr: 'GDPR Art. 32',
  hipaa: 'HIPAA Technical Safeguards',
  pci_dss: 'PCI-DSS v4.0',
  nis2: 'NIS2 Art. 21',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function vulnClassMatchesControl(vulnClass: string, control: ControlDef): boolean {
  const lc = vulnClass.toLowerCase().replace(/[^a-z0-9_]/g, '_')
  return control.vulnClassPrefixes.some(
    (prefix) => lc === prefix || lc.startsWith(prefix),
  )
}

function findingsForControl(
  findings: EvidenceFinding[],
  control: ControlDef,
): EvidenceFinding[] {
  return findings.filter(
    (f) =>
      vulnClassMatchesControl(f.vulnClass, control) &&
      (control.mandatorySeverities as string[]).includes(f.severity),
  )
}

function evidenceStatusForFindings(findings: EvidenceFinding[]): EvidenceStatus {
  if (findings.length === 0) return 'compliant'

  const openCount = findings.filter(
    (f) => f.status === 'open' || f.status === 'pr_opened',
  ).length
  const resolvedCount = findings.filter(
    (f) => f.status === 'resolved' || f.status === 'merged',
  ).length
  const riskAcceptedCount = findings.filter(
    (f) => f.status === 'accepted_risk',
  ).length

  if (openCount > 0) return 'gap'
  if (resolvedCount > 0) return 'remediated'
  if (riskAcceptedCount > 0) return 'risk_accepted'
  return 'compliant'
}

function buildFindingLogDescription(
  findings: EvidenceFinding[],
  control: ControlDef,
  gateDecisions: EvidenceGateDecision[],
): string {
  const open = findings.filter(
    (f) => f.status === 'open' || f.status === 'pr_opened',
  )
  const resolved = findings.filter(
    (f) => f.status === 'resolved' || f.status === 'merged',
  )

  const parts: string[] = []

  if (open.length > 0) {
    const critCount = open.filter((f) => f.severity === 'critical').length
    const highCount = open.filter((f) => f.severity === 'high').length
    parts.push(
      `${open.length} open finding(s) map to ${control.id}: ` +
        [critCount > 0 ? `${critCount} critical` : '', highCount > 0 ? `${highCount} high` : '']
          .filter(Boolean)
          .join(', ') +
        '.',
    )
  }

  if (resolved.length > 0) {
    // Compute average remediation time
    const times = resolved
      .filter((f) => f.resolvedAt !== undefined)
      .map((f) => (f.resolvedAt! - f.createdAt) / 86400000) // ms → days

    const avgDays =
      times.length > 0 ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : 0

    parts.push(
      `${resolved.length} finding(s) remediated${avgDays > 0 ? ` (avg ${avgDays} day(s))` : ''}.`,
    )
  }

  // Gate enforcement evidence
  const findingIds = new Set(findings.map((f) => f.id))
  const blockedGates = gateDecisions.filter(
    (g) => g.decision === 'blocked' && findingIds.has(g.findingId),
  )
  if (blockedGates.length > 0) {
    parts.push(
      `CI/CD gate blocked ${blockedGates.length} deployment(s) due to findings mapped to this control — enforcement evidence available.`,
    )
  }

  // PR audit trail evidence
  const prFindings = findings.filter((f) => f.prUrl)
  if (prFindings.length > 0) {
    parts.push(`${prFindings.length} finding(s) have associated fix PRs (audit trail available).`)
  }

  return parts.join(' ') || `No findings currently mapped to ${control.id}.`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function generateComplianceEvidence(
  input: ComplianceEvidenceInput,
): ComplianceEvidenceReport {
  const controls = FRAMEWORK_CONTROLS[input.framework] ?? []
  const frameworkLabel = FRAMEWORK_LABELS[input.framework] ?? input.framework

  if (controls.length === 0) {
    return {
      framework: input.framework,
      frameworkLabel,
      evidenceScore: 100,
      coveredControlCount: 0,
      openGapControlCount: 0,
      totalEvidenceItems: 0,
      evidenceItems: [],
      summary: `${frameworkLabel} control catalogue is not configured.`,
    }
  }

  const evidenceItems: EvidenceItem[] = []
  let openGapControlCount = 0

  for (const control of controls) {
    const matched = findingsForControl(input.findings, control)

    if (matched.length === 0) {
      // No findings affecting this control → compliant evidence
      evidenceItems.push({
        controlId: control.id,
        controlName: control.name,
        evidenceType: 'finding_log',
        status: 'compliant',
        description: `No findings currently affect ${control.id} (${control.name}).`,
        findingCount: 0,
        lastUpdatedAt: input.scanTimestamp,
      })
      continue
    }

    const status = evidenceStatusForFindings(matched)
    if (status === 'gap') openGapControlCount++

    // Determine primary evidence type based on what's available
    const hasGateBlock = input.gateDecisions.some(
      (g) => g.decision === 'blocked' && matched.some((f) => f.id === g.findingId),
    )
    const hasPrTrail = matched.some((f) => f.prUrl)
    const hasRiskAcceptance = matched.some((f) => f.status === 'accepted_risk')
    const hasRemediation = matched.some(
      (f) => f.status === 'resolved' || f.status === 'merged',
    )

    let evidenceType: EvidenceType = 'finding_log'
    if (hasGateBlock) evidenceType = 'gate_enforcement'
    else if (hasPrTrail) evidenceType = 'pr_audit_trail'
    else if (hasRemediation) evidenceType = 'remediation_timeline'
    else if (hasRiskAcceptance) evidenceType = 'risk_acceptance'

    const description = buildFindingLogDescription(
      matched,
      control,
      input.gateDecisions,
    )

    const lastUpdatedAt = Math.max(
      ...matched.map((f) => f.resolvedAt ?? f.createdAt),
      input.scanTimestamp,
    )

    evidenceItems.push({
      controlId: control.id,
      controlName: control.name,
      evidenceType,
      status,
      description,
      findingCount: matched.length,
      lastUpdatedAt,
    })
  }

  const compliantOrRemediatedCount = evidenceItems.filter(
    (item) => item.status === 'compliant' || item.status === 'remediated',
  ).length
  const coveredControlCount = evidenceItems.filter((item) => item.findingCount > 0).length

  const evidenceScore =
    controls.length > 0
      ? Math.round((compliantOrRemediatedCount / controls.length) * 100)
      : 100

  // Build summary
  const remediatedItems = evidenceItems.filter((i) => i.status === 'remediated')

  const summary =
    openGapControlCount === 0
      ? input.findings.length === 0
        ? `No findings to map — ${frameworkLabel} all ${controls.length} controls show no gaps.`
        : `${frameworkLabel}: all ${controls.length} controls are compliant or remediated. Evidence score: ${evidenceScore}/100.`
      : [
          `${frameworkLabel}: ${openGapControlCount} control(s) with open gaps out of ${controls.length} total.`,
          remediatedItems.length > 0
            ? ` ${remediatedItems.length} control(s) recently remediated.`
            : '',
          ` Evidence score: ${evidenceScore}/100.`,
        ].join('')

  return {
    framework: input.framework,
    frameworkLabel,
    evidenceScore,
    coveredControlCount,
    openGapControlCount,
    totalEvidenceItems: evidenceItems.length,
    evidenceItems,
    summary,
  }
}
