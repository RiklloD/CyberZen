type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
type ValidationStatus =
  | 'pending'
  | 'validated'
  | 'likely_exploitable'
  | 'unexploitable'
  | 'dismissed'
type FindingStatus = 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk'

export type GatePolicyFinding = {
  id: string
  title: string
  severity: Severity
  validationStatus: ValidationStatus
  status: FindingStatus
  source: string
  confidence: number
}

export type GatePolicy = {
  blockOnSeverities: readonly ('critical' | 'high' | 'medium' | 'low')[]
  blockOnValidationStatuses: readonly ('validated' | 'likely_exploitable' | 'pending')[]
  requireExplicitApprovalForCritical: boolean
}

export type GateFindingAssessment = {
  findingId: string
  decision: 'approved' | 'blocked'
  blockingReason: string
  justification: string
  recommendedAction: string
}

export type WorkflowGatePosture = {
  overallDecision: 'approved' | 'blocked'
  blockCount: number
  totalEvaluated: number
  summary: string
}

export const DEFAULT_GATE_POLICY: GatePolicy = {
  blockOnSeverities: ['critical', 'high'] as const,
  blockOnValidationStatuses: ['validated', 'likely_exploitable'] as const,
  requireExplicitApprovalForCritical: true,
}

// Assess a single finding against the gate policy.
// Only active findings (open or pr_opened) are gate-relevant; resolved or
// accepted-risk findings always pass without evaluation.
export function assessGateFinding(args: {
  finding: GatePolicyFinding
  policy: GatePolicy
  repositoryName: string
  branch: string
}): GateFindingAssessment {
  const { finding, policy, repositoryName, branch } = args

  const isActive = finding.status === 'open' || finding.status === 'pr_opened'
  if (!isActive) {
    return {
      findingId: finding.id,
      decision: 'approved',
      blockingReason: '',
      justification: `Finding "${finding.title}" is ${finding.status.replace(/_/g, ' ')} and not gate-relevant for ${repositoryName}.`,
      recommendedAction: 'No gate action required.',
    }
  }

  const severityBlocks = (policy.blockOnSeverities as readonly string[]).includes(
    finding.severity,
  )
  const validationBlocks = (policy.blockOnValidationStatuses as readonly string[]).includes(
    finding.validationStatus,
  )

  if (severityBlocks && validationBlocks) {
    const requiresManualOverride =
      policy.requireExplicitApprovalForCritical && finding.severity === 'critical'
    return {
      findingId: finding.id,
      decision: 'blocked',
      blockingReason: `"${finding.title}" has severity=${finding.severity} and validation=${finding.validationStatus.replace(/_/g, ' ')}, exceeding the gate threshold.`,
      justification: `Gate blocked for ${repositoryName} on ${branch}: ${finding.severity} ${finding.validationStatus.replace(/_/g, ' ')} finding requires resolution before merge or deploy.`,
      recommendedAction: requiresManualOverride
        ? 'Critical findings with exploit evidence require explicit named approval. Resolve the finding or obtain an override with justification before proceeding.'
        : `Resolve the finding or supply a justified override to unblock the ${branch} gate.`,
    }
  }

  return {
    findingId: finding.id,
    decision: 'approved',
    blockingReason: '',
    justification: `"${finding.title}" (${finding.severity}, ${finding.validationStatus.replace(/_/g, ' ')}) does not exceed the gate threshold for ${repositoryName} on ${branch}.`,
    recommendedAction:
      'Continue monitoring. Re-evaluate if advisory intelligence or code context changes.',
  }
}

// Aggregate all per-finding assessments into a single workflow-level posture.
export function computeWorkflowGatePosture(
  assessments: GateFindingAssessment[],
  repositoryName: string,
): WorkflowGatePosture {
  const blocked = assessments.filter((a) => a.decision === 'blocked')
  const overallDecision = blocked.length > 0 ? 'blocked' : 'approved'

  return {
    overallDecision,
    blockCount: blocked.length,
    totalEvaluated: assessments.length,
    summary:
      blocked.length > 0
        ? `Gate blocked by ${blocked.length} finding(s) in ${repositoryName} that exceed the configured severity and validation threshold.`
        : assessments.length > 0
          ? `Gate approved for ${repositoryName}: ${assessments.length} finding(s) evaluated, none exceeded the blocking threshold.`
          : `Gate approved for ${repositoryName}: no gate-relevant findings in scope for this workflow run.`,
  }
}
