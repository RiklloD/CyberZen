// WS-33 — Infrastructure as Code (IaC) Security Scanner: pure computation library.
//
// Detects security misconfigurations in Terraform, Kubernetes, Dockerfile,
// and Docker Compose files via static regex-rule analysis.
//
// Exports:
//   detectFileType       — infers IaC file type from filename
//   scanIacFile          — runs all applicable rules against a single file
//   combineIacResults    — aggregates per-file results into a summary

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IacFileType =
  | 'terraform'
  | 'cloudformation'
  | 'kubernetes'
  | 'dockerfile'
  | 'compose'
  | 'unknown'

export type IacSeverity = 'critical' | 'high' | 'medium' | 'low'

export type IacRuleId =
  // Terraform
  | 'TF_SG_OPEN_INGRESS' //  Security group allows 0.0.0.0/0 ingress
  | 'TF_S3_PUBLIC_ACL' //  S3 bucket ACL set to public-read / public-read-write
  | 'TF_RDS_PUBLIC' //  RDS instance is publicly accessible
  | 'TF_IAM_WILDCARD_ACTION' //  IAM policy grants Action: "*"
  | 'TF_IAM_WILDCARD_RESOURCE' //  IAM policy grants Resource: "*"
  | 'TF_HTTP_LISTENER' //  ALB listener uses plain HTTP without redirect
  // Kubernetes
  | 'K8S_PRIVILEGED_CONTAINER' //  Container runs in privileged mode
  | 'K8S_HOST_NETWORK' //  Pod uses host network namespace
  | 'K8S_HOST_PID' //  Pod shares host PID namespace
  | 'K8S_LATEST_IMAGE_TAG' //  Container image uses :latest tag
  | 'K8S_ALLOW_PRIVILEGE_ESCALATION' //  allowPrivilegeEscalation: true
  | 'K8S_RUN_AS_ROOT' //  runAsNonRoot explicitly set to false
  // Dockerfile
  | 'DOCKER_ROOT_USER' //  No USER instruction — container runs as root
  | 'DOCKER_ADD_COMMAND' //  ADD used instead of COPY (arbitrary URL risk)
  | 'DOCKER_LATEST_TAG' //  Base image uses :latest
  | 'DOCKER_SENSITIVE_ENV' //  ENV instruction stores credential-like name
  | 'DOCKER_CURL_BASH_PIPE' //  curl | bash / wget | sh anti-pattern
  // Docker Compose
  | 'COMPOSE_PRIVILEGED' //  Service runs in privileged mode
  | 'COMPOSE_HOST_NETWORK' //  Service uses host network mode
  | 'COMPOSE_SENSITIVE_ENV' //  environment block contains credential-like key

export type IacFinding = {
  ruleId: IacRuleId
  severity: IacSeverity
  title: string
  description: string
  remediation: string
}

export type IacScanResult = {
  filename: string
  fileType: IacFileType
  findings: IacFinding[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
}

export type IacScanSummary = {
  totalFiles: number
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  fileResults: IacScanResult[]
  summary: string
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

type IacRule = {
  id: IacRuleId
  severity: IacSeverity
  title: string
  description: string
  remediation: string
  fileTypes: IacFileType[]
  pattern: RegExp
  /** When true, the rule triggers if the pattern is NOT found in the content. */
  negated?: boolean
}

const RULES: IacRule[] = [
  // ── Terraform ─────────────────────────────────────────────────────────────
  {
    id: 'TF_SG_OPEN_INGRESS',
    severity: 'critical',
    title: 'Security group allows unrestricted inbound access',
    description:
      'A security group ingress rule uses 0.0.0.0/0 or ::/0 CIDR, allowing traffic from any IP address.',
    remediation: 'Restrict ingress CIDR blocks to specific IP ranges or VPC CIDRs.',
    fileTypes: ['terraform'],
    pattern: /cidr_blocks\s*=\s*\[?\s*"(?:0\.0\.0\.0\/0|::\/0)"/i,
  },
  {
    id: 'TF_S3_PUBLIC_ACL',
    severity: 'high',
    title: 'S3 bucket ACL grants public access',
    description:
      'The S3 bucket ACL is set to public-read or public-read-write, making objects publicly accessible.',
    remediation:
      'Use "private" ACL and manage public access through bucket policies with explicit conditions.',
    fileTypes: ['terraform'],
    pattern: /acl\s*=\s*"public-read(?:-write)?"/i,
  },
  {
    id: 'TF_RDS_PUBLIC',
    severity: 'critical',
    title: 'RDS instance is publicly accessible',
    description:
      'The RDS instance has publicly_accessible = true, exposing the database to the public internet.',
    remediation:
      'Set publicly_accessible = false and access RDS through a bastion host or VPN.',
    fileTypes: ['terraform'],
    pattern: /publicly_accessible\s*=\s*true/i,
  },
  {
    id: 'TF_IAM_WILDCARD_ACTION',
    severity: 'high',
    title: 'IAM policy grants wildcard Action',
    description:
      'An IAM policy contains Action = "*", granting all AWS actions to the principal.',
    remediation: 'Replace wildcard actions with the minimum set of actions required.',
    fileTypes: ['terraform'],
    pattern: /(?:actions|Action)\s*[=:]\s*\[?\s*["\[]*\s*"\*"/i,
  },
  {
    id: 'TF_IAM_WILDCARD_RESOURCE',
    severity: 'high',
    title: 'IAM policy grants wildcard Resource',
    description:
      'An IAM policy contains Resource = "*", applying permissions to all AWS resources.',
    remediation: 'Scope IAM policies to specific resource ARNs.',
    fileTypes: ['terraform'],
    pattern: /(?:resources|Resource)\s*[=:]\s*\[?\s*["\[]*\s*"\*"/i,
  },
  {
    id: 'TF_HTTP_LISTENER',
    severity: 'medium',
    title: 'ALB listener uses plain HTTP',
    description:
      'A load balancer listener is configured for HTTP without a redirect to HTTPS.',
    remediation:
      'Add an HTTPS listener or configure an HTTP→HTTPS redirect rule on the load balancer.',
    fileTypes: ['terraform'],
    pattern: /protocol\s*=\s*"HTTP"/i,
  },

  // ── Kubernetes ─────────────────────────────────────────────────────────────
  {
    id: 'K8S_PRIVILEGED_CONTAINER',
    severity: 'critical',
    title: 'Container runs in privileged mode',
    description:
      'A container has securityContext.privileged: true, giving it nearly full host access.',
    remediation:
      'Remove privileged: true and use specific Linux capabilities (e.g. SYS_NET_ADMIN) if needed.',
    fileTypes: ['kubernetes'],
    pattern: /privileged:\s*true/i,
  },
  {
    id: 'K8S_HOST_NETWORK',
    severity: 'high',
    title: 'Pod uses host network namespace',
    description:
      'hostNetwork: true allows the pod to access the host network stack directly.',
    remediation: 'Remove hostNetwork: true unless strictly required by the workload.',
    fileTypes: ['kubernetes'],
    pattern: /hostNetwork:\s*true/i,
  },
  {
    id: 'K8S_HOST_PID',
    severity: 'high',
    title: 'Pod shares host PID namespace',
    description:
      'hostPID: true gives the pod visibility into all processes on the host.',
    remediation: 'Remove hostPID: true unless required for debugging tooling.',
    fileTypes: ['kubernetes'],
    pattern: /hostPID:\s*true/i,
  },
  {
    id: 'K8S_LATEST_IMAGE_TAG',
    severity: 'medium',
    title: 'Container image uses :latest tag',
    description:
      'Using :latest makes deployments non-deterministic and can introduce untested changes.',
    remediation: 'Pin image tags to a specific version or digest (e.g. nginx:1.25.3).',
    fileTypes: ['kubernetes'],
    pattern: /image:\s*\S+:latest(?:\s|$)/i,
  },
  {
    id: 'K8S_ALLOW_PRIVILEGE_ESCALATION',
    severity: 'high',
    title: 'Container allows privilege escalation',
    description:
      'allowPrivilegeEscalation: true permits processes to gain more privileges than their parent.',
    remediation: 'Set allowPrivilegeEscalation: false in the container securityContext.',
    fileTypes: ['kubernetes'],
    pattern: /allowPrivilegeEscalation:\s*true/i,
  },
  {
    id: 'K8S_RUN_AS_ROOT',
    severity: 'high',
    title: 'Container explicitly permits running as root',
    description:
      'runAsNonRoot: false explicitly allows the container to run as the root user.',
    remediation: 'Set runAsNonRoot: true and specify a non-root runAsUser.',
    fileTypes: ['kubernetes'],
    pattern: /runAsNonRoot:\s*false/i,
  },

  // ── Dockerfile ─────────────────────────────────────────────────────────────
  {
    id: 'DOCKER_ROOT_USER',
    severity: 'high',
    title: 'Dockerfile has no USER instruction',
    description:
      'Without a USER instruction the container process runs as root, increasing blast radius if compromised.',
    remediation: 'Add a USER instruction with a non-root UID (e.g. USER 1001).',
    fileTypes: ['dockerfile'],
    pattern: /^USER\s+/im,
    negated: true,
  },
  {
    id: 'DOCKER_ADD_COMMAND',
    severity: 'medium',
    title: 'Dockerfile uses ADD instead of COPY',
    description:
      'ADD can fetch remote URLs and auto-extract archives, introducing unexpected attack surface.',
    remediation: 'Replace ADD with COPY for local files, or use RUN curl for explicit remote fetches.',
    fileTypes: ['dockerfile'],
    pattern: /^\s*ADD\s+(?!--chown)/im,
  },
  {
    id: 'DOCKER_LATEST_TAG',
    severity: 'medium',
    title: 'Dockerfile uses :latest base image',
    description:
      'FROM image:latest makes builds non-reproducible and may pull untested updates.',
    remediation: 'Pin the base image to a specific digest or version tag.',
    fileTypes: ['dockerfile'],
    pattern: /^\s*FROM\s+\S+:latest(?:\s|$)/im,
  },
  {
    id: 'DOCKER_SENSITIVE_ENV',
    severity: 'high',
    title: 'Dockerfile bakes credential into ENV',
    description:
      'An ENV instruction uses a name associated with credentials, risking secrets being baked into the image.',
    remediation:
      'Use build-time secrets (--secret), Docker Swarm secrets, or runtime environment injection instead.',
    fileTypes: ['dockerfile'],
    pattern:
      /^\s*ENV\s+(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY|APIKEY|CREDENTIAL|PRIVATE_KEY)\s*[= ]/im,
  },
  {
    id: 'DOCKER_CURL_BASH_PIPE',
    severity: 'high',
    title: 'Dockerfile uses curl | bash pipe',
    description:
      'Piping curl/wget output directly to bash or sh executes untrusted remote code without verification.',
    remediation: 'Download scripts, verify their checksum, then execute them separately.',
    fileTypes: ['dockerfile'],
    pattern: /(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh)\b/i,
  },

  // ── Docker Compose ─────────────────────────────────────────────────────────
  {
    id: 'COMPOSE_PRIVILEGED',
    severity: 'critical',
    title: 'Compose service runs in privileged mode',
    description:
      'privileged: true grants the container near-full host access, bypassing container isolation.',
    remediation: 'Remove privileged: true and use specific capabilities (cap_add) instead.',
    fileTypes: ['compose'],
    pattern: /privileged:\s*true/i,
  },
  {
    id: 'COMPOSE_HOST_NETWORK',
    severity: 'high',
    title: 'Compose service uses host network mode',
    description:
      'network_mode: host disables network isolation between the container and the host.',
    remediation: 'Use named Docker networks with explicit port mappings instead.',
    fileTypes: ['compose'],
    pattern: /network_mode:\s*["']?host["']?/i,
  },
  {
    id: 'COMPOSE_SENSITIVE_ENV',
    severity: 'medium',
    title: 'Compose service environment contains credential-like key',
    description:
      'An environment variable name suggests a hardcoded secret (password, token, key, etc.).',
    remediation: 'Use a secrets manager or reference external env files (.env) rather than hardcoding.',
    fileTypes: ['compose'],
    pattern:
      /(?:PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|CREDENTIAL|PRIVATE_KEY)\s*[:=]\s*(?!['"]?\s*['"]?$)/i,
  },
]

// ---------------------------------------------------------------------------
// detectFileType
// ---------------------------------------------------------------------------

/**
 * Infers the IaC file type from the filename.
 *
 * Rules (first match wins):
 *   *.tf                         → terraform
 *   *docker-compose*.yml/.yaml   → compose
 *   *compose*.yml/.yaml          → compose
 *   Dockerfile / *.dockerfile    → dockerfile
 *   *.yaml / *.yml               → kubernetes (default for YAML files)
 *   *.json containing "AWSTemplateFormatVersion" heuristic (content check)
 *     → use cloudformation when caller passes content with that header
 */
export function detectFileType(filename: string): IacFileType {
  const lower = filename.toLowerCase()
  const base = lower.split('/').pop() ?? lower

  if (base.endsWith('.tf')) return 'terraform'
  if (base.includes('docker-compose') || base.includes('compose.yml') || base.includes('compose.yaml'))
    return 'compose'
  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile'))
    return 'dockerfile'
  if (base.endsWith('.yaml') || base.endsWith('.yml')) return 'kubernetes'
  if (base.endsWith('.json')) return 'cloudformation'
  return 'unknown'
}

// ---------------------------------------------------------------------------
// scanIacFile
// ---------------------------------------------------------------------------

/**
 * Runs all IaC security rules applicable to the detected file type
 * against the provided content string.
 *
 * @param filename  Used to infer the file type
 * @param content   Full text of the IaC file
 */
export function scanIacFile(filename: string, content: string): IacScanResult {
  const fileType = detectFileType(filename)

  const applicableRules = RULES.filter((r) => r.fileTypes.includes(fileType))

  const findings: IacFinding[] = []

  for (const rule of applicableRules) {
    const matched = rule.pattern.test(content)
    const triggered = rule.negated ? !matched : matched

    if (triggered) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        remediation: rule.remediation,
      })
    }
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length

  return { filename, fileType, findings, criticalCount, highCount, mediumCount, lowCount }
}

// ---------------------------------------------------------------------------
// combineIacResults
// ---------------------------------------------------------------------------

/**
 * Aggregates per-file scan results into a single summary.
 */
export function combineIacResults(results: IacScanResult[]): IacScanSummary {
  const totalFindings = results.reduce((s, r) => s + r.findings.length, 0)
  const criticalCount = results.reduce((s, r) => s + r.criticalCount, 0)
  const highCount = results.reduce((s, r) => s + r.highCount, 0)
  const mediumCount = results.reduce((s, r) => s + r.mediumCount, 0)
  const lowCount = results.reduce((s, r) => s + r.lowCount, 0)

  const overallRisk: IacScanSummary['overallRisk'] =
    criticalCount > 0
      ? 'critical'
      : highCount > 0
        ? 'high'
        : mediumCount > 0
          ? 'medium'
          : lowCount > 0
            ? 'low'
            : 'none'

  const summary =
    results.length === 0
      ? 'No IaC files scanned.'
      : totalFindings === 0
        ? `Scanned ${results.length} IaC file${results.length === 1 ? '' : 's'}. No misconfigurations found.`
        : `Scanned ${results.length} IaC file${results.length === 1 ? '' : 's'}. Found ${totalFindings} misconfiguration${totalFindings === 1 ? '' : 's'}` +
          (criticalCount > 0 ? ` (${criticalCount} critical)` : '') +
          '.'

  return {
    totalFiles: results.length,
    totalFindings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    overallRisk,
    fileResults: results,
    summary,
  }
}
