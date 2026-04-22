/**
 * WS-47 — Compliance Gap Remediation Planner: pure computation library.
 *
 * Accepts the `ControlGap[]` outputs produced by WS-46's
 * `computeComplianceAttestation` and maps each gap to a concrete, ordered
 * remediation playbook drawn from the `REMEDIATION_CATALOG`.
 *
 * The catalog contains one entry per WS-46 control (22 total) and provides:
 *   - Step-by-step remediation instructions, each labelled with a category
 *     (code_fix / config_change / policy_doc / tool_setup / process_change)
 *     and an `automatable` flag indicating whether Sentinel or a common
 *     toolchain can execute it automatically.
 *   - Effort and estimated days, deduplicated by root cause so that the
 *     same underlying issue (e.g. a crypto weakness) appearing in multiple
 *     frameworks is not counted multiple times in `estimatedTotalDays`.
 *   - Evidence requirements: what an auditor would accept as proof of
 *     remediation.
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

import type { ControlGap, GapSeverity, ComplianceFramework } from './complianceAttestationReport'

// ---------------------------------------------------------------------------
// Constants & types
// ---------------------------------------------------------------------------

export type PlaybookStepCategory =
  | 'code_fix'
  | 'config_change'
  | 'policy_doc'
  | 'tool_setup'
  | 'process_change'

export type RemediationEffort = 'low' | 'medium' | 'high'

export type PlaybookStep = {
  order: number
  instruction: string
  category: PlaybookStepCategory
  /** True if Sentinel or a standard toolchain can execute this step automatically. */
  automatable: boolean
}

export type RemediationPlaybookEntry = {
  controlId: string
  controlName: string
  framework: ComplianceFramework
  /** Short imperative title shown in the dashboard action list. */
  title: string
  steps: PlaybookStep[]
  effort: RemediationEffort
  /** Realistic calendar days required assuming a focused engineer. */
  estimatedDays: number
  /** Whether this control requires a written policy document as evidence. */
  requiresPolicyDoc: boolean
  /** Audit evidence items the playbook produces when fully executed. */
  evidenceNeeded: string[]
}

export type RemediationAction = {
  controlId: string
  controlName: string
  framework: ComplianceFramework
  gapSeverity: GapSeverity
  title: string
  steps: PlaybookStep[]
  effort: RemediationEffort
  estimatedDays: number
  /** True when at least one step in the playbook is automatable. */
  automatable: boolean
  requiresPolicyDoc: boolean
  evidenceNeeded: string[]
}

export type ComplianceRemediationPlan = {
  /** Ordered list of remediation actions, critical gaps first. */
  actions: RemediationAction[]
  totalActions: number
  criticalActions: number
  highActions: number
  mediumActions: number
  lowActions: number
  /** Actions with at least one automatable step. */
  automatableActions: number
  /** Actions that require a written policy or procedure document. */
  requiresPolicyDocCount: number
  /**
   * Estimated total working days. Root-cause-deduplicated: if the same
   * underlying issue (e.g. crypto weakness) appears across multiple frameworks,
   * only the maximum estimated days for that root cause are counted once.
   */
  estimatedTotalDays: number
  summary: string
}

// ---------------------------------------------------------------------------
// Root-cause mapping (for estimatedTotalDays deduplication)
// Controls that share a root cause produce one effort estimate, not N.
// ---------------------------------------------------------------------------

export const CONTROL_ROOT_CAUSE: Record<string, string> = {
  'CC6.1': 'secret_exposure',
  'CC6.6': 'iac_misconfiguration',
  'CC6.7': 'crypto_weakness',
  'CC7.1': 'eol_or_cve',
  'CC7.2': 'sbom_integrity',
  'CC8.1': 'cicd_security',
  'CC9.2': 'supply_chain_risk',
  'Art.25': 'container_risk',
  'Art.32': 'crypto_weakness',         // same root as CC6.7
  'Art.33-34': 'eol_or_cve',           // same root as CC7.1
  'Req.6.2': 'eol_or_cve',
  'Req.6.3': 'eol_or_cve',
  'Req.6.5': 'sbom_integrity',         // same root as CC7.2
  'Req.11.3': 'eol_or_cve',
  '§164.312(a)(1)': 'secret_exposure', // same root as CC6.1
  '§164.312(a)(2)(iv)': 'crypto_weakness',
  '§164.312(c)(1)': 'sbom_integrity',
  '§164.312(e)(2)(ii)': 'crypto_weakness',
  'Art.21(2)(e)': 'supply_chain_risk', // same root as CC9.2
  'Art.21(2)(h)': 'container_risk',    // same root as Art.25
  'Art.21(2)(i)': 'crypto_weakness',
  'Art.21(2)(j)': 'secret_exposure',   // primarily secret/access exposure
}

// ---------------------------------------------------------------------------
// Remediation catalog — one entry per WS-46 control (22 total)
// ---------------------------------------------------------------------------

export const REMEDIATION_CATALOG: Record<string, RemediationPlaybookEntry> = {
  // ── SOC 2 ──────────────────────────────────────────────────────────────────
  'CC6.1': {
    controlId: 'CC6.1',
    controlName: 'Logical Access Controls',
    framework: 'soc2',
    title: 'Rotate exposed credentials and implement secret management',
    steps: [
      {
        order: 1,
        instruction: 'Immediately revoke all exposed API keys, tokens, and passwords detected in the codebase — treat each as compromised.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Move secrets to a dedicated secrets manager (AWS Secrets Manager, HashiCorp Vault, or equivalent) and reference them via environment variables.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Install a pre-commit hook (detect-secrets, gitleaks) to block future credential commits at the developer workstation level.',
        category: 'tool_setup',
        automatable: true,
      },
      {
        order: 4,
        instruction: 'Audit git history for the exposed credential value using git log -S and consider force-pushing clean history if the repository is private.',
        category: 'process_change',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 3,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Credential rotation confirmation from the provider (e.g. AWS key deletion log)',
      'Secrets manager configuration proof',
      'Pre-commit hook configuration screenshot',
    ],
  },

  'CC6.6': {
    controlId: 'CC6.6',
    controlName: 'Infrastructure Security',
    framework: 'soc2',
    title: 'Remediate IaC security misconfigurations',
    steps: [
      {
        order: 1,
        instruction: 'Fix all critical IaC misconfigurations identified in the scan — prioritise public S3/storage buckets, unrestricted security groups, and Kubernetes RBAC over-grants.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Add Sentinel IaC security scanning as a required CI/CD check; block merges that introduce critical-severity findings.',
        category: 'tool_setup',
        automatable: true,
      },
      {
        order: 3,
        instruction: 'Codify security baselines as OPA/Rego or Terraform Sentinel policies so they are enforced automatically on every plan.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'IaC scan clean run (0 critical findings)',
      'CI/CD policy gate configuration',
      'OPA/Sentinel policy file',
    ],
  },

  'CC6.7': {
    controlId: 'CC6.7',
    controlName: 'Encryption',
    framework: 'soc2',
    title: 'Replace deprecated cryptographic algorithms',
    steps: [
      {
        order: 1,
        instruction: 'Replace MD5 and SHA-1 with SHA-256 or SHA-3 in all authentication, integrity, and fingerprinting contexts.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Replace DES, 3DES, RC4, and Blowfish ciphers with AES-256-GCM throughout the codebase.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Disable ECB mode and unauthenticated CBC. Use an authenticated encryption mode (GCM, CCM, or ChaCha20-Poly1305).',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 4,
        instruction: 'Replace Math.random() / Python random with a cryptographically secure PRNG (crypto.randomBytes, secrets module, etc.).',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 5,
        instruction: 'Enable the Sentinel crypto-weakness gate in CI/CD to block future regressions automatically.',
        category: 'tool_setup',
        automatable: true,
      },
    ],
    effort: 'high',
    estimatedDays: 5,
    requiresPolicyDoc: false,
    evidenceNeeded: [
      'Crypto weakness scan clean run (0 critical findings)',
      'Code review confirming algorithm replacement',
    ],
  },

  'CC7.1': {
    controlId: 'CC7.1',
    controlName: 'Vulnerability Monitoring',
    framework: 'soc2',
    title: 'Patch CVE-affected and end-of-life dependencies',
    steps: [
      {
        order: 1,
        instruction: 'Upgrade all packages with known CVEs to the minimum safe version shown in the scan report (e.g. log4j-core ≥ 2.17.0, vm2 ≥ 3.9.17).',
        category: 'code_fix',
        automatable: true,
      },
      {
        order: 2,
        instruction: 'Upgrade all end-of-life runtime dependencies (Node.js, Python, PHP, etc.) to the current LTS or vendor-supported release.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Configure automated dependency update PRs via Dependabot or Renovate so future vulnerabilities are surfaced within 24 hours.',
        category: 'tool_setup',
        automatable: true,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: false,
    evidenceNeeded: [
      'CVE scan clean run (0 critical/high findings)',
      'EOL scan clean run',
      'Updated lockfile committed and passing CI',
    ],
  },

  'CC7.2': {
    controlId: 'CC7.2',
    controlName: 'Integrity',
    framework: 'soc2',
    title: 'Establish SBOM integrity verification',
    steps: [
      {
        order: 1,
        instruction: 'Trigger a fresh SBOM attestation after confirming the current component list is clean and untampered.',
        category: 'process_change',
        automatable: true,
      },
      {
        order: 2,
        instruction: 'Schedule periodic re-verification runs (Sentinel performs this automatically every 24 hours by default).',
        category: 'tool_setup',
        automatable: true,
      },
      {
        order: 3,
        instruction: 'Document the attestation and verification process in your security runbook so the team knows how to respond to a tamper alert.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'low',
    estimatedDays: 1,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'SBOM attestation record with status: valid',
      'Scheduled verification cron configuration',
    ],
  },

  'CC8.1': {
    controlId: 'CC8.1',
    controlName: 'Change Management',
    framework: 'soc2',
    title: 'Remediate CI/CD pipeline security misconfigurations',
    steps: [
      {
        order: 1,
        instruction: 'Fix critical CI/CD misconfigurations: pin third-party GitHub Actions to a specific commit SHA, remove GITHUB_TOKEN: write-all permissions, and require secret scanning on every PR.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Set a global permissions: read-all baseline in each workflow and grant write scopes only to the specific jobs that need them.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Enable Sentinel CI/CD security gate as a required status check to block future pipeline misconfigurations automatically.',
        category: 'tool_setup',
        automatable: true,
      },
    ],
    effort: 'medium',
    estimatedDays: 1,
    requiresPolicyDoc: false,
    evidenceNeeded: [
      'CI/CD scan clean run (0 critical findings)',
      'Updated workflow YAML files with pinned actions',
    ],
  },

  'CC9.2': {
    controlId: 'CC9.2',
    controlName: 'Supply Chain',
    framework: 'soc2',
    title: 'Remove or replace risky supply chain packages',
    steps: [
      {
        order: 1,
        instruction: 'Immediately remove all confirmed malicious or typosquatting packages and audit recent deployments for signs of compromise.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Replace abandoned or deprecated packages with actively-maintained alternatives listed in the scan recommendations.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Configure a private registry mirror or allowlist and update dependency resolution to prefer vetted packages.',
        category: 'tool_setup',
        automatable: false,
      },
      {
        order: 4,
        instruction: 'Enable the Sentinel supply-chain posture gate in CI/CD to block future introduction of malicious or abandoned packages.',
        category: 'tool_setup',
        automatable: true,
      },
    ],
    effort: 'high',
    estimatedDays: 3,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Supply chain posture scan: clean',
      'Updated package manifest',
      'Private registry configuration (if applicable)',
    ],
  },

  // ── GDPR ───────────────────────────────────────────────────────────────────
  'Art.25': {
    controlId: 'Art.25',
    controlName: 'Data Protection by Design',
    framework: 'gdpr',
    title: 'Upgrade EOL container base images for data protection by design',
    steps: [
      {
        order: 1,
        instruction: 'Replace all EOL base images with supported LTS equivalents (ubuntu:22.04, node:20-alpine, python:3.12-slim, etc.).',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Add Sentinel container image scanning as a required CI/CD gate to block future EOL or critical-risk images.',
        category: 'tool_setup',
        automatable: true,
      },
      {
        order: 3,
        instruction: 'Document the container update lifecycle and GDPR data-protection-by-design rationale in your security policy.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Container image scan clean run',
      'Updated Dockerfile(s) with supported base images',
      'Data protection policy referencing container security',
    ],
  },

  'Art.32': {
    controlId: 'Art.32',
    controlName: 'Security of Processing',
    framework: 'gdpr',
    title: 'Strengthen technical security measures per GDPR Art. 32',
    steps: [
      {
        order: 1,
        instruction: 'Replace deprecated cryptographic algorithms (see the CC6.7 playbook for specific substitutions).',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Improve SBOM completeness to a "good" or "excellent" grade by adding version pins and licence declarations for all direct dependencies.',
        category: 'code_fix',
        automatable: true,
      },
      {
        order: 3,
        instruction: 'Write and publish an encryption-at-rest and in-transit policy as required by GDPR Art. 32(1)(a).',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 5,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Crypto weakness scan clean run',
      'SBOM quality score ≥ 75 (grade: good or excellent)',
      'Written technical security measures policy (Art. 32 documentation)',
    ],
  },

  'Art.33-34': {
    controlId: 'Art.33-34',
    controlName: 'Breach Notification',
    framework: 'gdpr',
    title: 'Reduce breach risk and prepare notification procedures',
    steps: [
      {
        order: 1,
        instruction: 'Upgrade all CVE-affected components that could be exploited to access personal data.',
        category: 'code_fix',
        automatable: true,
      },
      {
        order: 2,
        instruction: 'Upgrade EOL software whose lack of security patches creates an elevated breach risk.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Prepare a 72-hour breach notification template and define an internal escalation list as required by Art. 33.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 3,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'CVE scan clean run',
      'EOL scan clean run',
      'Breach notification procedure document',
    ],
  },

  // ── PCI-DSS ────────────────────────────────────────────────────────────────
  'Req.6.2': {
    controlId: 'Req.6.2',
    controlName: 'Protect System Components',
    framework: 'pci_dss',
    title: 'Apply security patches for PCI-DSS scoped components',
    steps: [
      {
        order: 1,
        instruction: 'Apply patches for all critical-severity CVEs within 30 days of disclosure per PCI-DSS Req. 6.3.3.',
        category: 'code_fix',
        automatable: true,
      },
      {
        order: 2,
        instruction: 'Establish a monthly patching review cycle and document all patch decisions (applied, deferred, risk-accepted) in a patching register.',
        category: 'process_change',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'CVE scan: 0 critical findings',
      'Patching register documenting remediation dates',
    ],
  },

  'Req.6.3': {
    controlId: 'Req.6.3',
    controlName: 'Security Vulnerabilities',
    framework: 'pci_dss',
    title: 'Eliminate EOL software per PCI-DSS patch requirements',
    steps: [
      {
        order: 1,
        instruction: 'Upgrade all EOL system components (OS, runtime, frameworks) to vendor-supported versions per PCI-DSS Req. 6.3.4.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Document the software lifecycle status and planned upgrade dates for all PCI-scoped components.',
        category: 'policy_doc',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Configure automated EOL alerts so future version end-of-life dates are surfaced before they expire.',
        category: 'tool_setup',
        automatable: true,
      },
    ],
    effort: 'medium',
    estimatedDays: 3,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'EOL scan clean run',
      'Software lifecycle documentation for PCI scope',
    ],
  },

  'Req.6.5': {
    controlId: 'Req.6.5',
    controlName: 'Tamper Detection',
    framework: 'pci_dss',
    title: 'Implement software integrity verification for PCI scope',
    steps: [
      {
        order: 1,
        instruction: 'Resolve any SBOM attestation tampering event: re-attest after confirming the component list is clean.',
        category: 'process_change',
        automatable: true,
      },
      {
        order: 2,
        instruction: 'Document the software integrity verification procedure as required by PCI-DSS Req. 6.5.2 (change-detection mechanisms).',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'low',
    estimatedDays: 1,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'SBOM attestation record with status: valid',
      'Integrity verification procedure document',
    ],
  },

  'Req.11.3': {
    controlId: 'Req.11.3',
    controlName: 'Penetration Testing',
    framework: 'pci_dss',
    title: 'Remediate high-severity vulnerabilities per PCI-DSS Req. 11',
    steps: [
      {
        order: 1,
        instruction: 'Remediate all high-severity CVE findings within PCI-DSS patching windows; document the specific package versions upgraded.',
        category: 'code_fix',
        automatable: true,
      },
      {
        order: 2,
        instruction: 'Run a re-scan after remediation to confirm 0 high-severity findings and record the clean-scan timestamp as evidence.',
        category: 'process_change',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'CVE scan: 0 high-severity findings',
      'Remediation documentation with version change log',
    ],
  },

  // ── HIPAA ──────────────────────────────────────────────────────────────────
  '§164.312(a)(1)': {
    controlId: '§164.312(a)(1)',
    controlName: 'Access Control',
    framework: 'hipaa',
    title: 'Protect ePHI access — rotate exposed credentials',
    steps: [
      {
        order: 1,
        instruction: 'Immediately rotate all credentials exposed in HIPAA-relevant systems (databases, APIs, admin accounts).',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Implement role-based access control with the principle of least privilege for all systems that store or process ePHI.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Enable multi-factor authentication for all accounts with ePHI access per HIPAA §164.312(a)(2)(i).',
        category: 'tool_setup',
        automatable: false,
      },
      {
        order: 4,
        instruction: 'Document the access control policy and unique user identification requirements per §164.312(a)(2).',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 5,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Credential rotation confirmation',
      'MFA configuration screenshot',
      'Access control policy document',
    ],
  },

  '§164.312(a)(2)(iv)': {
    controlId: '§164.312(a)(2)(iv)',
    controlName: 'Encryption and Decryption',
    framework: 'hipaa',
    title: 'Implement encryption/decryption for ePHI',
    steps: [
      {
        order: 1,
        instruction: 'Encrypt all ePHI at rest using AES-256; replace any broken cipher usage detected by the crypto scanner.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Enforce TLS 1.2 minimum (preferably TLS 1.3) for all ePHI transmitted in transit.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Remove deprecated cryptographic primitives (MD5, SHA-1, DES, RC4) from any ePHI processing path.',
        category: 'code_fix',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 5,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Crypto scan clean run',
      'TLS configuration proof (e.g. ssllabs.com A rating)',
      'Encryption policy document',
    ],
  },

  '§164.312(c)(1)': {
    controlId: '§164.312(c)(1)',
    controlName: 'Integrity',
    framework: 'hipaa',
    title: 'Establish ePHI integrity controls and investigate tampering',
    steps: [
      {
        order: 1,
        instruction: 'Investigate the SBOM attestation tampering event to determine whether ePHI systems were affected; escalate per your incident response plan.',
        category: 'process_change',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Re-attest the SBOM after confirming the component list is clean and untampered.',
        category: 'process_change',
        automatable: true,
      },
      {
        order: 3,
        instruction: 'Implement audit logging for all ePHI modifications per HIPAA §164.312(b) (audit controls).',
        category: 'tool_setup',
        automatable: false,
      },
      {
        order: 4,
        instruction: 'Document the integrity monitoring procedure and incident response steps for tampering events.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 3,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'SBOM attestation record with status: valid',
      'Audit log configuration proof',
      'Integrity procedure document',
    ],
  },

  '§164.312(e)(2)(ii)': {
    controlId: '§164.312(e)(2)(ii)',
    controlName: 'Encryption in Transit',
    framework: 'hipaa',
    title: 'Encrypt ePHI transmission per HIPAA Technical Safeguards',
    steps: [
      {
        order: 1,
        instruction: 'Enforce TLS 1.2 or higher on all channels that transmit ePHI; update server and load-balancer TLS configuration.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Disable RC4, DES, 3DES, and NULL cipher suites across all ePHI endpoints.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Document the transmission encryption configuration and schedule annual TLS certificate rotation.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'TLS configuration audit (cipher scan report)',
      'Transmission security procedure document',
    ],
  },

  // ── NIS2 ───────────────────────────────────────────────────────────────────
  'Art.21(2)(e)': {
    controlId: 'Art.21(2)(e)',
    controlName: 'Supply Chain Security',
    framework: 'nis2',
    title: 'Remove malicious packages and assess supply chain integrity',
    steps: [
      {
        order: 1,
        instruction: 'Immediately remove all confirmed malicious or backdoored packages and redeploy any affected services.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Conduct a compromise assessment: review logs for data exfiltration or lateral movement from systems that ran the malicious package.',
        category: 'process_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Perform a supplier security assessment and document the results as required by NIS2 Art. 21(2)(e).',
        category: 'process_change',
        automatable: false,
      },
      {
        order: 4,
        instruction: 'Implement package vetting procedures (allowlist, registry mirror) for future supply chain additions.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 5,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Supply chain scan clean run',
      'Compromise assessment report',
      'Supplier assessment document',
    ],
  },

  'Art.21(2)(h)': {
    controlId: 'Art.21(2)(h)',
    controlName: 'Network and Information System Security',
    framework: 'nis2',
    title: 'Address container security risks per NIS2 risk management',
    steps: [
      {
        order: 1,
        instruction: 'Upgrade all critical-risk or EOL container base images to supported LTS alternatives.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Add Sentinel container image scanning as a CI/CD gate to enforce supported base images automatically.',
        category: 'tool_setup',
        automatable: true,
      },
      {
        order: 3,
        instruction: 'Enable non-root container execution and read-only root filesystems where architecturally feasible.',
        category: 'config_change',
        automatable: false,
      },
    ],
    effort: 'medium',
    estimatedDays: 2,
    requiresPolicyDoc: false,
    evidenceNeeded: [
      'Container image scan clean run',
      'Updated Dockerfile(s) with supported base images',
    ],
  },

  'Art.21(2)(i)': {
    controlId: 'Art.21(2)(i)',
    controlName: 'Cryptographic Measures',
    framework: 'nis2',
    title: 'Implement strong cryptographic measures per NIS2 Art. 21(2)(i)',
    steps: [
      {
        order: 1,
        instruction: 'Replace all deprecated or broken cryptographic algorithms with ENISA-approved alternatives (AES-256-GCM, SHA-256+, X25519/P-256 for key exchange).',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Write a cryptographic algorithm policy aligned with the ENISA guidelines for cryptographic measures.',
        category: 'policy_doc',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Enable the Sentinel crypto-weakness gate in CI/CD to detect and block future algorithmic regressions.',
        category: 'tool_setup',
        automatable: true,
      },
    ],
    effort: 'high',
    estimatedDays: 4,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Crypto weakness scan clean run',
      'Cryptographic algorithm policy document',
    ],
  },

  'Art.21(2)(j)': {
    controlId: 'Art.21(2)(j)',
    controlName: 'Access Management',
    framework: 'nis2',
    title: 'Strengthen access and authentication management per NIS2',
    steps: [
      {
        order: 1,
        instruction: 'Rotate all exposed credentials and migrate secrets to a centralised secrets management solution.',
        category: 'code_fix',
        automatable: false,
      },
      {
        order: 2,
        instruction: 'Fix CI/CD pipeline access control misconfigurations — particularly over-privileged workflow tokens and unpinned third-party actions.',
        category: 'config_change',
        automatable: false,
      },
      {
        order: 3,
        instruction: 'Implement multi-factor authentication and privileged access management for all administrator accounts.',
        category: 'tool_setup',
        automatable: false,
      },
      {
        order: 4,
        instruction: 'Document the access management policy per NIS2 Art. 21(2)(j) and schedule annual review.',
        category: 'policy_doc',
        automatable: false,
      },
    ],
    effort: 'high',
    estimatedDays: 4,
    requiresPolicyDoc: true,
    evidenceNeeded: [
      'Credential rotation confirmation',
      'CI/CD scan clean run',
      'Access management policy document',
    ],
  },
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<GapSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

function buildPlanSummary(
  actions: RemediationAction[],
  estimatedTotalDays: number,
): string {
  if (actions.length === 0) {
    return 'No remediation actions required — all compliance controls are satisfied.'
  }
  const critCount = actions.filter((a) => a.gapSeverity === 'critical').length
  const highCount = actions.filter((a) => a.gapSeverity === 'high').length
  const autoCount = actions.filter((a) => a.automatable).length

  const parts: string[] = []
  if (critCount > 0) {
    parts.push(
      `${critCount} critical action${critCount > 1 ? 's' : ''} require immediate attention`,
    )
  }
  if (highCount > 0) {
    parts.push(`${highCount} high-priority action${highCount > 1 ? 's' : ''} should be addressed within 7 days`)
  }
  const remaining = actions.length - critCount - highCount
  if (remaining > 0) {
    parts.push(`${remaining} additional action${remaining > 1 ? 's' : ''} for medium/low gaps`)
  }
  const effortNote = `Estimated remediation effort: ~${estimatedTotalDays} working day${estimatedTotalDays === 1 ? '' : 's'}.`
  const autoNote =
    autoCount > 0
      ? ` ${autoCount} action${autoCount > 1 ? 's' : ''} can be partially automated.`
      : ''
  return `${parts.join('; ')}. ${effortNote}${autoNote}`
}

// ---------------------------------------------------------------------------
// Primary export
// ---------------------------------------------------------------------------

/**
 * Compute a prioritised remediation plan from a list of compliance control gaps.
 *
 * Each gap is looked up in `REMEDIATION_CATALOG`. Unknown control IDs are
 * silently skipped. The returned `actions` array is sorted critical → high →
 * medium → low. `estimatedTotalDays` is root-cause-deduplicated — if the same
 * underlying issue (e.g. crypto weakness) appears in multiple frameworks, only
 * the maximum days for that root cause are counted once.
 */
export function computeRemediationPlan(
  controlGaps: ControlGap[],
): ComplianceRemediationPlan {
  if (controlGaps.length === 0) {
    return {
      actions: [],
      totalActions: 0,
      criticalActions: 0,
      highActions: 0,
      mediumActions: 0,
      lowActions: 0,
      automatableActions: 0,
      requiresPolicyDocCount: 0,
      estimatedTotalDays: 0,
      summary: 'No remediation actions required — all compliance controls are satisfied.',
    }
  }

  const actions: RemediationAction[] = []

  for (const gap of controlGaps) {
    const playbook = REMEDIATION_CATALOG[gap.controlId]
    if (!playbook) continue // unknown control — skip

    actions.push({
      controlId: gap.controlId,
      controlName: gap.controlName,
      framework: playbook.framework,
      gapSeverity: gap.gapSeverity,
      title: playbook.title,
      steps: playbook.steps,
      effort: playbook.effort,
      estimatedDays: playbook.estimatedDays,
      automatable: playbook.steps.some((s) => s.automatable),
      requiresPolicyDoc: playbook.requiresPolicyDoc,
      evidenceNeeded: playbook.evidenceNeeded,
    })
  }

  // Sort by gap severity: critical → high → medium → low
  actions.sort(
    (a, b) => (SEVERITY_RANK[a.gapSeverity] ?? 4) - (SEVERITY_RANK[b.gapSeverity] ?? 4),
  )

  // Compute aggregates
  const criticalActions = actions.filter((a) => a.gapSeverity === 'critical').length
  const highActions = actions.filter((a) => a.gapSeverity === 'high').length
  const mediumActions = actions.filter((a) => a.gapSeverity === 'medium').length
  const lowActions = actions.filter((a) => a.gapSeverity === 'low').length
  const automatableActions = actions.filter((a) => a.automatable).length
  const requiresPolicyDocCount = actions.filter((a) => a.requiresPolicyDoc).length

  // estimatedTotalDays: deduplicate by root cause (max days per root cause, then sum)
  const rootCauseMaxDays = new Map<string, number>()
  for (const action of actions) {
    const rootCause = CONTROL_ROOT_CAUSE[action.controlId] ?? action.controlId
    const current = rootCauseMaxDays.get(rootCause) ?? 0
    rootCauseMaxDays.set(rootCause, Math.max(current, action.estimatedDays))
  }
  const estimatedTotalDays = Array.from(rootCauseMaxDays.values()).reduce((s, d) => s + d, 0)

  const summary = buildPlanSummary(actions, estimatedTotalDays)

  return {
    actions,
    totalActions: actions.length,
    criticalActions,
    highActions,
    mediumActions,
    lowActions,
    automatableActions,
    requiresPolicyDocCount,
    estimatedTotalDays,
    summary,
  }
}
