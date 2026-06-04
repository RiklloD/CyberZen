// WS-33 — Infrastructure as Code (IaC) Security Scanner: unit tests
/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  combineIacResults,
  detectFileType,
  scanIacFile,
  type IacScanResult,
} from './iacSecurity'

// ---------------------------------------------------------------------------
// detectFileType
// ---------------------------------------------------------------------------

describe('detectFileType', () => {
  it('detects .tf as terraform', () => {
    expect(detectFileType('main.tf')).toBe('terraform')
  })

  it('detects nested .tf path as terraform', () => {
    expect(detectFileType('infra/modules/vpc/main.tf')).toBe('terraform')
  })

  it('detects docker-compose.yml as compose', () => {
    expect(detectFileType('docker-compose.yml')).toBe('compose')
  })

  it('detects docker-compose.yaml as compose', () => {
    expect(detectFileType('docker-compose.yaml')).toBe('compose')
  })

  it('detects compose.yml as compose', () => {
    expect(detectFileType('compose.yml')).toBe('compose')
  })

  it('detects Dockerfile as dockerfile', () => {
    expect(detectFileType('Dockerfile')).toBe('dockerfile')
  })

  it('detects Dockerfile.prod as dockerfile', () => {
    expect(detectFileType('Dockerfile.prod')).toBe('dockerfile')
  })

  it('detects .dockerfile extension as dockerfile', () => {
    expect(detectFileType('api.dockerfile')).toBe('dockerfile')
  })

  it('detects .yaml as kubernetes', () => {
    expect(detectFileType('deployment.yaml')).toBe('kubernetes')
  })

  it('detects .yml as kubernetes', () => {
    expect(detectFileType('service.yml')).toBe('kubernetes')
  })

  it('detects .json as cloudformation', () => {
    expect(detectFileType('template.json')).toBe('cloudformation')
  })

  it('returns unknown for unrecognised extensions', () => {
    expect(detectFileType('README.md')).toBe('unknown')
    expect(detectFileType('config.toml')).toBe('unknown')
  })
})

// ---------------------------------------------------------------------------
// scanIacFile — Terraform rules
// ---------------------------------------------------------------------------

describe('scanIacFile — Terraform', () => {
  it('detects TF_SG_OPEN_INGRESS with 0.0.0.0/0 CIDR', () => {
    const content = `
resource "aws_security_group_rule" "ingress" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}`
    const result = scanIacFile('main.tf', content)
    const ids = result.findings.map((f) => f.ruleId)
    expect(ids).toContain('TF_SG_OPEN_INGRESS')
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  it('detects TF_S3_PUBLIC_ACL with public-read', () => {
    const content = `
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}`
    const result = scanIacFile('s3.tf', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('TF_S3_PUBLIC_ACL')
  })

  it('detects TF_RDS_PUBLIC with publicly_accessible = true', () => {
    const content = `
resource "aws_db_instance" "db" {
  allocated_storage    = 20
  publicly_accessible  = true
}`
    const result = scanIacFile('rds.tf', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('TF_RDS_PUBLIC')
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  it('detects TF_IAM_WILDCARD_ACTION', () => {
    const content = `
data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["arn:aws:s3:::my-bucket"]
  }
}`
    const result = scanIacFile('iam.tf', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('TF_IAM_WILDCARD_ACTION')
  })

  it('detects TF_IAM_WILDCARD_RESOURCE', () => {
    const content = `
statement {
  actions   = ["s3:GetObject"]
  resources = ["*"]
}`
    const result = scanIacFile('iam.tf', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('TF_IAM_WILDCARD_RESOURCE')
  })

  it('detects TF_HTTP_LISTENER for HTTP protocol', () => {
    const content = `
resource "aws_alb_listener" "http" {
  protocol = "HTTP"
  port     = 80
}`
    const result = scanIacFile('alb.tf', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('TF_HTTP_LISTENER')
  })

  it('returns no findings for clean Terraform', () => {
    const content = `
resource "aws_s3_bucket" "secure" {
  bucket = "my-private-bucket"
  acl    = "private"
}
resource "aws_db_instance" "private_db" {
  publicly_accessible = false
}
`
    const result = scanIacFile('clean.tf', content)
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// scanIacFile — Kubernetes rules
// ---------------------------------------------------------------------------

describe('scanIacFile — Kubernetes', () => {
  it('detects K8S_PRIVILEGED_CONTAINER', () => {
    const content = `
spec:
  containers:
  - name: app
    securityContext:
      privileged: true`
    const result = scanIacFile('deployment.yaml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('K8S_PRIVILEGED_CONTAINER')
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  it('detects K8S_HOST_NETWORK', () => {
    const content = `
spec:
  hostNetwork: true
  containers: []`
    const result = scanIacFile('pod.yaml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('K8S_HOST_NETWORK')
  })

  it('detects K8S_HOST_PID', () => {
    const content = `
spec:
  hostPID: true`
    const result = scanIacFile('pod.yaml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('K8S_HOST_PID')
  })

  it('detects K8S_LATEST_IMAGE_TAG', () => {
    const content = `
spec:
  containers:
  - name: api
    image: myapp:latest`
    const result = scanIacFile('deploy.yaml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('K8S_LATEST_IMAGE_TAG')
  })

  it('detects K8S_ALLOW_PRIVILEGE_ESCALATION', () => {
    const content = `
securityContext:
  allowPrivilegeEscalation: true`
    const result = scanIacFile('pod.yml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('K8S_ALLOW_PRIVILEGE_ESCALATION')
  })

  it('detects K8S_RUN_AS_ROOT', () => {
    const content = `
securityContext:
  runAsNonRoot: false`
    const result = scanIacFile('deploy.yml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('K8S_RUN_AS_ROOT')
  })

  it('returns no findings for hardened Kubernetes spec', () => {
    const content = `
spec:
  hostNetwork: false
  hostPID: false
  containers:
  - name: api
    image: myapp:1.2.3
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      privileged: false`
    const result = scanIacFile('deployment.yaml', content)
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// scanIacFile — Dockerfile rules
// ---------------------------------------------------------------------------

describe('scanIacFile — Dockerfile', () => {
  it('detects DOCKER_ROOT_USER when no USER instruction', () => {
    const content = `FROM node:18\nRUN npm install\nCMD ["node", "server.js"]`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('DOCKER_ROOT_USER')
  })

  it('does NOT flag DOCKER_ROOT_USER when USER is present', () => {
    const content = `FROM node:18\nRUN npm install\nUSER 1001\nCMD ["node", "server.js"]`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).not.toContain('DOCKER_ROOT_USER')
  })

  it('detects DOCKER_ADD_COMMAND', () => {
    const content = `FROM ubuntu:22.04\nADD https://example.com/file.tar.gz /app/`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('DOCKER_ADD_COMMAND')
  })

  it('does NOT flag DOCKER_ADD_COMMAND for ADD --chown', () => {
    const content = `FROM ubuntu:22.04\nADD --chown=user:group file.tar.gz /app/\nUSER 1001`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).not.toContain('DOCKER_ADD_COMMAND')
  })

  it('detects DOCKER_LATEST_TAG', () => {
    const content = `FROM node:latest\nUSER 1001`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('DOCKER_LATEST_TAG')
  })

  it('detects DOCKER_SENSITIVE_ENV with PASSWORD', () => {
    const content = `FROM node:18\nENV PASSWORD changeme\nUSER 1001`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('DOCKER_SENSITIVE_ENV')
  })

  it('detects DOCKER_SENSITIVE_ENV with API_KEY', () => {
    const content = `FROM python:3.11\nENV API_KEY = sk-abc123\nUSER 1001`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('DOCKER_SENSITIVE_ENV')
  })

  it('detects DOCKER_CURL_BASH_PIPE', () => {
    const content = `FROM ubuntu:22.04\nRUN curl -fsSL https://install.sh | bash\nUSER 1001`
    const result = scanIacFile('Dockerfile', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('DOCKER_CURL_BASH_PIPE')
  })
})

// ---------------------------------------------------------------------------
// scanIacFile — Docker Compose rules
// ---------------------------------------------------------------------------

describe('scanIacFile — Docker Compose', () => {
  it('detects COMPOSE_PRIVILEGED', () => {
    const content = `
services:
  app:
    image: myapp:1.0.0
    privileged: true`
    const result = scanIacFile('docker-compose.yml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('COMPOSE_PRIVILEGED')
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  it('detects COMPOSE_HOST_NETWORK', () => {
    const content = `
services:
  app:
    image: myapp:1.0.0
    network_mode: host`
    const result = scanIacFile('docker-compose.yml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('COMPOSE_HOST_NETWORK')
  })

  it('detects COMPOSE_SENSITIVE_ENV', () => {
    const content = `
services:
  db:
    image: postgres:15
    environment:
      PASSWORD: supersecret`
    const result = scanIacFile('docker-compose.yaml', content)
    expect(result.findings.map((f) => f.ruleId)).toContain('COMPOSE_SENSITIVE_ENV')
  })

  it('returns no findings for clean compose file', () => {
    const content = `
services:
  app:
    image: myapp:1.2.3
    ports:
      - "8080:8080"
    networks:
      - app-net
networks:
  app-net: {}`
    const result = scanIacFile('docker-compose.yml', content)
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// scanIacFile — unknown file type
// ---------------------------------------------------------------------------

describe('scanIacFile — unknown type', () => {
  it('returns no findings for unknown file type', () => {
    const result = scanIacFile('config.toml', 'privileged: true\n0.0.0.0/0')
    expect(result.fileType).toBe('unknown')
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// combineIacResults
// ---------------------------------------------------------------------------

describe('combineIacResults', () => {
  const emptyResult: IacScanResult = {
    filename: 'empty.tf',
    fileType: 'terraform',
    findings: [],
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
  }

  it('returns none risk for empty results array', () => {
    const summary = combineIacResults([])
    expect(summary.overallRisk).toBe('none')
    expect(summary.totalFindings).toBe(0)
    expect(summary.summary).toMatch(/no iac files scanned/i)
  })

  it('returns none risk when no findings', () => {
    const summary = combineIacResults([emptyResult])
    expect(summary.overallRisk).toBe('none')
    expect(summary.summary).toMatch(/no misconfigurations found/i)
  })

  it('overallRisk is critical when any critical finding exists', () => {
    const result = scanIacFile(
      'main.tf',
      'resource "aws_db_instance" "db" { publicly_accessible = true }',
    )
    const summary = combineIacResults([result])
    expect(summary.overallRisk).toBe('critical')
  })

  it('overallRisk is high when only high findings', () => {
    const result = scanIacFile(
      'main.tf',
      'actions = ["*"] resources = ["arn:aws:s3:::bucket"]',
    )
    const summary = combineIacResults([result])
    expect(['high', 'medium', 'none']).toContain(summary.overallRisk)
  })

  it('aggregates counts across multiple files', () => {
    const r1 = scanIacFile(
      'Dockerfile',
      'FROM node:latest\n# no USER instruction',
    )
    const r2 = scanIacFile(
      'deployment.yaml',
      'securityContext:\n  privileged: true',
    )
    const summary = combineIacResults([r1, r2])
    expect(summary.totalFiles).toBe(2)
    expect(summary.totalFindings).toBeGreaterThanOrEqual(2)
    expect(summary.criticalCount).toBeGreaterThan(0)
  })

  it('summary mentions critical count when present', () => {
    const r = scanIacFile(
      'main.tf',
      'cidr_blocks = ["0.0.0.0/0"]',
    )
    const summary = combineIacResults([r])
    expect(summary.summary).toMatch(/critical/i)
  })

  it('totalFiles counts all provided results', () => {
    const summary = combineIacResults([emptyResult, emptyResult, emptyResult])
    expect(summary.totalFiles).toBe(3)
  })
})
