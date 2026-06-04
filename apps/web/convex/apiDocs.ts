import { v } from 'convex/values'
import { query } from './_generated/server'

// ─── OpenAPI 3.1 Spec ─────────────────────────────────────────────────────────

const OPENAPI_VERSION = '3.1.0'
const API_VERSION = '1.0.0'

function buildOpenApiSpec() {
  return {
    openapi: OPENAPI_VERSION,
    info: {
      title: 'CyberZen Security Platform API',
      version: API_VERSION,
      description:
        'The CyberZen API provides programmatic access to security findings, repositories, SBOM data, compliance evidence, and webhook management. All endpoints require authentication via an API key.',
      contact: {
        name: 'CyberZen Support',
        url: 'https://cyberzen.dev/docs',
      },
      license: {
        name: 'Proprietary',
      },
    },
    servers: [
      {
        url: 'https://api.cyberzen.dev',
        description: 'Production',
      },
    ],
    security: [{ BearerAuth: [] }, { ApiKeyAuth: [] }],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          description: 'JWT token obtained via OAuth2 login flow.',
        },
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-CyberZen-Api-Key',
          description: 'Service API key generated in Settings > API Keys.',
        },
      },
      schemas: {
        Severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'informational'],
        },
        FindingStatus: {
          type: 'string',
          enum: ['open', 'pr_opened', 'merged', 'resolved', 'accepted_risk', 'false_positive', 'ignored', 'snoozed'],
        },
        Finding: {
          type: 'object',
          required: ['id', 'severity', 'status', 'title', 'repository', 'createdAt'],
          properties: {
            id: { type: 'string', example: 'fnd_abc123' },
            severity: { $ref: '#/components/schemas/Severity' },
            status: { $ref: '#/components/schemas/FindingStatus' },
            title: { type: 'string', example: 'SQL Injection in auth middleware' },
            summary: { type: 'string' },
            repository: { type: 'string', example: 'acme/api-server' },
            confidence: { type: 'number', minimum: 0, maximum: 1 },
            vulnClass: { type: 'string', example: 'injection' },
            source: { type: 'string', example: 'sast' },
            createdAt: { type: 'string', format: 'date-time' },
            resolvedAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        Repository: {
          type: 'object',
          required: ['id', 'fullName', 'provider'],
          properties: {
            id: { type: 'string', example: 'repo_xyz' },
            fullName: { type: 'string', example: 'acme/api-server' },
            provider: { type: 'string', enum: ['github', 'gitlab'] },
            healthScore: { type: 'integer', minimum: 0, maximum: 100 },
            trustScore: { type: 'integer', minimum: 0, maximum: 100 },
            lastScannedAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        SbomComponent: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            version: { type: 'string' },
            ecosystem: { type: 'string', example: 'npm' },
            cves: { type: 'array', items: { type: 'string' } },
            licenseExpression: { type: 'string', nullable: true },
          },
        },
        WebhookEndpoint: {
          type: 'object',
          required: ['id', 'url', 'events', 'enabled'],
          properties: {
            id: { type: 'string' },
            url: { type: 'string', format: 'uri' },
            events: { type: 'array', items: { type: 'string' } },
            enabled: { type: 'boolean' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        Pagination: {
          type: 'object',
          properties: {
            cursor: { type: 'string', nullable: true },
            hasMore: { type: 'boolean' },
          },
        },
        Error: {
          type: 'object',
          required: ['error'],
          properties: {
            error: { type: 'string' },
            code: { type: 'string' },
          },
        },
        RateLimitHeaders: {
          description: 'Rate limiting headers included in all API responses.',
          properties: {
            'X-RateLimit-Limit': { type: 'integer', description: 'Requests allowed per window.' },
            'X-RateLimit-Remaining': { type: 'integer', description: 'Requests remaining in current window.' },
            'X-RateLimit-Reset': { type: 'integer', description: 'Unix timestamp when the window resets.' },
          },
        },
      },
    },
    paths: {
      '/api/findings': {
        get: {
          operationId: 'listFindings',
          summary: 'List findings',
          description: 'Returns a paginated list of security findings for the authenticated tenant.',
          tags: ['Findings'],
          parameters: [
            { name: 'severity', in: 'query', schema: { $ref: '#/components/schemas/Severity' } },
            { name: 'status', in: 'query', schema: { $ref: '#/components/schemas/FindingStatus' } },
            { name: 'repository', in: 'query', schema: { type: 'string' }, description: 'Filter by repository full name.' },
            { name: 'limit', in: 'query', schema: { type: 'integer', default: 50, maximum: 200 } },
            { name: 'cursor', in: 'query', schema: { type: 'string' }, description: 'Pagination cursor from previous response.' },
          ],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
                      pagination: { $ref: '#/components/schemas/Pagination' },
                    },
                  },
                },
              },
            },
            '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            '429': { description: 'Rate limit exceeded' },
          },
        },
      },
      '/api/repositories': {
        get: {
          operationId: 'listRepositories',
          summary: 'List repositories',
          description: 'Returns all connected repositories with health scores and last-scan timestamps.',
          tags: ['Repositories'],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/Repository' } },
                    },
                  },
                },
              },
            },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/api/sbom/export': {
        get: {
          operationId: 'exportSbom',
          summary: 'Export SBOM',
          description: 'Download the latest Software Bill of Materials for a repository in CycloneDX or SPDX format.',
          tags: ['SBOM'],
          parameters: [
            { name: 'repositoryId', in: 'query', required: true, schema: { type: 'string' } },
            { name: 'format', in: 'query', schema: { type: 'string', enum: ['cyclonedx', 'spdx'], default: 'cyclonedx' } },
          ],
          responses: {
            '200': { description: 'SBOM document returned as JSON.' },
            '404': { description: 'Repository or SBOM snapshot not found.' },
          },
        },
      },
      '/api/compliance/evidence': {
        get: {
          operationId: 'listComplianceEvidence',
          summary: 'List compliance evidence',
          description: 'Returns compliance evidence artifacts grouped by framework (SOC2, GDPR, HIPAA, PCI-DSS, NIS2).',
          tags: ['Compliance'],
          parameters: [
            { name: 'framework', in: 'query', schema: { type: 'string', enum: ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'] } },
          ],
          responses: {
            '200': { description: 'Evidence list returned.' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/webhooks/github': {
        post: {
          operationId: 'githubWebhook',
          summary: 'GitHub webhook receiver',
          description: 'Receives push, pull_request, and check_run events from GitHub. Authenticated via HMAC-SHA256 signature in X-Hub-Signature-256 header.',
          tags: ['Webhooks'],
          security: [],
          requestBody: {
            description: 'GitHub webhook payload.',
            content: { 'application/json': { schema: { type: 'object' } } },
          },
          responses: {
            '200': { description: 'Event accepted.' },
            '400': { description: 'Bad payload or signature mismatch.' },
          },
        },
      },
      '/webhooks/gitlab': {
        post: {
          operationId: 'gitlabWebhook',
          summary: 'GitLab webhook receiver',
          description: 'Receives push and merge_request events from GitLab. Authenticated via X-Gitlab-Token header.',
          tags: ['Webhooks'],
          security: [],
          responses: {
            '200': { description: 'Event accepted.' },
            '400': { description: 'Invalid token.' },
          },
        },
      },
    },
    tags: [
      { name: 'Findings', description: 'Security findings detected across your repositories.' },
      { name: 'Repositories', description: 'Connected source code repositories.' },
      { name: 'SBOM', description: 'Software Bill of Materials management.' },
      { name: 'Compliance', description: 'Compliance evidence and framework mapping.' },
      { name: 'Webhooks', description: 'Inbound webhook event receivers from SCM providers.' },
    ],
  }
}

// ─── Public Query ─────────────────────────────────────────────────────────────

export const getOpenApiSpec = query({
  args: {},
  handler: async (_ctx, _args) => {
    return buildOpenApiSpec()
  },
})
