import { describe, expect, it } from 'vitest'
import {
  API_SECURITY_RULES,
  isGraphQLSecurityConfig,
  scanApiSecurityDrift,
  type ApiSecurityDriftResult,
} from './apiSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): ApiSecurityDriftResult {
  return scanApiSecurityDrift(paths)
}

function expectClean(result: ApiSecurityDriftResult) {
  expect(result.riskScore).toBe(0)
  expect(result.riskLevel).toBe('none')
  expect(result.totalFindings).toBe(0)
  expect(result.findings).toHaveLength(0)
}

function hasRule(result: ApiSecurityDriftResult, ruleId: string) {
  return result.findings.some((f) => f.ruleId === ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('scanApiSecurityDrift — trivial inputs', () => {
  it('returns clean result for empty array', () => {
    expectClean(scan([]))
  })

  it('returns clean result for whitespace-only paths', () => {
    expectClean(scan(['', '   ', '\t']))
  })

  it('returns clean result for non-API-security files', () => {
    expectClean(scan(['src/index.ts', 'README.md', 'package.json', 'src/api/users.ts']))
  })

  it('summary mentions scanned file count for clean result', () => {
    const result = scan(['src/index.ts', 'README.md'])
    expect(result.summary).toMatch(/2 changed file/)
    expect(result.summary).toMatch(/no API security/)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('scanApiSecurityDrift — vendor path exclusion', () => {
  it('ignores rate-limit.config.ts inside node_modules', () => {
    expectClean(scan(['node_modules/express-rate-limit/rate-limit.config.ts']))
  })

  it('ignores api-keys.json inside dist', () => {
    expectClean(scan(['dist/config/api-keys.json']))
  })

  it('ignores openapi.yaml inside .cdk', () => {
    expectClean(scan(['.cdk/openapi.yaml']))
  })

  it('flags rate-limit.config.ts in non-vendor path', () => {
    const result = scan(['config/rate-limit.config.ts'])
    expect(hasRule(result, 'API_RATE_LIMIT_DRIFT')).toBe(true)
  })

  it('flags api-keys.json outside vendor but not inside node_modules', () => {
    const result = scan([
      'node_modules/some-lib/api-keys.json',  // excluded
      'config/api-keys.json',                  // included
    ])
    expect(hasRule(result, 'API_KEY_MANAGEMENT_DRIFT')).toBe(true)
    const f = result.findings.find((f) => f.ruleId === 'API_KEY_MANAGEMENT_DRIFT')!
    expect(f.matchedPath).toBe('config/api-keys.json')
  })
})

// ---------------------------------------------------------------------------
// API_RATE_LIMIT_DRIFT
// ---------------------------------------------------------------------------

describe('API_RATE_LIMIT_DRIFT — rate limiting and throttle config', () => {
  it.each([
    'rate-limit.config.ts',
    'rate-limit.config.js',
    'rate-limit.json',
    'rate-limit.yaml',
    'rate_limit.json',
    'ratelimit.json',
    'throttle.config.ts',
    'throttle.json',
    'throttle.yaml',
    'api-rate.config.ts',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'API_RATE_LIMIT_DRIFT')).toBe(true)
  })

  it.each([
    'rate-limit/config.json',
    'rate-limiting/settings.yaml',
    'throttle/rules.json',
  ])('flags file in rate-limit directory: %s', (file) => {
    expect(hasRule(scan([file]), 'API_RATE_LIMIT_DRIFT')).toBe(true)
  })

  it.each([
    'src/utils/rate.ts',
    'src/middleware/limiter.ts',
    'package.json',
    'README.md',
  ])('does not flag non-rate-limit file: %s', (file) => {
    expect(hasRule(scan([file]), 'API_RATE_LIMIT_DRIFT')).toBe(false)
  })

  it('records correct severity (high)', () => {
    const result = scan(['rate-limit.config.ts'])
    const f = result.findings.find((f) => f.ruleId === 'API_RATE_LIMIT_DRIFT')!
    expect(f.severity).toBe('high')
  })

  it('deduplicates multiple rate-limit files into single finding with matchCount', () => {
    const result = scan(['rate-limit.config.ts', 'throttle.yaml', 'api-rate.config.js'])
    const f = result.findings.filter((f) => f.ruleId === 'API_RATE_LIMIT_DRIFT')
    expect(f).toHaveLength(1)
    expect(f[0]!.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// API_KEY_MANAGEMENT_DRIFT
// ---------------------------------------------------------------------------

describe('API_KEY_MANAGEMENT_DRIFT — API key and credentials config', () => {
  it.each([
    'api-keys.json',
    'api-keys.yaml',
    'api-keys.yml',
    'api_keys.json',
    'apikeys.json',
    'api-key.config.ts',
    'api-keys.config.js',
    'api-credentials.config.ts',
    'api-token.config.ts',
    'api-auth.config.js',
    'api-access.config.ts',
    'api-key-rotation.json',
    'api_key_rotation.yaml',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'API_KEY_MANAGEMENT_DRIFT')).toBe(true)
  })

  it.each([
    'api-keys/provisioning.json',
    'api-key-management/config.yaml',
    'apikeys/rotation.json',
  ])('flags file in api-keys directory: %s', (file) => {
    expect(hasRule(scan([file]), 'API_KEY_MANAGEMENT_DRIFT')).toBe(true)
  })

  it.each([
    // WS-62 handles these (API gateway auth)
    'api-gateway-auth.config.ts',
    'api_gateway_auth.yaml',
    'apigateway-auth.json',
    // generic source code
    'src/services/apiClient.ts',
    'src/utils/api.ts',
  ])('does not flag: %s', (file) => {
    expect(hasRule(scan([file]), 'API_KEY_MANAGEMENT_DRIFT')).toBe(false)
  })

  it('records correct severity (high)', () => {
    const result = scan(['api-keys.json'])
    const f = result.findings.find((f) => f.ruleId === 'API_KEY_MANAGEMENT_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// isGraphQLSecurityConfig (user contribution) + GRAPHQL_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('isGraphQLSecurityConfig — user contribution point', () => {
  it.each([
    'graphql-shield.config.ts',
    'graphql-shield.config.js',
    'graphql-depth-limit.config.ts',
    'graphql_depth.config.ts',
    'graphql-complexity.config.ts',
    'graphql-permissions.config.ts',
    'graphql-auth.config.ts',
    'graphql-security.config.ts',
    'graphql-protect.config.ts',
    'graphql-query-limit.json',
    'graphql-firewall.config.ts',
    'hasura-auth.yaml',
    'hasura_auth.json',
    'persisted-queries.json',
    'persisted_queries.yaml',
  ])('detects %s as GraphQL security config', (file) => {
    expect(isGraphQLSecurityConfig(file)).toBe(true)
  })

  it.each([
    'apollo.config.ts',          // pure codegen config — no security qualifier
    'graphql.config.ts',         // codegen tooling
    'schema.graphql',            // schema file (not a config-file extension)
    'src/graphql/resolvers.ts',  // source code
    'node_modules/graphql/index.js',
  ])('does not detect %s as GraphQL security config', (file) => {
    expect(isGraphQLSecurityConfig(file)).toBe(false)
  })

  it('detects apollo security config via qualifier in basename', () => {
    expect(isGraphQLSecurityConfig('apollo-security.config.ts')).toBe(true)
  })

  it('detects file in graphql/security directory', () => {
    expect(isGraphQLSecurityConfig('src/graphql/security/graphql-rules.ts')).toBe(true)
  })

  it('returns false for non-config extensions even with GraphQL security name', () => {
    expect(isGraphQLSecurityConfig('graphql-shield.md')).toBe(false)
  })
})

describe('GRAPHQL_SECURITY_DRIFT rule', () => {
  it('fires on graphql-shield.config.ts', () => {
    expect(hasRule(scan(['graphql-shield.config.ts']), 'GRAPHQL_SECURITY_DRIFT')).toBe(true)
  })

  it('fires on graphql-depth-limit.config.ts', () => {
    expect(hasRule(scan(['graphql-depth-limit.config.ts']), 'GRAPHQL_SECURITY_DRIFT')).toBe(true)
  })

  it('fires on hasura-auth.yaml', () => {
    expect(hasRule(scan(['graphql/hasura-auth.yaml']), 'GRAPHQL_SECURITY_DRIFT')).toBe(true)
  })

  it('records correct severity (high)', () => {
    const result = scan(['graphql-shield.config.ts'])
    const f = result.findings.find((f) => f.ruleId === 'GRAPHQL_SECURITY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// OPENAPI_SECURITY_SCHEMA_DRIFT
// ---------------------------------------------------------------------------

describe('OPENAPI_SECURITY_SCHEMA_DRIFT — OpenAPI/Swagger specs', () => {
  it.each([
    'openapi.yaml',
    'openapi.yml',
    'openapi.json',
    'swagger.yaml',
    'swagger.yml',
    'swagger.json',
    'api-spec.yaml',
    'api-spec.json',
    'api_spec.yaml',
    'apispec.yaml',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'OPENAPI_SECURITY_SCHEMA_DRIFT')).toBe(true)
  })

  it.each([
    'openapi/v2.yaml',
    'swagger/definitions.yaml',
    'api-contracts/service.yaml',
  ])('flags file in openapi directory: %s', (file) => {
    expect(hasRule(scan([file]), 'OPENAPI_SECURITY_SCHEMA_DRIFT')).toBe(true)
  })

  it.each([
    'tests/fixtures/openapi.yaml',
    'tests/mocks/swagger.json',
    'examples/api-spec.yaml',
    'fixtures/openapi.json',
  ])('excludes test/mock/example directories: %s', (file) => {
    expect(hasRule(scan([file]), 'OPENAPI_SECURITY_SCHEMA_DRIFT')).toBe(false)
  })

  it('records correct severity (medium)', () => {
    const result = scan(['openapi.yaml'])
    const f = result.findings.find((f) => f.ruleId === 'OPENAPI_SECURITY_SCHEMA_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// WEBHOOK_VALIDATION_DRIFT
// ---------------------------------------------------------------------------

describe('WEBHOOK_VALIDATION_DRIFT — webhook HMAC and signature config', () => {
  it.each([
    'webhook.config.js',
    'webhook.config.ts',
    'webhook.config.json',
    'webhooks.config.js',
    'webhooks.config.json',
    'webhook-validation.json',
    'webhook_validation.json',
    'webhook-security.yaml',
    'webhook-security.json',
    'webhook-hmac.config.ts',
    'webhook-signing.config.ts',
    'webhook-handler.config.ts',
    'webhook-secret.config.ts',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'WEBHOOK_VALIDATION_DRIFT')).toBe(true)
  })

  it.each([
    'src/handlers/webhookHandler.ts',
    'src/webhooks/index.ts',
    'package.json',
  ])('does not flag non-webhook-config file: %s', (file) => {
    expect(hasRule(scan([file]), 'WEBHOOK_VALIDATION_DRIFT')).toBe(false)
  })

  it('records correct severity (medium)', () => {
    const result = scan(['webhook-validation.json'])
    const f = result.findings.find((f) => f.ruleId === 'WEBHOOK_VALIDATION_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// API_QUOTA_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('API_QUOTA_CONFIG_DRIFT — quota and timeout config', () => {
  it.each([
    'api-quota.json',
    'api-quota.yaml',
    'api_quota.json',
    'api_quota.yaml',
    'api-limits.json',
    'api_limits.json',
    'api-limits.yaml',
    'api_limits.yaml',
    'api-timeout.config.ts',
    'request-quota.yaml',
    'request-limit.config.ts',
    'quota.config.js',
    'api-budget.yaml',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'API_QUOTA_CONFIG_DRIFT')).toBe(true)
  })

  it.each([
    'src/services/quota.ts',
    'package.json',
    'README.md',
  ])('does not flag non-quota file: %s', (file) => {
    expect(hasRule(scan([file]), 'API_QUOTA_CONFIG_DRIFT')).toBe(false)
  })

  it('records correct severity (low)', () => {
    const result = scan(['api-quota.json'])
    const f = result.findings.find((f) => f.ruleId === 'API_QUOTA_CONFIG_DRIFT')!
    expect(f.severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// API_SCHEMA_VALIDATION_DRIFT
// ---------------------------------------------------------------------------

describe('API_SCHEMA_VALIDATION_DRIFT — request/response validation schemas', () => {
  it.each([
    'api-schema.json',
    'api-schema.yaml',
    'api_schema.json',
    'api_schema.yaml',
    'request-schema.json',
    'request-schema.yaml',
    'request_schema.json',
    'response-schema.json',
    'api-validation.config.ts',
    'api_validation.config.js',
    'request-validation.config.ts',
    'input-schema.json',
    'payload-schema.yaml',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'API_SCHEMA_VALIDATION_DRIFT')).toBe(true)
  })

  it.each([
    'src/schemas/user.ts',          // generic schema source code
    'database/schema.ts',           // DB schema
    'src/validation/email.ts',      // generic validation utility
    'package.json',
  ])('does not flag non-API-schema file: %s', (file) => {
    expect(hasRule(scan([file]), 'API_SCHEMA_VALIDATION_DRIFT')).toBe(false)
  })

  it('records correct severity (medium)', () => {
    const result = scan(['api-schema.json'])
    const f = result.findings.find((f) => f.ruleId === 'API_SCHEMA_VALIDATION_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// REST_API_SECURITY_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('REST_API_SECURITY_POLICY_DRIFT — REST security policy config', () => {
  it.each([
    'api-security.config.js',
    'api-security.config.ts',
    'api-security.config.json',
    'api-security.yaml',
    'api-security.json',
    'api_security.json',
    'rest-security.json',
    'rest-security.yaml',
    'api-policy.json',
    'api-policy.yaml',
    'api_policy.json',
    'api-access-control.config.ts',
    'api-acl.config.ts',
    'api-permissions.config.ts',
    'endpoint-security.config.ts',
  ])('flags %s', (file) => {
    expect(hasRule(scan([file]), 'REST_API_SECURITY_POLICY_DRIFT')).toBe(true)
  })

  it.each([
    'src/api/users.ts',
    'src/routes/health.ts',
    'package.json',
    'src/policies/email.ts',
  ])('does not flag non-security-policy file: %s', (file) => {
    expect(hasRule(scan([file]), 'REST_API_SECURITY_POLICY_DRIFT')).toBe(false)
  })

  it.each([
    'api-security/rules.json',
    'api_security/access.yaml',
    'api/security/config.json',
  ])('flags file in api-security directory: %s', (file) => {
    expect(hasRule(scan([file]), 'REST_API_SECURITY_POLICY_DRIFT')).toBe(true)
  })

  it('records correct severity (medium)', () => {
    const result = scan(['api-security.config.ts'])
    const f = result.findings.find((f) => f.ruleId === 'REST_API_SECURITY_POLICY_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Scoring and risk levels
// ---------------------------------------------------------------------------

describe('scanApiSecurityDrift — scoring', () => {
  it('returns riskScore 0 and riskLevel none for clean input', () => {
    const result = scan(['src/index.ts'])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
  })

  it('one high finding yields riskScore 15 (penalty per high)', () => {
    const result = scan(['rate-limit.config.ts'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('three high findings are capped at 45 (high cap)', () => {
    const result = scan([
      'rate-limit.config.ts',
      'api-keys.json',
      'graphql-shield.config.ts',
    ])
    expect(result.highCount).toBe(3)
    expect(result.riskScore).toBe(45)
    // score 45 maps to 'high' (threshold: score < 45 → medium, ≥ 45 → high)
    expect(result.riskLevel).toBe('high')
  })

  it('one medium finding yields riskScore 8', () => {
    const result = scan(['openapi.yaml'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })

  it('one low finding yields riskScore 4', () => {
    const result = scan(['api-quota.json'])
    expect(result.riskScore).toBe(4)
    expect(result.riskLevel).toBe('low')
  })

  it('combined high + medium findings accumulate correctly', () => {
    const result = scan([
      'rate-limit.config.ts',    // high  → +15
      'openapi.yaml',            // medium → +8
    ])
    expect(result.riskScore).toBe(23)
    expect(result.riskLevel).toBe('medium')
  })

  it('riskLevel critical at score >= 70', () => {
    const result = scan([
      'rate-limit.config.ts',
      'api-keys.json',
      'graphql-shield.config.ts',
      'openapi.yaml',
      'webhook-validation.json',
      'api-schema.json',
      'api-security.config.ts',
      'api-quota.json',
    ])
    expect(result.riskScore).toBeGreaterThanOrEqual(70)
    expect(result.riskLevel).toBe('critical')
  })

  it('riskScore is clamped to 100', () => {
    const result = scan([
      'rate-limit.config.ts',
      'api-keys.json',
      'graphql-shield.config.ts',
      'openapi.yaml',
      'webhook-validation.json',
      'api-schema.json',
      'api-security.config.ts',
      'api-quota.json',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('scanApiSecurityDrift — deduplication', () => {
  it('multiple rate-limit files produce one finding with correct matchCount', () => {
    const result = scan([
      'config/rate-limit.config.ts',
      'infra/throttle.yaml',
      'api-rate.config.js',
    ])
    const f = result.findings.filter((f) => f.ruleId === 'API_RATE_LIMIT_DRIFT')
    expect(f).toHaveLength(1)
    expect(f[0]!.matchCount).toBe(3)
    expect(f[0]!.matchedPath).toBe('config/rate-limit.config.ts')
  })

  it('each rule fires at most once regardless of how many paths match', () => {
    const result = scan([
      'openapi.yaml', 'openapi.json', 'swagger.yaml', 'api-spec.json',
    ])
    const openApiFindings = result.findings.filter((f) => f.ruleId === 'OPENAPI_SECURITY_SCHEMA_DRIFT')
    expect(openApiFindings).toHaveLength(1)
    expect(openApiFindings[0]!.matchCount).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('scanApiSecurityDrift — summary text', () => {
  it('clean result mentions "no API security"', () => {
    const result = scan(['src/users.ts'])
    expect(result.summary).toMatch(/no API security/)
  })

  it('high-severity result mentions the rule label', () => {
    const result = scan(['rate-limit.config.ts'])
    expect(result.summary).toMatch(/rate limit config/)
  })

  it('medium-only result mentions risk level', () => {
    const result = scan(['openapi.yaml'])
    expect(result.summary).toMatch(/medium|low|risk level/)
  })

  it('summary mentions "security review required" when high findings present', () => {
    const result = scan(['rate-limit.config.ts'])
    expect(result.summary).toMatch(/security review required/)
  })
})

// ---------------------------------------------------------------------------
// Multiple rules fire in a single scan
// ---------------------------------------------------------------------------

describe('scanApiSecurityDrift — multi-rule scenario', () => {
  it('all 8 rules can fire in one scan', () => {
    const result = scan([
      'rate-limit.config.ts',         // API_RATE_LIMIT_DRIFT
      'api-keys.json',                 // API_KEY_MANAGEMENT_DRIFT
      'graphql-shield.config.ts',      // GRAPHQL_SECURITY_DRIFT
      'openapi.yaml',                  // OPENAPI_SECURITY_SCHEMA_DRIFT
      'webhook-validation.json',       // WEBHOOK_VALIDATION_DRIFT
      'api-quota.json',                // API_QUOTA_CONFIG_DRIFT
      'api-schema.json',               // API_SCHEMA_VALIDATION_DRIFT
      'api-security.config.ts',        // REST_API_SECURITY_POLICY_DRIFT
    ])
    expect(result.totalFindings).toBe(8)
    expect(result.highCount).toBe(3)
    expect(result.mediumCount).toBe(4)
    expect(result.lowCount).toBe(1)
  })

  it('findings are returned in rule-definition order', () => {
    const result = scan([
      'api-security.config.ts',
      'rate-limit.config.ts',
    ])
    const ids = result.findings.map((f) => f.ruleId)
    const ruleOrder = API_SECURITY_RULES.map((r) => r.id)
    const filteredOrder = ruleOrder.filter((id) => ids.includes(id))
    expect(ids).toEqual(filteredOrder)
  })
})

// ---------------------------------------------------------------------------
// API_SECURITY_RULES registry integrity
// ---------------------------------------------------------------------------

describe('API_SECURITY_RULES registry integrity', () => {
  it('has exactly 8 rules', () => {
    expect(API_SECURITY_RULES).toHaveLength(8)
  })

  it('all rule IDs are unique', () => {
    const ids = API_SECURITY_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all rules have non-empty description and recommendation', () => {
    for (const rule of API_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const high   = API_SECURITY_RULES.filter((r) => r.severity === 'high').length
    const medium = API_SECURITY_RULES.filter((r) => r.severity === 'medium').length
    const low    = API_SECURITY_RULES.filter((r) => r.severity === 'low').length
    expect(high).toBe(3)
    expect(medium).toBe(4)
    expect(low).toBe(1)
  })
})
