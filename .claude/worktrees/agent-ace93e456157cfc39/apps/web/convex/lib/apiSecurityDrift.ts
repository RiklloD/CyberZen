// WS-65 — API Security Configuration Drift Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to API-layer security configuration files. This scanner covers the *API
// security control plane* — rate limiting, API key management, GraphQL
// security rules, OpenAPI security schemas, webhook HMAC validation, quota
// enforcement, and REST API security policies.
//
// DISTINCT from:
//   WS-60 securityConfigDriftResults — app-level security OPTIONS (JWT, CORS,
//                                       CSP, TLS options, session cookies, WAF)
//   WS-62 cloudSecurityDriftResults  — cloud infra security (IAM, KMS, network,
//                                       storage, API Gateway auth, secrets backend)
//   WS-35 cicdScanResults            — CI/CD pipeline misconfiguration
//
// WS-65 vs WS-60: WS-60 covers application-level security parameters (how the
//   web server configures its security posture). WS-65 covers API-specific
//   controls that govern per-request behaviour: rate limiting per endpoint,
//   API key lifecycle, GraphQL query depth limits, and OpenAPI security schemas.
//
// WS-65 vs WS-62: WS-62's API_GATEWAY_AUTH_DRIFT covers the infrastructure
//   gateway authorizer (Lambda authorizer, Cognito user pool). WS-65 covers
//   the application-layer API security sitting behind that gateway: per-route
//   rate limits, request validation schemas, and webhook signature verification.
//
// Covered rule groups (8 rules):
//
//   API_RATE_LIMIT_DRIFT          — Rate limiting / throttle config modified
//   API_KEY_MANAGEMENT_DRIFT      — API key rotation / provisioning config changed
//   GRAPHQL_SECURITY_DRIFT        — GraphQL depth/complexity/auth config changed ← user contribution
//   OPENAPI_SECURITY_SCHEMA_DRIFT — OpenAPI / Swagger security definitions changed
//   WEBHOOK_VALIDATION_DRIFT      — Webhook HMAC / signature validation config changed
//   API_QUOTA_CONFIG_DRIFT        — API quota / timeout enforcement config changed
//   API_SCHEMA_VALIDATION_DRIFT   — API request/response validation schema changed
//   REST_API_SECURITY_POLICY_DRIFT — REST API security policy / access-control config
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories (node_modules, dist, etc.) excluded.
//   • Same penalty/cap scoring model as WS-53–64 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Config-signal gating: topic keyword required so generic files (e.g.
//     `schema.ts`, `api.ts`) that happen to contain "api" are excluded.
//
// Exports:
//   isGraphQLSecurityConfig     — user contribution point (see TODO below)
//   scanApiSecurityDrift        — runs all 8 rules, returns ApiSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ApiSecurityRuleId =
  | 'API_RATE_LIMIT_DRIFT'
  | 'API_KEY_MANAGEMENT_DRIFT'
  | 'GRAPHQL_SECURITY_DRIFT'
  | 'OPENAPI_SECURITY_SCHEMA_DRIFT'
  | 'WEBHOOK_VALIDATION_DRIFT'
  | 'API_QUOTA_CONFIG_DRIFT'
  | 'API_SCHEMA_VALIDATION_DRIFT'
  | 'REST_API_SECURITY_POLICY_DRIFT'

export type ApiSecuritySeverity = 'high' | 'medium' | 'low'
export type ApiSecurityRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface ApiSecurityDriftFinding {
  ruleId: ApiSecurityRuleId
  severity: ApiSecuritySeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface ApiSecurityDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: ApiSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule (deduped). */
  findings: ApiSecurityDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

function getBasename(normalised: string): string {
  const parts = normalised.split('/')
  return parts[parts.length - 1] ?? ''
}

const VENDOR_DIRS = new Set([
  'node_modules', 'dist', 'build', 'vendor', '.yarn',
  '.git', 'coverage', 'out', '.next', '.nuxt',
  '.terraform', '.cdk', 'cdk.out', '__pycache__',
])

function isVendoredPath(normalised: string): boolean {
  return normalised.split('/').some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function startsWithAny(base: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => base.startsWith(p))
}

/** Returns true when the file has a config-signal extension (json/yaml/yml/
 *  toml/conf/cfg/ini/env/js/ts) that indicates it is a configuration file
 *  rather than source code that happens to have a security-related name. */
function isConfigFile(base: string): boolean {
  return /\.(json|yaml|yml|toml|conf|cfg|ini|env|js|ts|mjs|cjs)$/.test(base)
}

function pathContainsSegment(normalised: string, segments: readonly string[]): boolean {
  const parts = normalised.split('/')
  return segments.some((seg) => parts.includes(seg))
}

// ---------------------------------------------------------------------------
// API_RATE_LIMIT_DRIFT
// ---------------------------------------------------------------------------

const RATE_LIMIT_PREFIXES = [
  'rate-limit', 'rate_limit', 'ratelimit',
  'rate-limiting', 'rate_limiting', 'ratelimiting',
  'throttle', 'throttling',
  'api-rate', 'api_rate',
]

const RATE_LIMIT_EXACT = new Set([
  'rate-limit.json', 'rate-limit.yaml', 'rate-limit.yml', 'rate-limit.toml',
  'rate_limit.json', 'rate_limit.yaml', 'rate_limit.yml',
  'ratelimit.json', 'ratelimit.yaml', 'ratelimit.yml',
  'throttle.json', 'throttle.yaml', 'throttle.yml',
  'throttle.config.js', 'throttle.config.ts',
  'rate-limit.config.js', 'rate-limit.config.ts',
  'rate_limit.config.js', 'rate_limit.config.ts',
])

const RATE_LIMIT_DIR_SEGMENTS = ['rate-limit', 'rate-limiting', 'throttle', 'throttling']

function isRateLimitConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (RATE_LIMIT_EXACT.has(base)) return true
  if (pathContainsSegment(normalised.toLowerCase(), RATE_LIMIT_DIR_SEGMENTS) && isConfigFile(base)) return true
  return startsWithAny(base, RATE_LIMIT_PREFIXES) && isConfigFile(base)
}

// ---------------------------------------------------------------------------
// API_KEY_MANAGEMENT_DRIFT
// ---------------------------------------------------------------------------

const API_KEY_PREFIXES = [
  'api-key', 'api_key', 'apikey',
  'api-keys', 'api_keys', 'apikeys',
  'api-credential', 'api_credential', 'api-credentials', 'api_credentials',
  'api-token', 'api_token', 'api-tokens', 'api_tokens',
  'api-access', 'api_access',
  'api-auth', 'api_auth',
]

// Explicit exclusions: these start with api-auth but are handled by WS-62
const API_KEY_GATEWAY_EXCLUSIONS = [
  'api-gateway-auth', 'api_gateway_auth', 'apigateway-auth',
]

const API_KEY_EXACT = new Set([
  'api-keys.json', 'api-keys.yaml', 'api-keys.yml',
  'api_keys.json', 'api_keys.yaml', 'api_keys.yml',
  'apikeys.json', 'apikeys.yaml',
  'api-key-rotation.json', 'api-key-rotation.yaml',
  'api_key_rotation.json', 'api_key_rotation.yaml',
])

const API_KEY_DIR_SEGMENTS = ['api-keys', 'api_keys', 'apikeys', 'api-key-management']

function isApiKeyManagementConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (API_KEY_EXACT.has(base)) return true
  // Exclude gateway-level auth files already covered by WS-62
  if (API_KEY_GATEWAY_EXCLUSIONS.some((ex) => base.startsWith(ex))) return false
  if (pathContainsSegment(normalised.toLowerCase(), API_KEY_DIR_SEGMENTS) && isConfigFile(base)) return true
  return startsWithAny(base, API_KEY_PREFIXES) && isConfigFile(base)
}

// ---------------------------------------------------------------------------
// GRAPHQL_SECURITY_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents a GraphQL security
 * configuration file — one that controls depth limits, query complexity,
 * field-level authorisation, or persisted-query allowlists.
 *
 * Called by the GRAPHQL_SECURITY_DRIFT rule.
 *
 * GraphQL APIs are uniquely vulnerable to denial-of-service via deeply nested
 * queries, introspection leaks, and broken object-level authorisation. Files
 * that configure these protections are security-critical: changing depth or
 * complexity thresholds, disabling auth shields, or modifying persisted-query
 * allowlists can silently open attack surface.
 *
 * Files to detect (examples):
 *   graphql-shield.config.ts / graphql-shield.config.js
 *   graphql-depth-limit.config.ts / graphql-complexity.config.ts
 *   graphql-permissions.config.ts / graphql-auth.config.ts
 *   graphql-security.config.ts / graphql-protect.config.ts
 *   apollo.config.js / apollo.config.ts  (when in a security context)
 *   hasura-auth.yaml / hasura-metadata/databases.yaml
 *   graphql-query-limit.json / persisted-queries.json
 *   yoga.config.ts / yoga-security.config.ts  (GraphQL Yoga)
 *   mercurius.config.js  (Fastify GraphQL)
 *   pothos.config.ts  (Schema builder with auth plugin)
 *
 * Trade-offs to consider:
 *   - `graphql.config.ts` is often a tooling config (codegen), not a security
 *     config — should it match? (probably only if it also includes a security
 *     term)
 *   - `apollo.config.js` may be non-security (rover config) — security context
 *     may need path-based gating (e.g. inside /src/graphql/ or /config/)
 *   - Hasura metadata files (databases.yaml, actions.yaml) control permissions
 *     but are not always named with "security" or "auth"
 *
 * The current implementation requires either a specific GraphQL security term
 * OR the word "graphql" combined with a security qualifier.
 *
 * TODO: Implement this function. It should return true for GraphQL security
 * configuration files and false for non-security GraphQL tooling files.
 * The surrounding context (normalised path) is available if basename alone
 * is ambiguous (e.g. `apollo.config.js` in a `/graphql/security/` dir).
 */
export function isGraphQLSecurityConfig(normalisedPath: string): boolean {
  const base = getBasename(normalisedPath).toLowerCase()
  if (!isConfigFile(base)) return false

  // Specific GraphQL security tool identifiers (unambiguous)
  const GRAPHQL_SECURITY_TERMS = [
    'graphql-shield', 'graphql_shield',
    'graphql-depth', 'graphql_depth',
    'graphql-complexity', 'graphql_complexity',
    'graphql-permissions', 'graphql_permissions',
    'graphql-auth', 'graphql_auth',
    'graphql-security', 'graphql_security',
    'graphql-protect', 'graphql_protect',
    'graphql-query-limit', 'graphql_query_limit',
    'graphql-firewall', 'graphql_firewall',
    'hasura-auth', 'hasura_auth',
    'persisted-queries', 'persisted_queries',
  ]
  if (GRAPHQL_SECURITY_TERMS.some((t) => base.includes(t))) return true

  // Generic "graphql" combined with a security qualifier
  if (base.includes('graphql') || base.includes('apollo')) {
    const SECURITY_QUALIFIERS = [
      'security', 'auth', 'permission', 'shield', 'protect',
      'depth', 'complexity', 'limit', 'firewall', 'access',
    ]
    if (SECURITY_QUALIFIERS.some((q) => base.includes(q))) return true
  }

  // Path-context: graphql server config files in a security directory
  const pathLower = normalisedPath.toLowerCase()
  const SECURITY_DIR_SEGMENTS = [
    '/graphql/security/', '/graphql/auth/', '/graphql/permissions/',
    '/graphql-security/', '/graphql-auth/',
  ]
  if (SECURITY_DIR_SEGMENTS.some((seg) => pathLower.includes(seg)) && base.includes('graphql')) {
    return true
  }

  return false
}

// ---------------------------------------------------------------------------
// OPENAPI_SECURITY_SCHEMA_DRIFT
// ---------------------------------------------------------------------------

const OPENAPI_PREFIXES = [
  'openapi', 'swagger', 'api-spec', 'api_spec',
  'apispec', 'api-contract', 'api_contract',
  'openapi-spec', 'swagger-spec',
]

const OPENAPI_EXACT = new Set([
  'openapi.yaml', 'openapi.yml', 'openapi.json',
  'swagger.yaml', 'swagger.yml', 'swagger.json',
  'api-spec.yaml', 'api-spec.yml', 'api-spec.json',
  'api_spec.yaml', 'api_spec.yml', 'api_spec.json',
  'apispec.yaml', 'apispec.json',
])

const OPENAPI_DIR_SEGMENTS = ['openapi', 'swagger', 'api-spec', 'api-contracts']

function isOpenApiSecuritySchema(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  // Gating: exclude test/mock/fixture/example directories before any match
  const pathLower = normalised.toLowerCase()
  const EXCLUDED_DIRS = ['/test/', '/tests/', '/mock/', '/mocks/', '/fixture/', '/fixtures/', '/example/', '/examples/']
  if (EXCLUDED_DIRS.some((d) => pathLower.includes(d))) return false
  // Also check if the path starts with an excluded segment (no leading slash)
  const firstSegment = normalised.split('/')[0]?.toLowerCase() ?? ''
  const EXCLUDED_ROOTS = new Set(['test', 'tests', 'mock', 'mocks', 'fixture', 'fixtures', 'example', 'examples'])
  if (EXCLUDED_ROOTS.has(firstSegment)) return false
  if (OPENAPI_EXACT.has(base)) return true
  if (pathContainsSegment(pathLower, OPENAPI_DIR_SEGMENTS) && /\.(yaml|yml|json)$/.test(base)) return true
  return startsWithAny(base, OPENAPI_PREFIXES) && /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// WEBHOOK_VALIDATION_DRIFT
// ---------------------------------------------------------------------------

const WEBHOOK_PREFIXES = [
  'webhook.config', 'webhook_config', 'webhooks.config', 'webhooks_config',
  'webhook-validation', 'webhook_validation',
  'webhook-handler.config', 'webhook_handler_config',
  'webhook-secret', 'webhook_secret',
  'webhook-security', 'webhook_security',
  'webhook-hmac', 'webhook_hmac',
  'webhook-signing', 'webhook_signing',
]

const WEBHOOK_EXACT = new Set([
  'webhook.config.js', 'webhook.config.ts', 'webhook.config.json',
  'webhooks.config.js', 'webhooks.config.ts', 'webhooks.config.json',
  'webhook-validation.json', 'webhook_validation.json',
  'webhook-security.yaml', 'webhook-security.json',
])

const WEBHOOK_DIR_SEGMENTS = ['webhook-config', 'webhooks/config', 'webhook-handlers/config']

function isWebhookValidationConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (WEBHOOK_EXACT.has(base)) return true
  const pathLower = normalised.toLowerCase()
  if (WEBHOOK_DIR_SEGMENTS.some((seg) => pathLower.includes(seg)) && isConfigFile(base)) return true
  return startsWithAny(base, WEBHOOK_PREFIXES) && isConfigFile(base)
}

// ---------------------------------------------------------------------------
// API_QUOTA_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const QUOTA_PREFIXES = [
  'api-quota', 'api_quota',
  'api-limits', 'api_limits',
  'api-timeout', 'api_timeout',
  'request-quota', 'request_quota',
  'request-limit', 'request_limit',
  'quota.config', 'quota_config',
  'api-budget', 'api_budget',
]

const QUOTA_EXACT = new Set([
  'api-quota.json', 'api-quota.yaml', 'api-quota.yml',
  'api_quota.json', 'api_quota.yaml',
  'api-limits.json', 'api-limits.yaml',
  'api_limits.json', 'api_limits.yaml',
])

function isApiQuotaConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (QUOTA_EXACT.has(base)) return true
  return startsWithAny(base, QUOTA_PREFIXES) && isConfigFile(base)
}

// ---------------------------------------------------------------------------
// API_SCHEMA_VALIDATION_DRIFT
// ---------------------------------------------------------------------------

const SCHEMA_VALIDATION_PREFIXES = [
  'api-schema', 'api_schema',
  'request-schema', 'request_schema',
  'response-schema', 'response_schema',
  'api-validation', 'api_validation',
  'request-validation', 'request_validation',
  'input-schema', 'input_schema',
  'payload-schema', 'payload_schema',
  'api-body-schema', 'api_body_schema',
]

const SCHEMA_VALIDATION_EXACT = new Set([
  'api-schema.json', 'api-schema.yaml', 'api-schema.yml',
  'api_schema.json', 'api_schema.yaml',
  'request-schema.json', 'request-schema.yaml',
  'request_schema.json', 'request_schema.yaml',
])

function isApiSchemaValidationConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (SCHEMA_VALIDATION_EXACT.has(base)) return true
  return startsWithAny(base, SCHEMA_VALIDATION_PREFIXES) && isConfigFile(base)
}

// ---------------------------------------------------------------------------
// REST_API_SECURITY_POLICY_DRIFT
// ---------------------------------------------------------------------------

const REST_SECURITY_PREFIXES = [
  'api-security.config', 'api_security_config',
  'rest-security', 'rest_security',
  'http-security.config', 'http_security_config',
  'api-policy', 'api_policy',
  'api-access-control', 'api_access_control',
  'api-acl', 'api_acl',
  'api-permissions', 'api_permissions',
  'endpoint-security', 'endpoint_security',
]

const REST_SECURITY_EXACT = new Set([
  'api-security.config.js', 'api-security.config.ts', 'api-security.config.json',
  'api-security.yaml', 'api-security.yml', 'api-security.json',
  'api_security.json', 'api_security.yaml',
  'rest-security.json', 'rest-security.yaml',
  'api-policy.json', 'api-policy.yaml',
  'api_policy.json', 'api_policy.yaml',
])

const REST_SECURITY_DIR_SEGMENTS = ['api-security', 'api_security', 'api/security', 'api/policies']

function isRestApiSecurityPolicy(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (REST_SECURITY_EXACT.has(base)) return true
  const pathLower = normalised.toLowerCase()
  if (REST_SECURITY_DIR_SEGMENTS.some((seg) => pathLower.includes(seg)) && isConfigFile(base)) return true
  return startsWithAny(base, REST_SECURITY_PREFIXES) && isConfigFile(base)
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface ApiSecurityRule {
  id: ApiSecurityRuleId
  severity: ApiSecuritySeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const API_SECURITY_RULES: readonly ApiSecurityRule[] = [
  {
    id: 'API_RATE_LIMIT_DRIFT',
    severity: 'high',
    description:
      'API rate limiting or throttle configuration modified — rate limiting is the primary defence against brute-force, credential-stuffing, and denial-of-service attacks on API endpoints. Raising or removing rate limits silently lowers the cost of an attack against every authenticated and unauthenticated endpoint in your service.',
    recommendation:
      'Review any increased per-IP or per-user request thresholds. Verify that authentication and password-reset endpoints still have the most restrictive limits. Confirm that burst allowances and window periods were not loosened. Consider whether the change was made in response to a legitimate capacity need or represents a configuration error.',
    matches: isRateLimitConfig,
  },
  {
    id: 'API_KEY_MANAGEMENT_DRIFT',
    severity: 'high',
    description:
      'API key management or rotation configuration modified — API keys that are never rotated, have no expiry, or are provisioned with excessive permissions are a high-value target for attackers. Changes to key rotation schedules, provisioning policies, or key scopes can significantly increase the blast radius of a compromised key.',
    recommendation:
      'Verify that no key rotation intervals were extended or disabled. Confirm that key scope was not broadened to include additional API endpoints or operations. Check that minimum-privilege provisioning rules remain intact. Ensure that revocation procedures for compromised keys were not weakened.',
    matches: isApiKeyManagementConfig,
  },
  {
    id: 'GRAPHQL_SECURITY_DRIFT',
    severity: 'high',
    description:
      'GraphQL security configuration modified — GraphQL APIs are uniquely susceptible to denial-of-service via deeply nested queries, introspection-based reconnaissance, and broken field-level authorisation. Disabling depth limits, raising complexity thresholds, or modifying the GraphQL permission shield can expose the entire API to abuse.',
    recommendation:
      'Check that query depth limits and complexity thresholds were not raised or removed. Verify that the GraphQL permission shield or auth middleware is still applied to all resolvers. Confirm that introspection is still disabled in production if it was previously disabled. Review any new resolver or mutation added to the schema for missing authorisation rules.',
    matches: isGraphQLSecurityConfig,
  },
  {
    id: 'OPENAPI_SECURITY_SCHEMA_DRIFT',
    severity: 'medium',
    description:
      'OpenAPI or Swagger security definition modified — the OpenAPI security schema is the machine-readable contract for which authentication schemes and scopes are required per endpoint. Changes to `securitySchemes`, `security` arrays, or `components/securitySchemes` can retroactively remove authentication requirements from existing endpoints without any code change.',
    recommendation:
      'Review any endpoints where the `security` array was reduced or removed — removing the array makes the endpoint public regardless of the implementation. Verify that new endpoints declare the correct security scheme. Confirm that OAuth scopes were not narrowed or substituted for less restrictive alternatives. Use an OpenAPI diff tool (e.g. openapi-diff) to surface breaking security changes.',
    matches: isOpenApiSecuritySchema,
  },
  {
    id: 'WEBHOOK_VALIDATION_DRIFT',
    severity: 'medium',
    description:
      'Webhook HMAC validation or signature verification configuration modified — webhook endpoints that do not validate incoming signatures can be replayed, spoofed, or used to trigger privileged actions without a legitimate event source. Changes to HMAC secrets, validation logic, or tolerance windows affect every inbound webhook.',
    recommendation:
      'Verify that signature validation was not disabled or weakened (e.g. `strict: false`, removed `crypto.timingSafeEqual`). Confirm that the HMAC secret was not replaced with a weaker or shorter value. Check that replay-attack protection (timestamp tolerance) was not significantly extended. Ensure that failures in signature validation still result in a `400` response and are logged.',
    matches: isWebhookValidationConfig,
  },
  {
    id: 'API_QUOTA_CONFIG_DRIFT',
    severity: 'low',
    description:
      'API quota or timeout configuration modified — quota and timeout configurations govern how many requests a client may make over a billing period and how long the server waits for slow requests. Raising quotas or extending timeouts can enable resource exhaustion attacks and increase infrastructure cost exposure.',
    recommendation:
      'Review any increased monthly or daily quota allocations for specific API clients or tiers. Confirm that server-side timeout values were not significantly extended, which can increase memory and compute pressure under load. Verify that any quota changes are aligned with approved customer tiers.',
    matches: isApiQuotaConfig,
  },
  {
    id: 'API_SCHEMA_VALIDATION_DRIFT',
    severity: 'medium',
    description:
      'API request or response validation schema modified — input validation schemas are the last line of defence against injection attacks, type confusion, and unexpected payload shapes. Loosening schema constraints (removing required fields, widening types, removing format validators) can expose downstream services to malformed or malicious inputs.',
    recommendation:
      'Verify that no `required` fields were removed from request bodies — missing required-field validation is a common injection path. Confirm that `additionalProperties: false` was not changed to `true` for security-sensitive objects. Check that string length limits, pattern constraints, and enum restrictions were not removed. Review any new nullable fields added to authenticated endpoints.',
    matches: isApiSchemaValidationConfig,
  },
  {
    id: 'REST_API_SECURITY_POLICY_DRIFT',
    severity: 'medium',
    description:
      'REST API security policy or access-control configuration modified — API security policies codify which HTTP methods, IP ranges, client certificates, or authentication tokens are permitted per endpoint group. Modifying these policies can silently change the effective access control for all endpoints covered by the policy.',
    recommendation:
      'Review any new IP allowlist entries or removed IP restrictions. Verify that HTTP method restrictions were not loosened (e.g. allowing `DELETE` or `PUT` where previously `GET`-only). Confirm that mTLS client certificate requirements were not disabled. Check that any new endpoints added to the policy have the correct security posture.',
    matches: isRestApiSecurityPolicy,
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–64 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<ApiSecuritySeverity, number> = {
  high:   15,
  medium:  8,
  low:     4,
}

const PENALTY_CAP: Record<ApiSecuritySeverity, number> = {
  high:   45,
  medium: 25,
  low:    15,
}

function toRiskLevel(score: number): ApiSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_SHORT_LABEL: Record<ApiSecurityRuleId, string> = {
  API_RATE_LIMIT_DRIFT:           'rate limit config',
  API_KEY_MANAGEMENT_DRIFT:       'API key management',
  GRAPHQL_SECURITY_DRIFT:         'GraphQL security config',
  OPENAPI_SECURITY_SCHEMA_DRIFT:  'OpenAPI security schema',
  WEBHOOK_VALIDATION_DRIFT:       'webhook validation config',
  API_QUOTA_CONFIG_DRIFT:         'API quota config',
  API_SCHEMA_VALIDATION_DRIFT:    'API schema validation',
  REST_API_SECURITY_POLICY_DRIFT: 'REST API security policy',
}

function buildSummary(
  findings: ApiSecurityDriftFinding[],
  riskLevel: ApiSecurityRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no API security configuration file changes detected.`
  }
  const highFindings = findings.filter((f) => f.severity === 'high')
  if (highFindings.length > 0) {
    const labels  = highFindings.map((f) => RULE_SHORT_LABEL[f.ruleId])
    const unique  = [...new Set(labels)]
    const joined  =
      unique.length <= 2
        ? unique.join(' and ')
        : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return (
      `${findings.length} API security configuration file${findings.length === 1 ? '' : 's'} modified ` +
      `including ${joined} — security review required before merge.`
    )
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${findings.length} API security configuration change${findings.length === 1 ? '' : 's'} across ` +
    `${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which API security configuration files
 * were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor/build directories are excluded.
 * - Each rule fires at most once per scan (deduplicated per rule ID).
 * - The finding records the first matched path and total count of matched paths.
 */
export function scanApiSecurityDrift(filePaths: string[]): ApiSecurityDriftResult {
  const ruleAccumulator = new Map<ApiSecurityRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of API_SECURITY_RULES) {
      if (!rule.matches(normalised)) continue
      const acc = ruleAccumulator.get(rule.id)
      if (acc) {
        acc.count++
      } else {
        ruleAccumulator.set(rule.id, { firstPath: rawPath, count: 1 })
      }
    }
  }

  // Build findings in rule-definition order for consistent output
  const findings: ApiSecurityDriftFinding[] = []
  for (const rule of API_SECURITY_RULES) {
    const acc = ruleAccumulator.get(rule.id)
    if (!acc) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    acc.firstPath,
      matchCount:     acc.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  // Score
  const penaltyBySeverity = new Map<ApiSecuritySeverity, number>([
    ['high', 0], ['medium', 0], ['low', 0],
  ])
  for (const f of findings) {
    const current = penaltyBySeverity.get(f.severity) ?? 0
    penaltyBySeverity.set(
      f.severity,
      Math.min(current + PENALTY_PER[f.severity], PENALTY_CAP[f.severity]),
    )
  }
  const riskScore = Math.min(
    100,
    (penaltyBySeverity.get('high')   ?? 0) +
    (penaltyBySeverity.get('medium') ?? 0) +
    (penaltyBySeverity.get('low')    ?? 0),
  )

  const riskLevel    = toRiskLevel(riskScore)
  const highCount    = findings.filter((f) => f.severity === 'high').length
  const mediumCount  = findings.filter((f) => f.severity === 'medium').length
  const lowCount     = findings.filter((f) => f.severity === 'low').length

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary: buildSummary(findings, riskLevel, filePaths.filter((p) => p.trim()).length),
  }
}
