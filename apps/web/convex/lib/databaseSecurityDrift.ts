// WS-64 — Database Security Configuration Drift Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to database authentication, access control, TLS, and security configuration
// files. This scanner covers the *database security* layer — auth configuration
// for PostgreSQL, MySQL/MariaDB, MongoDB, Redis, Elasticsearch/OpenSearch, TLS
// connection settings, connection pool/proxy security config, and
// security-sensitive database migration files.
//
// DISTINCT from:
//   WS-33 iacScanResults         — content-level IaC rule checks (reads YAML *content*)
//   WS-60 securityConfigDrift    — application-layer security config (JWT/CORS/TLS for
//                                   the web server, NOT the database)
//   WS-62 cloudSecurityDrift     — cloud-provider IAM/KMS/VPC/S3 configuration
//   WS-63 containerHardeningDrift — Kubernetes RBAC/NetworkPolicy/PodSecurity
//
// WS-64 vs WS-60: WS-60 covers application-level TLS (the HTTPS server's TLS
//   settings). WS-64 covers database-level TLS (the database connection's SSL/TLS
//   settings in pg_hba.conf, mysql.conf ssl options, etc.) and database
//   authentication methods (password, md5, scram-sha-256, trust, peer, ident).
//
// Covered rule groups (8 rules):
//
//   POSTGRES_AUTH_CONFIG_DRIFT   — pg_hba.conf / postgresql.conf auth changes
//   MYSQL_AUTH_CONFIG_DRIFT      — my.cnf / mysql.conf / mysqld.cnf auth changes
//   MONGO_AUTH_CONFIG_DRIFT      — mongod.conf / mongos.conf auth changes
//   REDIS_AUTH_CONFIG_DRIFT      — redis.conf / redis.acl / sentinel.conf changes
//   DATABASE_TLS_CONFIG_DRIFT    — Database TLS/SSL connection config changes
//   CONNECTION_POOL_CONFIG_DRIFT — pgbouncer / pgpool / ProxySQL security config
//   DB_MIGRATION_SECURITY_DRIFT  — Security-sensitive DB migrations  ← user contribution
//   ELASTICSEARCH_SECURITY_DRIFT — Elasticsearch / OpenSearch / Kibana security config
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories (node_modules, dist, .terraform, etc.) excluded.
//   • Same penalty/cap scoring model as WS-53–63 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Extension gating: each rule requires a configuration-signal extension to
//     exclude source-code files (e.g. mysql.ts utility won't trigger the rule).
//
// Exports:
//   isDatabaseMigrationSecurityFile — user contribution point (see TODO below)
//   scanDatabaseSecurityDrift       — runs all 8 rules, returns DatabaseSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DatabaseSecurityRuleId =
  | 'POSTGRES_AUTH_CONFIG_DRIFT'
  | 'MYSQL_AUTH_CONFIG_DRIFT'
  | 'MONGO_AUTH_CONFIG_DRIFT'
  | 'REDIS_AUTH_CONFIG_DRIFT'
  | 'DATABASE_TLS_CONFIG_DRIFT'
  | 'CONNECTION_POOL_CONFIG_DRIFT'
  | 'DB_MIGRATION_SECURITY_DRIFT'
  | 'ELASTICSEARCH_SECURITY_DRIFT'

export type DatabaseSecuritySeverity = 'critical' | 'high' | 'medium'
export type DatabaseSecurityRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface DatabaseSecurityFinding {
  ruleId: DatabaseSecurityRuleId
  severity: DatabaseSecuritySeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface DatabaseSecurityDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: DatabaseSecurityRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  /** One finding per triggered rule (deduped). */
  findings: DatabaseSecurityFinding[]
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

function includesAny(str: string, terms: readonly string[]): boolean {
  return terms.some((t) => str.includes(t))
}

function isConfFile(base: string): boolean {
  return /\.(conf|cnf|ini|cfg)$/.test(base)
}

function isYamlFile(base: string): boolean {
  return /\.(yaml|yml)$/.test(base)
}

function isConfOrYaml(base: string): boolean {
  return isConfFile(base) || isYamlFile(base)
}

// ---------------------------------------------------------------------------
// POSTGRES_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

/** Canonical PostgreSQL auth / config file names (always match, no prefix required). */
const POSTGRES_EXACT = new Set([
  'pg_hba.conf', 'pg_ident.conf',
  'postgresql.conf', 'postgresql.auto.conf',
  'recovery.conf',             // legacy auth and replication config
  'pg_hba.conf.bak',           // backup of pg_hba still triggers review
])

const POSTGRES_PREFIXES = [
  'pg_hba', 'pg_ident', 'postgresql',
  'postgres-', 'postgres_', 'pg-', 'pg_',
]

const POSTGRES_DIR_TERMS = [
  '/postgresql/', '/postgres/', '/pg/', '/pgdata/',
  'postgresql.conf.d/', 'pg_hba.conf.d/',
]

function isPostgresAuthConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (POSTGRES_EXACT.has(base)) return true
  if (startsWithAny(base, POSTGRES_PREFIXES) && isConfOrYaml(base)) return true
  if (POSTGRES_DIR_TERMS.some((d) => lower.includes(d)) && isConfFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// MYSQL_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const MYSQL_EXACT = new Set([
  'my.cnf', 'my.ini', 'mysqld.cnf', 'mysql.conf',
  'mariadb.conf', 'mysqld_safe.conf',
  '.my.cnf',    // user-level MySQL credentials file
  'mysql_init.sql', 'init.sql',
])

const MYSQL_PREFIXES = [
  'mysql', 'mysqld', 'mariadb', 'my-',
]

const MYSQL_DIR_TERMS = [
  '/mysql/', '/mysql.conf.d/', '/mysqld.conf.d/',
  '/mariadb/', '/mariadb.conf.d/',
]

function isMysqlAuthConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (MYSQL_EXACT.has(base)) return true
  if (startsWithAny(base, MYSQL_PREFIXES) && isConfFile(base)) return true
  if (MYSQL_DIR_TERMS.some((d) => lower.includes(d)) && isConfFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// MONGO_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const MONGO_EXACT = new Set([
  'mongod.conf', 'mongos.conf', 'mongo.conf',
  'mongod.yaml', 'mongos.yaml',
])

const MONGO_PREFIXES = [
  'mongod', 'mongos', 'mongo-', 'mongo_', 'mongodb-', 'mongodb_',
]

const MONGO_DIR_TERMS = ['/mongodb/', '/mongod/', '/mongo/']

function isMongoAuthConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (MONGO_EXACT.has(base)) return true
  if (startsWithAny(base, MONGO_PREFIXES) && isConfOrYaml(base)) return true
  if (MONGO_DIR_TERMS.some((d) => lower.includes(d)) && isConfOrYaml(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// REDIS_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const REDIS_EXACT = new Set([
  'redis.conf', 'redis.acl', 'sentinel.conf',
  'redis-sentinel.conf', 'redis_sentinel.conf',
  'redis-cluster.conf', 'redis_cluster.conf',
])

const REDIS_PREFIXES = [
  'redis', 'sentinel', 'redis-', 'redis_',
]

const REDIS_DIR_TERMS = ['/redis/', '/redis.conf.d/']

function isRedisAuthConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (REDIS_EXACT.has(base)) return true
  // redis.conf + redis.acl are exact; redis- prefixes with conf/acl extension
  if (startsWithAny(base, REDIS_PREFIXES) && /\.(conf|acl|ini)$/.test(base)) return true
  if (REDIS_DIR_TERMS.some((d) => lower.includes(d)) && /\.(conf|acl|ini)$/.test(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// DATABASE_TLS_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const DB_TLS_TERMS = [
  'db-ssl', 'db_ssl', 'db-tls', 'db_tls',
  'database-ssl', 'database_ssl', 'database-tls', 'database_tls',
  'postgres-ssl', 'postgres_ssl', 'postgres-tls', 'postgres_tls',
  'mysql-ssl', 'mysql_ssl', 'mysql-tls', 'mysql_tls',
  'mongo-tls', 'mongo_tls', 'redis-tls', 'redis_tls',
  'pg-ssl', 'pg_ssl', 'pg-tls', 'pg_tls',
  'db-cert', 'db_cert',
]

const DB_TLS_EXACT = new Set([
  'database-ssl.conf', 'database_ssl.conf',
  'db-tls.conf', 'db_tls.conf',
  'postgres-ssl.conf', 'postgres_ssl.conf',
  'mysql-ssl.cnf', 'mysql_ssl.cnf',
])

function isDatabaseTlsConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (DB_TLS_EXACT.has(base)) return true
  if (includesAny(base, DB_TLS_TERMS) && isConfOrYaml(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// CONNECTION_POOL_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const POOL_EXACT = new Set([
  'pgbouncer.ini', 'pgbouncer.conf', 'userlist.txt',
  'pgpool.conf', 'pgpool2.conf', 'pool_hba.conf',
  'proxysql.cnf', 'proxysql-admin.cnf',
  'haproxy.cfg', 'haproxy.conf',   // when used as a DB proxy
])

const POOL_PREFIXES = [
  'pgbouncer', 'pgpool', 'proxysql', 'pg-pool', 'pg_pool',
  'connection-pool', 'connection_pool', 'db-proxy', 'db_proxy',
]

const POOL_DIR_TERMS = [
  '/pgbouncer/', '/pgpool/', '/proxysql/',
  'pgbouncer.conf.d/', 'pgpool.conf.d/',
]

function isConnectionPoolConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (POOL_EXACT.has(base)) return true
  if (startsWithAny(base, POOL_PREFIXES) && isConfFile(base)) return true
  if (POOL_DIR_TERMS.some((d) => lower.includes(d)) && isConfFile(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// DB_MIGRATION_SECURITY_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents a security-sensitive
 * database migration file.
 *
 * Called by the DB_MIGRATION_SECURITY_DRIFT rule.
 *
 * Database migrations that create or modify users, roles, permissions, grants,
 * or revocations directly affect who can access what data. A migration that
 * unintentionally grants an overly broad privilege or creates a service account
 * without a password can compromise the entire database.
 *
 * Files to detect (examples — common migration frameworks):
 *   db/migrate/20240101_add_user_role.rb          (Rails ActiveRecord)
 *   migrations/0042_grant_read_user.sql           (plain SQL)
 *   alembic/versions/abc123_add_auth_schema.py    (Python Alembic)
 *   flyway/V1__create_roles.sql                   (Flyway)
 *   liquibase/changelogs/add_permissions.xml       (Liquibase)
 *   prisma/migrations/20240101_auth_table/migration.sql (Prisma)
 *
 * Trade-offs to consider:
 *   - Should ALL migrations in a `migrations/` directory match? (too broad — most
 *     migrations are schema-only and not security-sensitive)
 *   - Should the security signal come from the filename, directory, or both?
 *   - Which keywords indicate a security-relevant migration?
 *     Strong signals: auth, permission, role, grant, revoke, privilege, password, token, secret
 *     Weaker signals: user, account, access, policy
 *   - Should Prisma's `migration.sql` inside a security-named directory match?
 *
 * The current implementation requires a security keyword in the file *basename*
 * (not just the directory) and a recognised migration file extension or directory
 * pattern, to avoid matching every migration file in a security-named directory.
 */
export function isDatabaseMigrationSecurityFile(normalisedPath: string): boolean {
  const base  = getBasename(normalisedPath).toLowerCase()
  const lower = normalisedPath.toLowerCase()

  // Must be a SQL, Ruby, Python, TypeScript/JavaScript, or XML migration file
  const MIGRATION_EXTS = /\.(sql|rb|py|ts|js|xml|yaml|yml)$/
  if (!MIGRATION_EXTS.test(base)) return false

  // Must be inside a recognised migration directory.
  // Prepend '/' so that `migrations/foo.sql` (no leading slash) matches `/migrations/`
  // without also matching `some-migrations/foo.sql`.
  const MIGRATION_DIRS = [
    '/migrations/', '/migrate/',
    '/db/migrate/', '/db/migrations/',
    '/alembic/versions/', '/flyway/', '/liquibase/', '/changelogs/',
    '/prisma/migrations/', '/knex/migrations/', '/sequelize/migrations/',
    '/typeorm/migrations/', '/django/migrations/',
  ]
  const withSlash = '/' + lower
  const inMigrationDir = MIGRATION_DIRS.some((d) => withSlash.includes(d))
  if (!inMigrationDir) return false

  // Security-sensitive keywords checked in:
  //   1. the file basename (conventional naming: 0042_add_user_role.sql)
  //   2. the immediate parent directory name (Prisma-style: add_auth_table/migration.sql)
  const SECURITY_KEYWORDS = [
    'auth', 'permission', 'role', 'grant', 'revoke', 'privilege',
    'password', 'token', 'secret', 'credential', 'policy', 'access',
    'user', 'account', 'admin', 'security',
  ]
  const parts     = lower.split('/')
  const parentDir = parts.length >= 2 ? (parts[parts.length - 2] ?? '') : ''
  return SECURITY_KEYWORDS.some((kw) => base.includes(kw) || parentDir.includes(kw))
}

// ---------------------------------------------------------------------------
// ELASTICSEARCH_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const ES_EXACT = new Set([
  'elasticsearch.yml', 'elasticsearch.yaml',
  'opensearch.yml', 'opensearch.yaml',
  'kibana.yml', 'kibana.yaml',
  'logstash.yml', 'logstash.yaml',
  'elasticsearch.keystore',   // stores secure settings
])

const ES_PREFIXES = [
  'elasticsearch', 'opensearch', 'kibana', 'logstash',
  'es-security', 'es_security', 'elastic-security', 'elastic_security',
]

const ES_DIR_TERMS = [
  '/elasticsearch/', '/opensearch/', '/kibana/',
  '/elastic/', '/elastic-stack/', '/elk/',
]

function isElasticsearchSecurityConfig(normalised: string): boolean {
  const base  = getBasename(normalised).toLowerCase()
  const lower = normalised.toLowerCase()
  if (ES_EXACT.has(base)) return true
  if (startsWithAny(base, ES_PREFIXES) && (isYamlFile(base) || isConfFile(base))) return true
  if (ES_DIR_TERMS.some((d) => lower.includes(d)) && (isYamlFile(base) || isConfFile(base))) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface DatabaseSecurityRule {
  id: DatabaseSecurityRuleId
  severity: DatabaseSecuritySeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const DATABASE_SECURITY_RULES: readonly DatabaseSecurityRule[] = [
  {
    id: 'POSTGRES_AUTH_CONFIG_DRIFT',
    severity: 'critical',
    description:
      'PostgreSQL authentication configuration (`pg_hba.conf`, `postgresql.conf`) modified — `pg_hba.conf` is the primary auth control for all PostgreSQL databases. A single `trust` or `md5` entry replacing `scram-sha-256` can silently disable password authentication for a specific host or user range. Changes to `listen_addresses` or `ssl` settings in `postgresql.conf` can expose the database to the network or disable encryption in transit.',
    recommendation:
      'Review every modified `pg_hba.conf` record for new `trust` authentication methods (which bypass passwords entirely). Verify that no records grant access from `all` hosts without requiring a strong auth method. Confirm that `ssl = on` remains set in `postgresql.conf` and that `ssl_min_protocol_version` was not lowered. Audit any new superuser password configurations.',
    matches: isPostgresAuthConfig,
  },
  {
    id: 'MYSQL_AUTH_CONFIG_DRIFT',
    severity: 'critical',
    description:
      'MySQL/MariaDB authentication configuration (`my.cnf`, `mysqld.cnf`) modified — MySQL configuration files control authentication plugins, network binding, TLS settings, and password validation. Changes to `skip-grant-tables`, `skip-networking`, or authentication plugin settings can disable access controls for all databases on the server. Binding to `0.0.0.0` exposes MySQL to external networks.',
    recommendation:
      'Verify that `skip-grant-tables` and `skip-networking` were not added (these disable all authentication). Confirm that `bind-address` was not changed to `0.0.0.0` or `::` without a compensating firewall rule. Check that `default_authentication_plugin` was not changed from `caching_sha2_password` to the older, weaker `mysql_native_password`. Ensure `require_secure_transport = ON` remains set.',
    matches: isMysqlAuthConfig,
  },
  {
    id: 'MONGO_AUTH_CONFIG_DRIFT',
    severity: 'high',
    description:
      'MongoDB authentication configuration (`mongod.conf`, `mongos.conf`) modified — MongoDB configuration controls whether authentication is enabled, the network interfaces it binds to, and TLS settings. Setting `security.authorization: disabled` removes all authentication, and changing `net.bindIp` to `0.0.0.0` has historically been the root cause of major MongoDB data exposure incidents.',
    recommendation:
      'Verify that `security.authorization` was not changed from `enabled` to `disabled`. Confirm that `net.bindIp` was not broadened to `0.0.0.0` without a compensating network restriction. Check that `net.tls.mode` remains `requireTLS` or `allowTLS`. Review any changes to `security.keyFile` or `security.clusterAuthMode` for replica set and sharded cluster authentication.',
    matches: isMongoAuthConfig,
  },
  {
    id: 'REDIS_AUTH_CONFIG_DRIFT',
    severity: 'high',
    description:
      'Redis authentication configuration (`redis.conf`, `redis.acl`) modified — Redis is frequently misconfigured with no authentication. Changes to `requirepass`, ACL rules, or `protected-mode` can silently remove the only access control layer. Redis ACL files (`.acl`) control which users can execute which commands and access which key patterns — changes can grant excessive privileges to service accounts.',
    recommendation:
      'Verify that `requirepass` was not removed or set to an empty string. Confirm that `protected-mode no` was not added (this disables the loopback restriction). Review any modified ACL user rules for new `nopass` flags or `~*` (all key) / `+@all` (all command) permissions being granted to non-admin users. Ensure Sentinel `requirepass` matches the cluster password.',
    matches: isRedisAuthConfig,
  },
  {
    id: 'DATABASE_TLS_CONFIG_DRIFT',
    severity: 'high',
    description:
      'Database TLS/SSL connection configuration modified — database TLS configuration files control whether connections between application servers and database servers are encrypted in transit. Disabling TLS or lowering the minimum protocol version allows credentials and query results to be transmitted in plaintext over the network, exposable to any network-level attacker.',
    recommendation:
      'Verify that `sslmode` was not changed from `require` or `verify-full` to `prefer`, `allow`, or `disable`. Confirm that minimum TLS version was not lowered (e.g. `TLSv1.3` → `TLSv1.1`). Check that client certificate verification (`ssl_ca_file`, `ssl_cert_file`) was not removed. Validate that cipher suite changes do not include known-weak ciphers (RC4, MD5-based, export-grade).',
    matches: isDatabaseTlsConfig,
  },
  {
    id: 'CONNECTION_POOL_CONFIG_DRIFT',
    severity: 'high',
    description:
      'Database connection pool or proxy security configuration modified — pgBouncer, pgPool-II, and ProxySQL manage the authentication between application servers and the database. Changes to pool authentication mode, user lists, or TLS settings can allow unauthenticated connections, expose credentials, or bypass the database\'s own authentication layer entirely.',
    recommendation:
      'For pgBouncer: verify that `auth_type` was not changed from `scram-sha-256` to `md5` or `trust`. Confirm that `userlist.txt` was not modified to add new users or change passwords. For ProxySQL: review any changes to `mysql_users` table definitions. Ensure TLS settings for frontend connections were not downgraded. Validate that administrative interfaces remain bound to localhost only.',
    matches: isConnectionPoolConfig,
  },
  {
    id: 'DB_MIGRATION_SECURITY_DRIFT',
    severity: 'medium',
    description:
      'Security-sensitive database migration file modified — database migrations that create or alter users, roles, grants, revocations, or password policies directly affect who can access what data in the database. A migration that grants an overly broad privilege or creates a service account without a password can persist indefinitely and is difficult to detect post-merge.',
    recommendation:
      'Review every GRANT statement in the migration for least-privilege compliance — service accounts should receive only the minimum permissions needed. Verify that no REVOKE statements unintentionally remove security controls. Confirm that new user accounts have password requirements and that superuser privileges are not granted to application service accounts. Ensure the migration is idempotent and reversible.',
    matches: isDatabaseMigrationSecurityFile,
  },
  {
    id: 'ELASTICSEARCH_SECURITY_DRIFT',
    severity: 'medium',
    description:
      'Elasticsearch, OpenSearch, or Kibana security configuration modified — Elasticsearch security settings control network exposure, TLS for the transport and HTTP layer, authentication realm configuration, and role-based access control. Elasticsearch has historically been a major source of data breach incidents when deployed with no authentication and bound to public interfaces.',
    recommendation:
      'Verify that `xpack.security.enabled` was not set to `false`. Confirm that `network.host` was not changed to `0.0.0.0` or a public IP without compensating firewall rules. Check that TLS settings (`xpack.security.transport.ssl.enabled`, `xpack.security.http.ssl.enabled`) were not disabled. Review any changes to realm configuration or role mapping files for newly granted permissions.',
    matches: isElasticsearchSecurityConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–63 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<DatabaseSecuritySeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
}

const PENALTY_CAP: Record<DatabaseSecuritySeverity, number> = {
  critical: 75,
  high:     35,
  medium:   20,
}

function toRiskLevel(score: number): DatabaseSecurityRiskLevel {
  if (score === 0)  return 'none'
  if (score < 25)   return 'low'
  if (score < 50)   return 'medium'
  if (score < 75)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_SHORT_LABEL: Record<DatabaseSecurityRuleId, string> = {
  POSTGRES_AUTH_CONFIG_DRIFT:   'PostgreSQL auth config',
  MYSQL_AUTH_CONFIG_DRIFT:      'MySQL auth config',
  MONGO_AUTH_CONFIG_DRIFT:      'MongoDB auth config',
  REDIS_AUTH_CONFIG_DRIFT:      'Redis auth config',
  DATABASE_TLS_CONFIG_DRIFT:    'database TLS config',
  CONNECTION_POOL_CONFIG_DRIFT: 'connection pool config',
  DB_MIGRATION_SECURITY_DRIFT:  'security migration',
  ELASTICSEARCH_SECURITY_DRIFT: 'Elasticsearch security config',
}

function buildSummary(
  findings: DatabaseSecurityFinding[],
  riskLevel: DatabaseSecurityRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return (
      `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — ` +
      'no database security configuration file changes detected.'
    )
  }
  const critOrHigh = findings.filter((f) => f.severity === 'critical' || f.severity === 'high')
  if (critOrHigh.length > 0) {
    const labels = critOrHigh.map((f) => RULE_SHORT_LABEL[f.ruleId])
    const unique  = [...new Set(labels)]
    const joined  =
      unique.length <= 2
        ? unique.join(' and ')
        : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return (
      `${findings.length} database security configuration file${findings.length === 1 ? '' : 's'} modified ` +
      `including ${joined} — mandatory database security review required before merge.`
    )
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${findings.length} database security configuration change${findings.length === 1 ? '' : 's'} across ` +
    `${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which database security configuration files
 * were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor/build directories are excluded.
 * - Each rule fires at most once per scan (deduplicated per rule ID).
 * - The finding records the first matched path and total count of matched paths.
 */
export function scanDatabaseSecurityDrift(filePaths: string[]): DatabaseSecurityDriftResult {
  const ruleAccumulator = new Map<DatabaseSecurityRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of DATABASE_SECURITY_RULES) {
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
  const findings: DatabaseSecurityFinding[] = []
  for (const rule of DATABASE_SECURITY_RULES) {
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

  // Compute score with per-tier caps
  const penaltyByTier: Partial<Record<DatabaseSecuritySeverity, number>> = {}
  for (const f of findings) {
    penaltyByTier[f.severity] = (penaltyByTier[f.severity] ?? 0) + PENALTY_PER[f.severity]
  }

  let riskScore = 0
  for (const [sev, total] of Object.entries(penaltyByTier) as [DatabaseSecuritySeverity, number][]) {
    riskScore += Math.min(total, PENALTY_CAP[sev])
  }
  riskScore = Math.min(riskScore, 100)

  const riskLevel     = toRiskLevel(riskScore)
  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount     = findings.filter((f) => f.severity === 'high').length
  const mediumCount   = findings.filter((f) => f.severity === 'medium').length

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    findings,
    summary: buildSummary(findings, riskLevel, filePaths.filter((p) => p.trim()).length),
  }
}
