import { describe, expect, it } from 'vitest'
import {
  DATABASE_SECURITY_RULES,
  isDatabaseMigrationSecurityFile,
  scanDatabaseSecurityDrift,
  type DatabaseSecurityDriftResult,
} from './databaseSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): DatabaseSecurityDriftResult {
  return scanDatabaseSecurityDrift(paths)
}

function expectClean(result: DatabaseSecurityDriftResult) {
  expect(result.riskScore).toBe(0)
  expect(result.riskLevel).toBe('none')
  expect(result.totalFindings).toBe(0)
  expect(result.findings).toHaveLength(0)
}

function hasRule(result: DatabaseSecurityDriftResult, ruleId: string) {
  return result.findings.some((f) => f.ruleId === ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('scanDatabaseSecurityDrift — trivial inputs', () => {
  it('returns clean result for empty array', () => {
    expectClean(scan([]))
  })

  it('returns clean result for whitespace-only paths', () => {
    expectClean(scan(['', '   ', '\t']))
  })

  it('returns clean result for non-database-security files', () => {
    expectClean(scan(['src/index.ts', 'README.md', 'package.json']))
  })

  it('summary mentions scanned file count for clean result', () => {
    const result = scan(['src/index.ts', 'src/app.ts'])
    expect(result.summary).toMatch(/2 changed file/)
    expect(result.summary).toMatch(/no database security/)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('scanDatabaseSecurityDrift — vendor path exclusion', () => {
  it('ignores pg_hba.conf inside node_modules', () => {
    expectClean(scan(['node_modules/pg/pg_hba.conf']))
  })

  it('ignores redis.conf inside dist', () => {
    expectClean(scan(['dist/redis.conf']))
  })

  it('ignores mongod.conf inside .terraform', () => {
    expectClean(scan(['.terraform/modules/mongod.conf']))
  })

  it('flags pg_hba.conf in non-vendor path', () => {
    const result = scan(['config/pg_hba.conf'])
    expect(result.totalFindings).toBeGreaterThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// POSTGRES_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('POSTGRES_AUTH_CONFIG_DRIFT rule', () => {
  it('fires for pg_hba.conf', () => {
    expect(hasRule(scan(['config/pg_hba.conf']), 'POSTGRES_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for pg_ident.conf', () => {
    expect(hasRule(scan(['postgres/pg_ident.conf']), 'POSTGRES_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for postgresql.conf', () => {
    expect(hasRule(scan(['infra/postgresql.conf']), 'POSTGRES_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for postgresql.auto.conf', () => {
    expect(hasRule(scan(['pgdata/postgresql.auto.conf']), 'POSTGRES_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for postgresql-prod.conf (prefixed)', () => {
    expect(hasRule(scan(['config/postgresql-prod.conf']), 'POSTGRES_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for files inside /postgresql/ directory', () => {
    expect(hasRule(scan(['infra/postgresql/auth.conf']), 'POSTGRES_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT fire for postgresql.ts source file', () => {
    expectClean(scan(['src/postgresql.ts']))
  })

  it('severity is critical', () => {
    const result = scan(['config/pg_hba.conf'])
    const f = result.findings.find((f) => f.ruleId === 'POSTGRES_AUTH_CONFIG_DRIFT')!
    expect(f.severity).toBe('critical')
  })

  it('records matchCount for multiple PostgreSQL config files', () => {
    const result = scan(['pg_hba.conf', 'postgresql.conf', 'pg_ident.conf'])
    const f = result.findings.find((f) => f.ruleId === 'POSTGRES_AUTH_CONFIG_DRIFT')!
    expect(f.matchCount).toBe(3)
  })

  it('records matchedPath as first matched file', () => {
    const result = scan(['config/pg_hba.conf', 'config/postgresql.conf'])
    const f = result.findings.find((f) => f.ruleId === 'POSTGRES_AUTH_CONFIG_DRIFT')!
    expect(f.matchedPath).toBe('config/pg_hba.conf')
  })
})

// ---------------------------------------------------------------------------
// MYSQL_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('MYSQL_AUTH_CONFIG_DRIFT rule', () => {
  it('fires for my.cnf', () => {
    expect(hasRule(scan(['config/my.cnf']), 'MYSQL_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for my.ini', () => {
    expect(hasRule(scan(['mysql/my.ini']), 'MYSQL_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mysqld.cnf', () => {
    expect(hasRule(scan(['etc/mysql/mysqld.cnf']), 'MYSQL_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mysql.conf', () => {
    expect(hasRule(scan(['infra/mysql.conf']), 'MYSQL_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mariadb.conf', () => {
    expect(hasRule(scan(['config/mariadb.conf']), 'MYSQL_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for files inside /mysql/ directory', () => {
    expect(hasRule(scan(['infra/mysql/server.conf']), 'MYSQL_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT fire for mysql.ts source file', () => {
    expectClean(scan(['src/db/mysql.ts']))
  })

  it('severity is critical', () => {
    const result = scan(['config/my.cnf'])
    const f = result.findings.find((f) => f.ruleId === 'MYSQL_AUTH_CONFIG_DRIFT')!
    expect(f.severity).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// MONGO_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('MONGO_AUTH_CONFIG_DRIFT rule', () => {
  it('fires for mongod.conf', () => {
    expect(hasRule(scan(['config/mongod.conf']), 'MONGO_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mongos.conf', () => {
    expect(hasRule(scan(['infra/mongos.conf']), 'MONGO_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mongod.yaml', () => {
    expect(hasRule(scan(['deploy/mongod.yaml']), 'MONGO_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mongodb-prod.conf (prefixed)', () => {
    expect(hasRule(scan(['infra/mongodb-prod.conf']), 'MONGO_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for files inside /mongodb/ directory', () => {
    expect(hasRule(scan(['infra/mongodb/auth.yaml']), 'MONGO_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT fire for mongodb.ts source file', () => {
    expectClean(scan(['src/db/mongodb.ts']))
  })

  it('severity is high', () => {
    const result = scan(['config/mongod.conf'])
    const f = result.findings.find((f) => f.ruleId === 'MONGO_AUTH_CONFIG_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// REDIS_AUTH_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('REDIS_AUTH_CONFIG_DRIFT rule', () => {
  it('fires for redis.conf', () => {
    expect(hasRule(scan(['config/redis.conf']), 'REDIS_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for redis.acl', () => {
    expect(hasRule(scan(['infra/redis.acl']), 'REDIS_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for sentinel.conf', () => {
    expect(hasRule(scan(['redis/sentinel.conf']), 'REDIS_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for redis-cluster.conf', () => {
    expect(hasRule(scan(['infra/redis-cluster.conf']), 'REDIS_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for files inside /redis/ directory', () => {
    expect(hasRule(scan(['infra/redis/auth.conf']), 'REDIS_AUTH_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT fire for redis.ts source file', () => {
    expectClean(scan(['src/cache/redis.ts']))
  })

  it('severity is high', () => {
    const result = scan(['config/redis.conf'])
    const f = result.findings.find((f) => f.ruleId === 'REDIS_AUTH_CONFIG_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// DATABASE_TLS_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('DATABASE_TLS_CONFIG_DRIFT rule', () => {
  it('fires for db-ssl.conf', () => {
    expect(hasRule(scan(['config/db-ssl.conf']), 'DATABASE_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for database-tls.yaml', () => {
    expect(hasRule(scan(['infra/database-tls.yaml']), 'DATABASE_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for postgres-ssl.conf', () => {
    expect(hasRule(scan(['config/postgres-ssl.conf']), 'DATABASE_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for mysql-ssl.cnf', () => {
    expect(hasRule(scan(['mysql/mysql-ssl.cnf']), 'DATABASE_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for db-cert.conf', () => {
    expect(hasRule(scan(['tls/db-cert.conf']), 'DATABASE_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT fire for tls.ts source file', () => {
    expectClean(scan(['src/utils/tls.ts']))
  })

  it('severity is high', () => {
    const result = scan(['config/db-ssl.conf'])
    const f = result.findings.find((f) => f.ruleId === 'DATABASE_TLS_CONFIG_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// CONNECTION_POOL_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('CONNECTION_POOL_CONFIG_DRIFT rule', () => {
  it('fires for pgbouncer.ini', () => {
    expect(hasRule(scan(['config/pgbouncer.ini']), 'CONNECTION_POOL_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for pgpool.conf', () => {
    expect(hasRule(scan(['infra/pgpool.conf']), 'CONNECTION_POOL_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for proxysql.cnf', () => {
    expect(hasRule(scan(['proxy/proxysql.cnf']), 'CONNECTION_POOL_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for userlist.txt (pgBouncer auth file)', () => {
    expect(hasRule(scan(['pgbouncer/userlist.txt']), 'CONNECTION_POOL_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for pool_hba.conf', () => {
    expect(hasRule(scan(['pgpool/pool_hba.conf']), 'CONNECTION_POOL_CONFIG_DRIFT')).toBe(true)
  })

  it('fires for files inside /pgbouncer/ directory', () => {
    expect(
      hasRule(scan(['infra/pgbouncer/server.conf']), 'CONNECTION_POOL_CONFIG_DRIFT'),
    ).toBe(true)
  })

  it('does NOT fire for pool.ts source file', () => {
    expectClean(scan(['src/db/pool.ts']))
  })

  it('severity is high', () => {
    const result = scan(['config/pgbouncer.ini'])
    const f = result.findings.find((f) => f.ruleId === 'CONNECTION_POOL_CONFIG_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// DB_MIGRATION_SECURITY_DRIFT — isDatabaseMigrationSecurityFile helper
// ---------------------------------------------------------------------------

describe('isDatabaseMigrationSecurityFile', () => {
  it('detects auth migration in Rails migrations directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('db/migrate/20240101_add_user_role.rb'),
    ).toBe(true)
  })

  it('detects permission migration in SQL migrations directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('migrations/0042_grant_read_permission.sql'),
    ).toBe(true)
  })

  it('detects role migration in Alembic versions directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('alembic/versions/abc123_create_admin_role.py'),
    ).toBe(true)
  })

  it('detects grant migration in Flyway directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('flyway/V1__grant_service_access.sql'),
    ).toBe(true)
  })

  it('detects security migration in Prisma migrations directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('prisma/migrations/20240201_add_auth_table/migration.sql'),
    ).toBe(true)
  })

  it('detects password migration in Liquibase changelogs', () => {
    expect(
      isDatabaseMigrationSecurityFile('liquibase/changelogs/update_password_policy.xml'),
    ).toBe(true)
  })

  it('does NOT detect plain schema migration (no security keyword)', () => {
    expect(
      isDatabaseMigrationSecurityFile('migrations/0043_add_products_table.sql'),
    ).toBe(false)
  })

  it('does NOT detect migration outside recognised migration directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('scripts/add_auth_column.sql'),
    ).toBe(false)
  })

  it('does NOT detect non-migration file (wrong extension)', () => {
    expect(
      isDatabaseMigrationSecurityFile('migrations/auth_config.json'),
    ).toBe(false)
  })

  it('does NOT detect README in migrations directory', () => {
    expect(
      isDatabaseMigrationSecurityFile('migrations/README.md'),
    ).toBe(false)
  })
})

describe('DB_MIGRATION_SECURITY_DRIFT rule (via scanner)', () => {
  it('fires for auth migration in migrations/ directory', () => {
    expect(
      hasRule(scan(['migrations/0042_grant_read_permission.sql']), 'DB_MIGRATION_SECURITY_DRIFT'),
    ).toBe(true)
  })

  it('fires for role migration in db/migrate/ directory', () => {
    expect(
      hasRule(scan(['db/migrate/20240101_add_admin_role.rb']), 'DB_MIGRATION_SECURITY_DRIFT'),
    ).toBe(true)
  })

  it('does NOT fire for plain schema migration', () => {
    expect(
      hasRule(scan(['migrations/0043_add_products_table.sql']), 'DB_MIGRATION_SECURITY_DRIFT'),
    ).toBe(false)
  })

  it('severity is medium', () => {
    const result = scan(['migrations/0042_grant_read_permission.sql'])
    const f = result.findings.find((f) => f.ruleId === 'DB_MIGRATION_SECURITY_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// ELASTICSEARCH_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('ELASTICSEARCH_SECURITY_DRIFT rule', () => {
  it('fires for elasticsearch.yml', () => {
    expect(hasRule(scan(['config/elasticsearch.yml']), 'ELASTICSEARCH_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for opensearch.yaml', () => {
    expect(hasRule(scan(['infra/opensearch.yaml']), 'ELASTICSEARCH_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for kibana.yml', () => {
    expect(hasRule(scan(['elastic/kibana.yml']), 'ELASTICSEARCH_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for logstash.yml', () => {
    expect(hasRule(scan(['elk/logstash.yml']), 'ELASTICSEARCH_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for elasticsearch-prod.yml (prefixed)', () => {
    expect(hasRule(scan(['infra/elasticsearch-prod.yml']), 'ELASTICSEARCH_SECURITY_DRIFT')).toBe(true)
  })

  it('fires for files inside /elasticsearch/ directory', () => {
    expect(
      hasRule(scan(['infra/elasticsearch/security.yml']), 'ELASTICSEARCH_SECURITY_DRIFT'),
    ).toBe(true)
  })

  it('does NOT fire for elasticsearch.ts source file', () => {
    expectClean(scan(['src/search/elasticsearch.ts']))
  })

  it('severity is medium', () => {
    const result = scan(['config/elasticsearch.yml'])
    const f = result.findings.find((f) => f.ruleId === 'ELASTICSEARCH_SECURITY_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanDatabaseSecurityDrift — scoring', () => {
  it('riskScore is 0 for clean result', () => {
    expect(scan([]).riskScore).toBe(0)
  })

  it('riskLevel is none for zero findings', () => {
    expect(scan([]).riskLevel).toBe('none')
  })

  it('riskScore is positive when a critical rule fires', () => {
    const result = scan(['pg_hba.conf'])
    expect(result.riskScore).toBeGreaterThan(0)
  })

  it('riskLevel is elevated (medium or above) when critical rule fires', () => {
    // Single critical finding: penalty=30 → 'medium' band (25–49)
    const result = scan(['pg_hba.conf'])
    expect(['medium', 'high', 'critical']).toContain(result.riskLevel)
  })

  it('riskScore increases with more rules firing', () => {
    const single = scan(['pg_hba.conf'])
    const multi  = scan(['pg_hba.conf', 'config/my.cnf'])
    expect(multi.riskScore).toBeGreaterThan(single.riskScore)
  })

  it('riskScore is capped at 100', () => {
    const result = scan([
      'pg_hba.conf', 'config/my.cnf',
      'config/mongod.conf', 'config/redis.conf',
      'config/db-ssl.conf', 'config/pgbouncer.ini',
      'migrations/0042_grant_permission.sql',
      'config/elasticsearch.yml',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })

  it('criticalCount and highCount are populated correctly', () => {
    const result = scan([
      'pg_hba.conf',       // critical
      'config/my.cnf',     // critical
      'config/redis.conf', // high
    ])
    expect(result.criticalCount).toBe(2)
    expect(result.highCount).toBe(1)
  })

  it('mediumCount is populated correctly', () => {
    const result = scan([
      'migrations/0042_grant_permission.sql',
      'config/elasticsearch.yml',
    ])
    expect(result.mediumCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('scanDatabaseSecurityDrift — summary', () => {
  it('mentions "database security" in findings summary', () => {
    const result = scan(['pg_hba.conf'])
    expect(result.summary).toMatch(/database security/)
  })

  it('mentions "mandatory" for critical/high findings', () => {
    const result = scan(['pg_hba.conf'])
    expect(result.summary).toMatch(/mandatory/)
  })

  it('mentions "no database security" for clean result', () => {
    const result = scan(['src/index.ts'])
    expect(result.summary).toMatch(/no database security/)
  })

  it('includes rule count in multi-finding summary', () => {
    const result = scan(['pg_hba.conf', 'config/redis.conf'])
    expect(result.summary).toMatch(/2 database security/)
  })
})

// ---------------------------------------------------------------------------
// DATABASE_SECURITY_RULES constant integrity
// ---------------------------------------------------------------------------

describe('DATABASE_SECURITY_RULES constants', () => {
  it('contains 8 rules', () => {
    expect(DATABASE_SECURITY_RULES).toHaveLength(8)
  })

  it('all rules have non-empty descriptions', () => {
    for (const rule of DATABASE_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
    }
  })

  it('all rules have non-empty recommendations', () => {
    for (const rule of DATABASE_SECURITY_RULES) {
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })

  it('critical rules come before high and medium', () => {
    const severities = DATABASE_SECURITY_RULES.map((r) => r.severity)
    const criticalIdx = severities.findIndex((s) => s === 'critical')
    const mediumIdx   = severities.findIndex((s) => s === 'medium')
    expect(criticalIdx).toBeLessThan(mediumIdx)
  })

  it('all rule IDs are unique', () => {
    const ids = DATABASE_SECURITY_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})
