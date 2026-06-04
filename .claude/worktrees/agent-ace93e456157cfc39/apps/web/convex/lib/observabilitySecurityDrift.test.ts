import { describe, it, expect } from 'vitest'
import {
  scanObservabilitySecurityDrift,
  isTracingSecurityConfig,
  OBSERVABILITY_SECURITY_RULES,
} from './observabilitySecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]) {
  return scanObservabilitySecurityDrift(files)
}

function hasRule(files: string[], ruleId: string) {
  return scan(files).findings.some((f) => f.ruleId === ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('trivial inputs', () => {
  it('empty array → none result', () => {
    const r = scan([])
    expect(r.riskLevel).toBe('none')
    expect(r.riskScore).toBe(0)
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
  })

  it('no matching files → none result', () => {
    const r = scan(['src/app.ts', 'README.md', 'package.json'])
    expect(r.riskLevel).toBe('none')
    expect(r.riskScore).toBe(0)
  })

  it('vendor directories excluded', () => {
    expect(scan(['node_modules/alertmanager.yml'])).toMatchObject({ riskLevel: 'none' })
    expect(scan(['vendor/fluent.conf'])).toMatchObject({ riskLevel: 'none' })
    expect(scan(['.terraform/alertmanager.yaml'])).toMatchObject({ riskLevel: 'none' })
  })

  it('windows backslash paths normalised', () => {
    expect(hasRule(['monitoring\\rules\\alert-rules.yml'], 'PROMETHEUS_ALERT_RULES_DRIFT')).toBe(true)
    expect(hasRule(['alertmanager\\alertmanager.yml'], 'ALERTMANAGER_CONFIG_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// PROMETHEUS_ALERT_RULES_DRIFT
// ---------------------------------------------------------------------------

describe('PROMETHEUS_ALERT_RULES_DRIFT', () => {
  const RULE = 'PROMETHEUS_ALERT_RULES_DRIFT'

  it('alerts.yml exact → flagged', () => expect(hasRule(['alerts.yml'], RULE)).toBe(true))
  it('alerts.yaml exact → flagged', () => expect(hasRule(['alerts.yaml'], RULE)).toBe(true))
  it('alert-rules.yml exact → flagged', () => expect(hasRule(['alert-rules.yml'], RULE)).toBe(true))
  it('alert-rules.yaml exact → flagged', () => expect(hasRule(['alert-rules.yaml'], RULE)).toBe(true))
  it('prometheus-rules.yml exact → flagged', () => expect(hasRule(['prometheus-rules.yml'], RULE)).toBe(true))
  it('rules.yml exact → flagged', () => expect(hasRule(['rules.yml'], RULE)).toBe(true))
  it('recording-rules.yaml exact → flagged', () => expect(hasRule(['recording-rules.yaml'], RULE)).toBe(true))

  it('.rules.yml suffix → flagged', () => expect(hasRule(['security.rules.yml'], RULE)).toBe(true))
  it('.rules.yaml suffix → flagged', () => expect(hasRule(['auth-alerts.rules.yaml'], RULE)).toBe(true))

  it('file in prometheus/ dir → flagged', () =>
    expect(hasRule(['prometheus/security-alerts.yaml'], RULE)).toBe(true))
  it('file in alerting/ dir → flagged', () =>
    expect(hasRule(['alerting/high-severity.yml'], RULE)).toBe(true))
  it('file in monitoring/rules/ dir → flagged', () =>
    expect(hasRule(['monitoring/rules/auth.yaml'], RULE)).toBe(true))

  it('prometheus.yml alone NOT flagged (scrape config)', () =>
    expect(hasRule(['prometheus.yml'], RULE)).toBe(false))
  it('prometheus.yaml alone NOT flagged (scrape config)', () =>
    expect(hasRule(['prometheus.yaml'], RULE)).toBe(false))
  it('generic yaml not in monitoring dir NOT flagged', () =>
    expect(hasRule(['config/rules.json'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// ALERTMANAGER_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('ALERTMANAGER_CONFIG_DRIFT', () => {
  const RULE = 'ALERTMANAGER_CONFIG_DRIFT'

  it('alertmanager.yml exact → flagged', () => expect(hasRule(['alertmanager.yml'], RULE)).toBe(true))
  it('alertmanager.yaml exact → flagged', () => expect(hasRule(['alertmanager.yaml'], RULE)).toBe(true))
  it('alertmanager-config.yml exact → flagged', () =>
    expect(hasRule(['alertmanager-config.yml'], RULE)).toBe(true))
  it('alertmanager.json exact → flagged', () => expect(hasRule(['alertmanager.json'], RULE)).toBe(true))

  it('file in alertmanager/ dir → flagged', () =>
    expect(hasRule(['alertmanager/config.yml'], RULE)).toBe(true))
  it('file in etc/alertmanager/ dir → flagged', () =>
    expect(hasRule(['etc/alertmanager/alertmanager.yml'], RULE)).toBe(true))

  it('alertmanager- prefix → flagged', () =>
    expect(hasRule(['alertmanager-silence.yaml'], RULE)).toBe(true))

  it('generic config.yml not flagged', () =>
    expect(hasRule(['config/config.yml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// LOG_PIPELINE_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('LOG_PIPELINE_SECURITY_DRIFT', () => {
  const RULE = 'LOG_PIPELINE_SECURITY_DRIFT'

  it('fluent.conf exact → flagged', () => expect(hasRule(['fluent.conf'], RULE)).toBe(true))
  it('fluentd.conf exact → flagged', () => expect(hasRule(['fluentd.conf'], RULE)).toBe(true))
  it('fluent-bit.conf exact → flagged', () => expect(hasRule(['fluent-bit.conf'], RULE)).toBe(true))
  it('fluent-bit.yaml exact → flagged', () => expect(hasRule(['fluent-bit.yaml'], RULE)).toBe(true))
  it('td-agent.conf exact → flagged', () => expect(hasRule(['td-agent.conf'], RULE)).toBe(true))
  it('logstash.conf exact → flagged', () => expect(hasRule(['logstash.conf'], RULE)).toBe(true))
  it('logstash.yml exact → flagged', () => expect(hasRule(['logstash.yml'], RULE)).toBe(true))
  it('vector.toml exact → flagged', () => expect(hasRule(['vector.toml'], RULE)).toBe(true))
  it('vector.yaml exact → flagged', () => expect(hasRule(['vector.yaml'], RULE)).toBe(true))
  it('filebeat.yml exact → flagged', () => expect(hasRule(['filebeat.yml'], RULE)).toBe(true))
  it('auditbeat.yml exact → flagged', () => expect(hasRule(['auditbeat.yml'], RULE)).toBe(true))
  it('metricbeat.yml exact → flagged', () => expect(hasRule(['metricbeat.yml'], RULE)).toBe(true))

  it('file in fluentd/ dir → flagged', () =>
    expect(hasRule(['fluentd/custom.conf'], RULE)).toBe(true))
  it('file in logstash/pipeline/ dir → flagged', () =>
    expect(hasRule(['logstash/pipeline/auth.conf'], RULE)).toBe(true))
  it('file in log-pipeline/ dir → flagged', () =>
    expect(hasRule(['log-pipeline/vector.toml'], RULE)).toBe(true))

  it('logstash- prefix → flagged', () =>
    expect(hasRule(['logstash-security.yml'], RULE)).toBe(true))
  it('filebeat- prefix → flagged', () =>
    expect(hasRule(['filebeat-security.yaml'], RULE)).toBe(true))

  it('logstash/*.conf in logstash dir → flagged', () =>
    expect(hasRule(['logstash/filters.conf'], RULE)).toBe(true))

  it('generic app.conf not flagged', () =>
    expect(hasRule(['config/app.conf'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// OTEL_COLLECTOR_DRIFT
// ---------------------------------------------------------------------------

describe('OTEL_COLLECTOR_DRIFT', () => {
  const RULE = 'OTEL_COLLECTOR_DRIFT'

  it('otel-collector.yaml exact → flagged', () =>
    expect(hasRule(['otel-collector.yaml'], RULE)).toBe(true))
  it('otelcol.yaml exact → flagged', () => expect(hasRule(['otelcol.yaml'], RULE)).toBe(true))
  it('opentelemetry-collector.yaml exact → flagged', () =>
    expect(hasRule(['opentelemetry-collector.yaml'], RULE)).toBe(true))
  it('otel-config.yaml exact → flagged', () =>
    expect(hasRule(['otel-config.yaml'], RULE)).toBe(true))

  it('file in otel/ dir → flagged', () =>
    expect(hasRule(['otel/collector.yaml'], RULE)).toBe(true))
  it('file in opentelemetry/ dir → flagged', () =>
    expect(hasRule(['opentelemetry/config.yml'], RULE)).toBe(true))

  it('otel- prefix → flagged', () =>
    expect(hasRule(['otel-security.yaml'], RULE)).toBe(true))
  it('otelcol- prefix → flagged', () =>
    expect(hasRule(['otelcol-config.yml'], RULE)).toBe(true))

  it('generic collector.json not in otel dir NOT flagged', () =>
    expect(hasRule(['config/collector.json'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// GRAFANA_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('GRAFANA_SECURITY_DRIFT', () => {
  const RULE = 'GRAFANA_SECURITY_DRIFT'

  it('grafana.ini exact → flagged', () => expect(hasRule(['grafana.ini'], RULE)).toBe(true))
  it('grafana-datasources.yaml exact → flagged', () =>
    expect(hasRule(['grafana-datasources.yaml'], RULE)).toBe(true))
  it('grafana-datasources.json exact → flagged', () =>
    expect(hasRule(['grafana-datasources.json'], RULE)).toBe(true))
  it('grafana-auth.yaml exact → flagged', () =>
    expect(hasRule(['grafana-auth.yaml'], RULE)).toBe(true))

  it('file in grafana/ dir → flagged', () =>
    expect(hasRule(['grafana/datasources.yaml'], RULE)).toBe(true))
  it('file in grafana/provisioning/ → flagged', () =>
    expect(hasRule(['grafana/provisioning/auth.yaml'], RULE)).toBe(true))
  it('file in monitoring/grafana/ → flagged', () =>
    expect(hasRule(['monitoring/grafana/config.ini'], RULE)).toBe(true))

  it('grafana- prefix → flagged', () =>
    expect(hasRule(['grafana-alerts.yaml'], RULE)).toBe(true))

  it('generic datasources.yaml not in grafana dir NOT flagged', () =>
    expect(hasRule(['config/datasources.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// CLOUDWATCH_ALARM_DRIFT
// ---------------------------------------------------------------------------

describe('CLOUDWATCH_ALARM_DRIFT', () => {
  const RULE = 'CLOUDWATCH_ALARM_DRIFT'

  it('cloudwatch-alarms.json exact → flagged', () =>
    expect(hasRule(['cloudwatch-alarms.json'], RULE)).toBe(true))
  it('cloudwatch-alarms.yaml exact → flagged', () =>
    expect(hasRule(['cloudwatch-alarms.yaml'], RULE)).toBe(true))
  it('cloudwatch.config exact → flagged', () =>
    expect(hasRule(['cloudwatch.config'], RULE)).toBe(true))
  it('cloudwatch-agent.json exact → flagged', () =>
    expect(hasRule(['cloudwatch-agent.json'], RULE)).toBe(true))
  it('monitoring-alarms.json exact → flagged', () =>
    expect(hasRule(['monitoring-alarms.json'], RULE)).toBe(true))

  it('file in cloudwatch/ dir → flagged', () =>
    expect(hasRule(['cloudwatch/alarms.json'], RULE)).toBe(true))
  it('file in monitoring/alarms/ dir → flagged', () =>
    expect(hasRule(['monitoring/alarms/high-severity.yaml'], RULE)).toBe(true))
  it('file in aws/cloudwatch/ dir → flagged', () =>
    expect(hasRule(['aws/cloudwatch/config.json'], RULE)).toBe(true))

  it('cloudwatch- prefix → flagged', () =>
    expect(hasRule(['cloudwatch-security-alarms.yml'], RULE)).toBe(true))

  it('generic alarms.json not in cloudwatch dir NOT flagged', () =>
    expect(hasRule(['config/alarms.json'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// isTracingSecurityConfig (user contribution)
// ---------------------------------------------------------------------------

describe('isTracingSecurityConfig', () => {
  it('k8s/ directory excluded', () =>
    expect(isTracingSecurityConfig('k8s/jaeger.yaml')).toBe(false))
  it('kubernetes/ directory excluded', () =>
    expect(isTracingSecurityConfig('kubernetes/tempo.yaml')).toBe(false))
  it('helm/ directory excluded', () =>
    expect(isTracingSecurityConfig('helm/charts/jaeger/values.yaml')).toBe(false))
  it('charts/ directory excluded', () =>
    expect(isTracingSecurityConfig('charts/tempo/config.yaml')).toBe(false))
  it('terraform/ directory excluded', () =>
    expect(isTracingSecurityConfig('terraform/jaeger.yaml')).toBe(false))

  it('jaeger.yaml exact outside k8s → flagged', () =>
    expect(isTracingSecurityConfig('config/jaeger.yaml')).toBe(true))
  it('jaeger-config.yaml exact outside k8s → flagged', () =>
    expect(isTracingSecurityConfig('jaeger-config.yaml')).toBe(true))
  it('tempo.yaml exact outside k8s → flagged', () =>
    expect(isTracingSecurityConfig('observability/tempo.yaml')).toBe(true))
  it('tempo-config.yaml exact outside k8s → flagged', () =>
    expect(isTracingSecurityConfig('tempo-config.yaml')).toBe(true))
  it('zipkin.yaml exact outside k8s → flagged', () =>
    expect(isTracingSecurityConfig('zipkin.yaml')).toBe(true))
  it('zipkin-config.yaml exact → flagged', () =>
    expect(isTracingSecurityConfig('zipkin-config.yaml')).toBe(true))

  it('jaeger- prefix yaml → flagged', () =>
    expect(isTracingSecurityConfig('jaeger-collector.yaml')).toBe(true))
  it('tempo- prefix yaml → flagged', () =>
    expect(isTracingSecurityConfig('tempo-security.yml')).toBe(true))
  it('zipkin- prefix json → flagged', () =>
    expect(isTracingSecurityConfig('zipkin-server.json')).toBe(true))

  it('file in jaeger/ dir → flagged', () =>
    expect(isTracingSecurityConfig('jaeger/config.yaml')).toBe(true))
  it('file in tempo/ dir → flagged', () =>
    expect(isTracingSecurityConfig('tempo/storage.yaml')).toBe(true))
  it('file in tracing/ dir → flagged', () =>
    expect(isTracingSecurityConfig('tracing/backend.conf')).toBe(true))
  it('file in distributed-tracing/ dir → flagged', () =>
    expect(isTracingSecurityConfig('distributed-tracing/config.yaml')).toBe(true))

  it('generic config.yaml in unrelated dir NOT flagged', () =>
    expect(isTracingSecurityConfig('config/service.yaml')).toBe(false))
  it('generic observability.yaml not in tracing dir NOT flagged', () =>
    expect(isTracingSecurityConfig('observability.yaml')).toBe(false))
})

describe('TRACING_SECURITY_DRIFT via scanner', () => {
  const RULE = 'TRACING_SECURITY_DRIFT'

  it('jaeger.yaml (outside k8s) → flagged', () =>
    expect(hasRule(['config/jaeger.yaml'], RULE)).toBe(true))
  it('tempo-config.yaml → flagged', () =>
    expect(hasRule(['tempo-config.yaml'], RULE)).toBe(true))
  it('k8s/jaeger.yaml → NOT flagged', () =>
    expect(hasRule(['k8s/jaeger.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// LOG_RETENTION_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('LOG_RETENTION_POLICY_DRIFT', () => {
  const RULE = 'LOG_RETENTION_POLICY_DRIFT'

  it('logrotate.conf exact → flagged', () =>
    expect(hasRule(['logrotate.conf'], RULE)).toBe(true))
  it('rsyslog.conf exact → flagged', () =>
    expect(hasRule(['rsyslog.conf'], RULE)).toBe(true))
  it('syslog.conf exact → flagged', () =>
    expect(hasRule(['syslog.conf'], RULE)).toBe(true))
  it('syslog-ng.conf exact → flagged', () =>
    expect(hasRule(['syslog-ng.conf'], RULE)).toBe(true))
  it('journald.conf exact → flagged', () =>
    expect(hasRule(['journald.conf'], RULE)).toBe(true))
  it('log-retention.yaml exact → flagged', () =>
    expect(hasRule(['log-retention.yaml'], RULE)).toBe(true))
  it('log-policy.yml exact → flagged', () =>
    expect(hasRule(['log-policy.yml'], RULE)).toBe(true))

  it('file in etc/logrotate.d/ dir → flagged', () =>
    expect(hasRule(['etc/logrotate.d/nginx'], RULE)).toBe(true))
  it('file in logrotate.d/ dir → flagged', () =>
    expect(hasRule(['logrotate.d/app'], RULE)).toBe(true))
  it('file in rsyslog.d/ dir → flagged', () =>
    expect(hasRule(['etc/rsyslog.d/50-default.conf'], RULE)).toBe(true))

  it('log-retention prefix → flagged', () =>
    expect(hasRule(['log-retention-policy.yaml'], RULE)).toBe(true))
  it('rsyslog- prefix → flagged', () =>
    expect(hasRule(['rsyslog-auth.conf'], RULE)).toBe(true))

  it('generic app.log NOT flagged', () =>
    expect(hasRule(['logs/app.log'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 high match → score 15, risk low', () => {
    const r = scan(['alertmanager.yml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('3 different high rules → score 45, risk high', () => {
    const r = scan(['alertmanager.yml', 'alerts.yml', 'fluent.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('3 files for same high rule → score 45 (hits cap), risk high', () => {
    const r = scan(['alertmanager.yml', 'alertmanager-config.yml', 'alertmanager/config.yml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('1 medium match → score 8, risk low', () => {
    const r = scan(['grafana.ini'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('1 low match → score 4, risk low', () => {
    const r = scan(['logrotate.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('score < 20 → low', () => {
    const r = scan(['alerts.yml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('score 20 → medium', () => {
    const r = scan(['alerts.yml', 'alert-rules.yml'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('score ≥ 45 → high', () => {
    const r = scan(['alertmanager.yml', 'alerts.yml', 'fluent.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score ≥ 70 → critical', () => {
    // 3 high (45) + 4 medium (32) = 77
    const r = scan([
      'alertmanager.yml',
      'alerts.yml',
      'fluent.conf',
      'grafana.ini',
      'otel-collector.yaml',
      'cloudwatch-alarms.json',
      'logrotate.conf',
    ])
    expect(r.riskScore).toBeGreaterThanOrEqual(70)
    expect(r.riskLevel).toBe('critical')
  })

  it('score clamped at 100', () => {
    const manyFiles = Array.from({ length: 20 }, (_, i) => `alert-rule-${i}.rules.yml`)
    manyFiles.push('alertmanager.yml', 'fluent.conf', 'grafana.ini', 'otel-collector.yaml', 'cloudwatch-alarms.json', 'logrotate.conf', 'jaeger.yaml')
    expect(scan(manyFiles).riskScore).toBe(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => expect(scan([]).riskLevel).toBe('none'))
  it('score 4 → low', () => expect(scan(['logrotate.conf']).riskLevel).toBe('low'))
  it('score 15 → low', () => expect(scan(['alertmanager.yml']).riskLevel).toBe('low'))
  it('score 19 → low', () => {
    // 1 high (15) + 1 low (4) = 19
    const r = scan(['alertmanager.yml', 'logrotate.conf'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })
  it('score 23 → medium', () => {
    // 1 high (15) + 1 medium (8) = 23
    const r = scan(['alertmanager.yml', 'grafana.ini'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 43 → medium (below 45 boundary)', () => {
    // 1 high (15) + 3 medium (8+8+8=24) + 1 low (4) = 43
    const r = scan([
      'alertmanager.yml',
      'grafana.ini', 'otel-collector.yaml', 'cloudwatch-alarms.json',
      'logrotate.conf',
    ])
    expect(r.riskScore).toBe(43)
    expect(r.riskLevel).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('same rule triggered by 3 files → one finding with matchCount 3', () => {
    const r = scan(['alertmanager.yml', 'alertmanager/config.yml', 'alertmanager-config.yml'])
    const f = r.findings.find((x) => x.ruleId === 'ALERTMANAGER_CONFIG_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
    expect(r.findings).toHaveLength(1)
  })

  it('firstPath is the first matched path', () => {
    const r = scan(['fluent.conf', 'logstash.conf'])
    const f = r.findings.find((x) => x.ruleId === 'LOG_PIPELINE_SECURITY_DRIFT')
    expect(f!.matchedPath).toBe('fluent.conf')
  })
})

// ---------------------------------------------------------------------------
// Finding ordering
// ---------------------------------------------------------------------------

describe('finding ordering', () => {
  it('high before medium before low', () => {
    const r = scan(['alertmanager.yml', 'grafana.ini', 'logrotate.conf'])
    expect(r.findings[0].severity).toBe('high')
    expect(r.findings[1].severity).toBe('medium')
    expect(r.findings[2].severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('empty → default summary', () => {
    expect(scan([]).summary).toBe('No observability and security monitoring configuration drift detected.')
  })

  it('findings → includes finding counts', () => {
    const r = scan(['alertmanager.yml', 'grafana.ini'])
    expect(r.summary).toContain('1 high')
    expect(r.summary).toContain('1 medium')
    expect(r.summary).toContain('alertmanager config drift')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('complete observability stack drift → multiple findings', () => {
    const r = scan([
      'alertmanager.yml',         // ALERTMANAGER_CONFIG_DRIFT
      'alerts.yml',               // PROMETHEUS_ALERT_RULES_DRIFT
      'fluent.conf',              // LOG_PIPELINE_SECURITY_DRIFT
      'grafana.ini',              // GRAFANA_SECURITY_DRIFT
      'otel-collector.yaml',      // OTEL_COLLECTOR_DRIFT
      'cloudwatch-alarms.json',   // CLOUDWATCH_ALARM_DRIFT
      'jaeger.yaml',              // TRACING_SECURITY_DRIFT (blocked → outside k8s)
      'logrotate.conf',           // LOG_RETENTION_POLICY_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(3)
    expect(r.mediumCount).toBe(4)
    expect(r.lowCount).toBe(1)
  })

  it('only log pipeline changes → correct risk level', () => {
    const r = scan(['fluent.conf'])
    expect(r.riskLevel).toBe('low')
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0].ruleId).toBe('LOG_PIPELINE_SECURITY_DRIFT')
  })

  it('mixed: prometheus + alertmanager + log pipeline → 3 findings', () => {
    const r = scan(['alerts.yml', 'alertmanager.yml', 'vector.toml'])
    expect(r.totalFindings).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('registry completeness', () => {
  const expectedRuleIds = [
    'PROMETHEUS_ALERT_RULES_DRIFT',
    'ALERTMANAGER_CONFIG_DRIFT',
    'LOG_PIPELINE_SECURITY_DRIFT',
    'OTEL_COLLECTOR_DRIFT',
    'GRAFANA_SECURITY_DRIFT',
    'CLOUDWATCH_ALARM_DRIFT',
    'TRACING_SECURITY_DRIFT',
    'LOG_RETENTION_POLICY_DRIFT',
  ] as const

  it('registry has exactly 8 rules', () => {
    expect(OBSERVABILITY_SECURITY_RULES).toHaveLength(8)
  })

  for (const ruleId of expectedRuleIds) {
    it(`registry contains ${ruleId}`, () => {
      expect(OBSERVABILITY_SECURITY_RULES.some((r) => r.id === ruleId)).toBe(true)
    })
  }

  it('all rules have non-empty descriptions and recommendations', () => {
    for (const rule of OBSERVABILITY_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })
})
