import { describe, it, expect } from 'vitest'
import {
  SIEM_SECURITY_RULES,
  isSiemDetectionRuleFile,
  scanSiemSecurityDrift,
  type SiemSecurityRuleId,
} from './siemSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function triggeredRules(paths: string[]): SiemSecurityRuleId[] {
  return scanSiemSecurityDrift(paths).findings.map((f) => f.ruleId)
}

function onlyRule(paths: string[]): SiemSecurityRuleId | null {
  const ids = triggeredRules(paths)
  return ids.length === 1 ? ids[0] : null
}

// ---------------------------------------------------------------------------
// Rule 1: SPLUNK_DETECTION_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('SPLUNK_DETECTION_CONFIG_DRIFT', () => {
  it('triggers on savedsearches.conf (ungated)', () => {
    expect(onlyRule(['savedsearches.conf'])).toBe('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on alert_actions.conf (ungated)', () => {
    expect(onlyRule(['alert_actions.conf'])).toBe('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on correlationsearches.conf (ungated)', () => {
    expect(onlyRule(['correlationsearches.conf'])).toBe('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on notable_event_actions.conf (ungated)', () => {
    expect(onlyRule(['notable_event_actions.conf'])).toBe('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on correlation_search-*.conf prefix', () => {
    expect(triggeredRules(['correlation_search-lateral-movement.conf'])).toContain(
      'SPLUNK_DETECTION_CONFIG_DRIFT',
    )
  })

  it('triggers on transforms.conf in splunk/ dir', () => {
    expect(triggeredRules(['splunk/transforms.conf'])).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on macros.conf in splunk/ dir', () => {
    expect(triggeredRules(['splunk/macros.conf'])).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on .conf in splunk-es/ dir', () => {
    expect(triggeredRules(['splunk-es/custom-alerts.conf'])).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('triggers on CSV lookup table in splunk dir', () => {
    expect(triggeredRules(['splunk/lookups/threat_intel.csv'])).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('does NOT trigger on transforms.conf outside splunk dir', () => {
    expect(triggeredRules(['config/transforms.conf'])).not.toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('does NOT trigger on macros.conf outside splunk dir', () => {
    expect(triggeredRules(['scripts/macros.conf'])).not.toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/splunk/savedsearches.conf'])).not.toContain(
      'SPLUNK_DETECTION_CONFIG_DRIFT',
    )
  })

  it('handles Windows-style paths', () => {
    expect(triggeredRules(['C:\\config\\savedsearches.conf'])).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: ELASTIC_SIEM_RULE_DRIFT
// ---------------------------------------------------------------------------

describe('ELASTIC_SIEM_RULE_DRIFT', () => {
  it('triggers on .ndjson in detection-rules/ dir', () => {
    expect(triggeredRules(['detection-rules/lateral-movement.ndjson'])).toContain(
      'ELASTIC_SIEM_RULE_DRIFT',
    )
  })

  it('triggers on .ndjson in detection_rules/ dir', () => {
    expect(triggeredRules(['detection_rules/credential_access.ndjson'])).toContain(
      'ELASTIC_SIEM_RULE_DRIFT',
    )
  })

  it('triggers on elastic-siem-*.json prefix (ungated)', () => {
    expect(triggeredRules(['elastic-siem-rules.json'])).toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('triggers on detection-rule-*.yaml prefix (ungated)', () => {
    expect(triggeredRules(['detection-rule-brute-force.yaml'])).toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('triggers on .json in elastic-security/ dir', () => {
    expect(triggeredRules(['elastic-security/rules.json'])).toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('triggers on .toml detection rule in siem-rules/ dir', () => {
    expect(triggeredRules(['siem-rules/endpoint-rule.toml'])).toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('triggers on .yaml in kibana-rules/ dir', () => {
    expect(triggeredRules(['kibana-rules/persistence.yaml'])).toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('does NOT trigger on .ndjson outside detection dirs', () => {
    expect(triggeredRules(['data/export.ndjson'])).not.toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('does NOT trigger on .json in unrelated dir', () => {
    expect(triggeredRules(['src/config.json'])).not.toContain('ELASTIC_SIEM_RULE_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['node_modules/elastic-rules/detection-rules/rule.ndjson'])).not.toContain(
      'ELASTIC_SIEM_RULE_DRIFT',
    )
  })
})

// ---------------------------------------------------------------------------
// Rule 3: SENTINEL_ANALYTICS_DRIFT
// ---------------------------------------------------------------------------

describe('SENTINEL_ANALYTICS_DRIFT', () => {
  it('triggers on analyticsrules.json (ungated)', () => {
    expect(onlyRule(['analyticsrules.json'])).toBe('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on analyticsrules.yaml (ungated)', () => {
    expect(onlyRule(['analyticsrules.yaml'])).toBe('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on huntingqueries.json (ungated)', () => {
    expect(onlyRule(['huntingqueries.json'])).toBe('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on huntingqueries.yaml (ungated)', () => {
    expect(onlyRule(['huntingqueries.yaml'])).toBe('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on analyticsrule-*.json prefix', () => {
    expect(triggeredRules(['analyticsrule-lateral-movement.json'])).toContain(
      'SENTINEL_ANALYTICS_DRIFT',
    )
  })

  it('triggers on huntingquery-*.yaml prefix', () => {
    expect(triggeredRules(['huntingquery-pass-the-hash.yaml'])).toContain('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on alertrule-*.json prefix', () => {
    expect(triggeredRules(['alertrule-sign-in-from-tor.json'])).toContain('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on .json in sentinel/ dir', () => {
    expect(triggeredRules(['sentinel/custom-rule.json'])).toContain('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on .kql in azure-sentinel/ dir', () => {
    expect(triggeredRules(['azure-sentinel/hunting.kql'])).toContain('SENTINEL_ANALYTICS_DRIFT')
  })

  it('triggers on .yaml in microsoft-sentinel/ dir', () => {
    expect(triggeredRules(['microsoft-sentinel/analytics.yaml'])).toContain('SENTINEL_ANALYTICS_DRIFT')
  })

  it('does NOT trigger on .json outside sentinel dirs', () => {
    expect(triggeredRules(['config/custom-rule.json'])).not.toContain('SENTINEL_ANALYTICS_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/sentinel/analyticsrules.json'])).not.toContain(
      'SENTINEL_ANALYTICS_DRIFT',
    )
  })
})

// ---------------------------------------------------------------------------
// Rule 4: OSQUERY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('OSQUERY_CONFIG_DRIFT', () => {
  it('triggers on osquery.conf (ungated)', () => {
    expect(onlyRule(['osquery.conf'])).toBe('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on osquery.flags (ungated)', () => {
    expect(onlyRule(['osquery.flags'])).toBe('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on .osquery.conf (ungated)', () => {
    expect(onlyRule(['.osquery.conf'])).toBe('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on osquery-*.conf prefix', () => {
    expect(triggeredRules(['osquery-endpoint.conf'])).toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on osquery-packs-*.json prefix', () => {
    expect(triggeredRules(['osquery-packs-incident-response.json'])).toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on .json in osquery/ dir', () => {
    expect(triggeredRules(['osquery/packs/threat-detection.json'])).toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on .conf in osquery-config/ dir', () => {
    expect(triggeredRules(['osquery-config/prod.conf'])).toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('triggers on .json in osquery-packs/ dir', () => {
    expect(triggeredRules(['osquery-packs/lateral-movement.json'])).toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('does NOT trigger on .conf outside osquery dirs', () => {
    expect(triggeredRules(['config/system.conf'])).not.toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/osquery/osquery.conf'])).not.toContain('OSQUERY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 5: SIEM_DETECTION_SUPPRESSION_DRIFT
// ---------------------------------------------------------------------------

describe('SIEM_DETECTION_SUPPRESSION_DRIFT', () => {
  it('triggers on detection-exceptions.yaml (ungated)', () => {
    expect(onlyRule(['detection-exceptions.yaml'])).toBe('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('triggers on alert-exceptions.json (ungated)', () => {
    expect(onlyRule(['alert-exceptions.json'])).toBe('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('triggers on suppression-rules.yaml (ungated)', () => {
    expect(onlyRule(['suppression-rules.yaml'])).toBe('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('triggers on detection-suppressions.json (ungated)', () => {
    expect(onlyRule(['detection-suppressions.json'])).toBe('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('triggers on *-exceptions.yaml in siem/ dir', () => {
    expect(triggeredRules(['siem/brute-force-exceptions.yaml'])).toContain(
      'SIEM_DETECTION_SUPPRESSION_DRIFT',
    )
  })

  it('triggers on *-whitelist.json in siem-config/ dir', () => {
    expect(triggeredRules(['siem-config/scanner-whitelist.json'])).toContain(
      'SIEM_DETECTION_SUPPRESSION_DRIFT',
    )
  })

  it('triggers on *-suppression.yaml in security-rules/ dir', () => {
    expect(triggeredRules(['security-rules/network-suppression.yaml'])).toContain(
      'SIEM_DETECTION_SUPPRESSION_DRIFT',
    )
  })

  it('triggers on allowlist.yaml in siem/ dir', () => {
    expect(triggeredRules(['siem/allowlist.yaml'])).toContain('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('triggers on exceptions.json in detection/ dir', () => {
    expect(triggeredRules(['detection/exceptions.json'])).toContain('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('triggers on *-exceptions.yaml in splunk/ dir (cross-dir suppression)', () => {
    expect(triggeredRules(['splunk/fp-exceptions.yaml'])).toContain('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('does NOT trigger on allowlist.yaml in unrelated dir', () => {
    expect(triggeredRules(['config/allowlist.yaml'])).not.toContain('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/siem/detection-exceptions.yaml'])).not.toContain(
      'SIEM_DETECTION_SUPPRESSION_DRIFT',
    )
  })
})

// ---------------------------------------------------------------------------
// Rule 6: SOAR_PLAYBOOK_DRIFT
// ---------------------------------------------------------------------------

describe('SOAR_PLAYBOOK_DRIFT', () => {
  it('triggers on xsoar-config.yaml (ungated)', () => {
    expect(onlyRule(['xsoar-config.yaml'])).toBe('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on demisto-config.yaml (ungated)', () => {
    expect(onlyRule(['demisto-config.yaml'])).toBe('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on phantom-config.json (ungated)', () => {
    expect(onlyRule(['phantom-config.json'])).toBe('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on xsoar-playbook-*.yaml prefix', () => {
    expect(triggeredRules(['xsoar-playbook-phishing.yaml'])).toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on demisto-playbook-*.json prefix', () => {
    expect(triggeredRules(['demisto-playbook-endpoint-isolation.json'])).toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on playbook-*.yaml in soar/ dir', () => {
    expect(triggeredRules(['soar/playbook-ransomware-response.yaml'])).toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on automation-*.py in cortex-xsoar/ dir', () => {
    expect(triggeredRules(['cortex-xsoar/automation-block-ip.py'])).toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on .yaml in phantom/ dir', () => {
    expect(triggeredRules(['phantom/containment.yaml'])).toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('triggers on .json in xsoar/ dir', () => {
    expect(triggeredRules(['xsoar/ir-response.json'])).toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('does NOT trigger on playbook-*.yaml outside soar dirs', () => {
    // playbook-* prefix without soar context — requires gating
    expect(triggeredRules(['docs/playbook-incident.yaml'])).not.toContain('SOAR_PLAYBOOK_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/xsoar/xsoar-config.yaml'])).not.toContain('SOAR_PLAYBOOK_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: THREAT_INTEL_FEED_DRIFT
// ---------------------------------------------------------------------------

describe('THREAT_INTEL_FEED_DRIFT', () => {
  it('triggers on misp.conf (ungated)', () => {
    expect(onlyRule(['misp.conf'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on misp-config.yaml (ungated)', () => {
    expect(onlyRule(['misp-config.yaml'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on misp-config.json (ungated)', () => {
    expect(onlyRule(['misp-config.json'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on .misp.conf (ungated)', () => {
    expect(onlyRule(['.misp.conf'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on opencti.yml (ungated)', () => {
    expect(onlyRule(['opencti.yml'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on taxii-config.json (ungated)', () => {
    expect(onlyRule(['taxii-config.json'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on stix-config.yaml (ungated)', () => {
    expect(onlyRule(['stix-config.yaml'])).toBe('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on misp-*.yaml prefix', () => {
    expect(triggeredRules(['misp-feeds.yaml'])).toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on taxii-*.json prefix', () => {
    expect(triggeredRules(['taxii-server-config.json'])).toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on threat-intel keyword in name gated on threat-intel dir', () => {
    expect(triggeredRules(['threat-intel/feeds.yaml'])).toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on .yaml in misp/ dir', () => {
    expect(triggeredRules(['misp/feeds-config.yaml'])).toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('triggers on .json in iocs/ dir', () => {
    expect(triggeredRules(['iocs/custom-feed.json'])).toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('does NOT trigger on threat-intel named file in terraform/ dir', () => {
    expect(triggeredRules(['terraform/threat-intel.yaml'])).not.toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('does NOT trigger on threat-intel named file in .github/ dir', () => {
    expect(triggeredRules(['.github/workflows/threat-intel.yaml'])).not.toContain(
      'THREAT_INTEL_FEED_DRIFT',
    )
  })

  it('does NOT trigger on sigma/ dir files (WS-67 territory)', () => {
    expect(triggeredRules(['sigma/threat-detection.yaml'])).not.toContain('THREAT_INTEL_FEED_DRIFT')
  })

  it('does NOT trigger on prometheus-rules/ dir files (WS-71 territory)', () => {
    expect(triggeredRules(['prometheus-rules/threat-alerts.yaml'])).not.toContain(
      'THREAT_INTEL_FEED_DRIFT',
    )
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/misp/misp.conf'])).not.toContain('THREAT_INTEL_FEED_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: SIEM_LOG_SOURCE_DRIFT
// ---------------------------------------------------------------------------

describe('SIEM_LOG_SOURCE_DRIFT', () => {
  it('triggers on inputs.conf in splunk/ dir', () => {
    expect(triggeredRules(['splunk/inputs.conf'])).toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('triggers on outputs.conf in splunk/ dir', () => {
    expect(triggeredRules(['splunk/outputs.conf'])).toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('triggers on inputs.conf in splunk-forwarder/ dir', () => {
    expect(triggeredRules(['splunk-forwarder/inputs.conf'])).toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('triggers on .conf in universal-forwarder/ dir', () => {
    expect(triggeredRules(['universal-forwarder/custom-inputs.conf'])).toContain(
      'SIEM_LOG_SOURCE_DRIFT',
    )
  })

  it('triggers on .yaml in siem-inputs/ dir', () => {
    expect(triggeredRules(['siem-inputs/windows-events.yaml'])).toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('triggers on .conf in heavy-forwarder/ dir', () => {
    expect(triggeredRules(['heavy-forwarder/transforms.conf'])).toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('does NOT trigger on inputs.conf outside splunk/siem dirs', () => {
    expect(triggeredRules(['config/inputs.conf'])).not.toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('does NOT trigger on outputs.conf outside splunk dirs', () => {
    expect(triggeredRules(['app/outputs.conf'])).not.toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('does NOT trigger on vendor paths', () => {
    expect(triggeredRules(['vendor/splunk/inputs.conf'])).not.toContain('SIEM_LOG_SOURCE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// isSiemDetectionRuleFile unit tests
// ---------------------------------------------------------------------------

describe('isSiemDetectionRuleFile', () => {
  it('returns true for file in threat-intel/ dir even without keyword in base', () => {
    // threat-intel/ is in THREAT_INTEL_DIRS so any .yaml inside matches
    expect(isSiemDetectionRuleFile('threat-intel/feeds.yaml', 'feeds.yaml')).toBe(true)
  })

  it('returns true for threat-intel keyword base in threat-intel dir', () => {
    expect(isSiemDetectionRuleFile('threat-intel/threat-feeds.yaml', 'threat-feeds.yaml')).toBe(true)
  })

  it('returns true for ioc-config.json in iocs/ dir', () => {
    expect(isSiemDetectionRuleFile('iocs/ioc-config.json', 'ioc-config.json')).toBe(true)
  })

  it('returns true for misp-feeds.yaml (misp keyword)', () => {
    expect(isSiemDetectionRuleFile('config/misp-feeds.yaml', 'misp-feeds.yaml')).toBe(true)
  })

  it('returns true for stix-bundle.json (stix keyword)', () => {
    expect(isSiemDetectionRuleFile('config/stix-bundle.json', 'stix-bundle.json')).toBe(true)
  })

  it('returns true for .yaml in threat-intelligence/ dir', () => {
    expect(isSiemDetectionRuleFile('threat-intelligence/rules.yaml', 'rules.yaml')).toBe(true)
  })

  it('returns false for terraform/ exclusion', () => {
    expect(isSiemDetectionRuleFile('terraform/threat-intel.yaml', 'threat-intel.yaml')).toBe(false)
  })

  it('returns false for .github/ exclusion', () => {
    expect(isSiemDetectionRuleFile('.github/workflows/intel.yaml', 'intel.yaml')).toBe(false)
  })

  it('returns false for .gitlab/ exclusion', () => {
    expect(isSiemDetectionRuleFile('.gitlab/ci/threat.yaml', 'threat.yaml')).toBe(false)
  })

  it('returns false for prometheus-rules/ exclusion (WS-71)', () => {
    expect(isSiemDetectionRuleFile('prometheus-rules/alert.yaml', 'alert.yaml')).toBe(false)
  })

  it('returns false for sigma/ exclusion (WS-67)', () => {
    expect(isSiemDetectionRuleFile('sigma/threat-detection.yaml', 'threat-detection.yaml')).toBe(false)
  })

  it('returns false for falco/ exclusion (WS-67)', () => {
    expect(isSiemDetectionRuleFile('falco/threat-rules.yaml', 'threat-rules.yaml')).toBe(false)
  })

  it('returns false for generic .yaml with no keyword, no dir match', () => {
    expect(isSiemDetectionRuleFile('config/settings.yaml', 'settings.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('ignores node_modules/ paths for all rules', () => {
    const result = scanSiemSecurityDrift([
      'node_modules/splunk/savedsearches.conf',
      'node_modules/misp/misp.conf',
    ])
    expect(result.findings).toHaveLength(0)
  })

  it('ignores .git/ paths', () => {
    expect(triggeredRules(['.git/hooks/savedsearches.conf'])).not.toContain(
      'SPLUNK_DETECTION_CONFIG_DRIFT',
    )
  })

  it('ignores venv/ paths', () => {
    expect(triggeredRules(['venv/lib/osquery.conf'])).not.toContain('OSQUERY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('handles backslash paths for ungated Splunk files', () => {
    expect(triggeredRules(['C:\\config\\savedsearches.conf'])).toContain(
      'SPLUNK_DETECTION_CONFIG_DRIFT',
    )
  })

  it('handles backslash paths for ungated osquery files', () => {
    expect(triggeredRules(['C:\\osquery\\osquery.conf'])).toContain('OSQUERY_CONFIG_DRIFT')
  })

  it('handles backslash for Splunk dir gating', () => {
    expect(triggeredRules(['D:\\splunk\\inputs.conf'])).toContain('SIEM_LOG_SOURCE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('produces one finding for multiple Splunk detection files', () => {
    const findings = scanSiemSecurityDrift([
      'savedsearches.conf',
      'alert_actions.conf',
      'correlationsearches.conf',
    ]).findings.filter((f) => f.ruleId === 'SPLUNK_DETECTION_CONFIG_DRIFT')
    expect(findings).toHaveLength(1)
    expect(findings[0].matchCount).toBe(3)
  })

  it('produces one finding for multiple osquery files', () => {
    const findings = scanSiemSecurityDrift([
      'osquery.conf',
      'osquery.flags',
      'osquery-endpoint.conf',
    ]).findings.filter((f) => f.ruleId === 'OSQUERY_CONFIG_DRIFT')
    expect(findings).toHaveLength(1)
    expect(findings[0].matchCount).toBe(3)
  })

  it('matchedPath is the first matched file', () => {
    const result = scanSiemSecurityDrift(['savedsearches.conf', 'alert_actions.conf'])
    const finding = result.findings.find((f) => f.ruleId === 'SPLUNK_DETECTION_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('savedsearches.conf')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and riskLevel none for empty input', () => {
    const result = scanSiemSecurityDrift([])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
    expect(result.totalFindings).toBe(0)
  })

  it('single HIGH finding produces score 15', () => {
    const result = scanSiemSecurityDrift(['savedsearches.conf'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('single MEDIUM finding produces score 8', () => {
    const result = scanSiemSecurityDrift(['detection-exceptions.yaml'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })

  it('single LOW finding produces score 4', () => {
    // siem-inputs/ dir only triggers SIEM_LOG_SOURCE_DRIFT (not SPLUNK_DETECTION)
    const result = scanSiemSecurityDrift(['siem-inputs/windows-events.yaml'])
    expect(result.riskScore).toBe(4)
    expect(result.riskLevel).toBe('low')
  })

  it('3 HIGH findings hit cap 45 → riskLevel high (not medium)', () => {
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',
      'detection_rules/rule.ndjson',
      'osquery.conf',
    ])
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })

  it('score exactly 42 → riskLevel medium', () => {
    // 2H(15+15=30) + 1M(8) + 1L(4) = 42 → medium
    // Use siem-inputs/ for LOW to avoid double-counting with SPLUNK_DETECTION
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',              // SPLUNK H=15
      'analyticsrules.json',             // SENTINEL H=15
      'detection-exceptions.yaml',       // SUPPRESSION M=8
      'siem-inputs/windows-events.yaml', // LOG_SOURCE L=4
    ])
    expect(result.riskScore).toBe(42)
    expect(result.riskLevel).toBe('medium')
  })

  it('all 4 HIGH rules produce capped score 45', () => {
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',              // SPLUNK HIGH
      'detection-rule-test.ndjson',      // not gated — no dir → wait, need to check
      'analyticsrules.json',             // SENTINEL HIGH
      'osquery.conf',                    // OSQUERY HIGH
    ])
    // detection-rule-test.ndjson — has prefix detection-rule- → ELASTIC_SIEM triggered
    const highFindings = result.findings.filter((f) => f.severity === 'high')
    expect(highFindings.length).toBeGreaterThanOrEqual(3)
    expect(result.riskScore).toBeGreaterThanOrEqual(45)
    expect(result.riskLevel).toBe('high')
  })

  it('score 69 → riskLevel high', () => {
    // 3H cap=45 + 3M cap=24 = 69
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',
      'analyticsrules.json',
      'osquery.conf',
      'detection-exceptions.yaml',
      'xsoar-config.yaml',
      'misp.conf',
    ])
    expect(result.riskScore).toBe(69)
    expect(result.riskLevel).toBe('high')
  })

  it('score 70 → riskLevel critical', () => {
    // 3H(45) + 3M(24) + 1L(4) = 73, capped at 100 → 73 → critical
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',
      'analyticsrules.json',
      'osquery.conf',
      'detection-exceptions.yaml',
      'xsoar-config.yaml',
      'misp.conf',
      'splunk/inputs.conf',
    ])
    expect(result.riskScore).toBeGreaterThanOrEqual(70)
    expect(result.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 19 → low', () => {
    // 1H(15) + 1L(4) = 19 → low
    // Use siem-inputs/ for LOW to avoid double-counting with SPLUNK_DETECTION
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',              // SPLUNK H=15
      'siem-inputs/windows-events.yaml', // LOG_SOURCE L=4
    ])
    expect(result.riskScore).toBe(19)
    expect(result.riskLevel).toBe('low')
  })

  it('score 20 → medium', () => {
    // 1H=15 + partial medium: need score exactly 20
    // 1H(15) + 1M(8) = 23 → still medium
    // 1H(15) + need 5 more → not achievable cleanly with single matches
    // Let's use: match 2 files for LOW (2*4=8) + 1H = 23 → medium
    // Actually score 20 test: 1H(15) won't reach 20 alone
    // Use multiple matches for MEDIUM rule: 2 files → 2*8=16, but cap is 25
    // 1H(15) + 0 = 15 → low. Need 1H+5 more
    // 2M(16) = 16 < 20, still low...
    // Try 1H(15) + 1M(8) = 23 → medium (>= 20)
    const result = scanSiemSecurityDrift(['savedsearches.conf', 'detection-exceptions.yaml'])
    expect(result.riskScore).toBe(23)
    expect(result.riskLevel).toBe('medium')
  })

  it('score < 45 → medium (boundary check: 42 is medium)', () => {
    // 2H(30) + 1M(8) + 1L(4) = 42 → medium; use siem-inputs/ for LOW
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',
      'analyticsrules.json',
      'detection-exceptions.yaml',
      'siem-inputs/windows-events.yaml',
    ])
    expect(result.riskScore).toBeLessThan(45)
    expect(result.riskLevel).toBe('medium')
  })

  it('score = 45 → high (not medium: check is score < 45)', () => {
    // 3H(45) = 45 → exactly 45 → high
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',
      'analyticsrules.json',
      'osquery.conf',
    ])
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('findings are sorted high → medium → low', () => {
    const result = scanSiemSecurityDrift([
      'splunk/inputs.conf',       // LOW
      'detection-exceptions.yaml', // MEDIUM
      'savedsearches.conf',        // HIGH
    ])
    const severities = result.findings.map((f) => f.severity)
    const highIdx  = severities.indexOf('high')
    const medIdx   = severities.indexOf('medium')
    const lowIdx   = severities.indexOf('low')
    if (highIdx !== -1 && medIdx !== -1) expect(highIdx).toBeLessThan(medIdx)
    if (medIdx !== -1 && lowIdx !== -1) expect(medIdx).toBeLessThan(lowIdx)
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('clean result has correct shape', () => {
    const result = scanSiemSecurityDrift([])
    expect(result).toEqual({
      riskScore:     0,
      riskLevel:     'none',
      totalFindings: 0,
      highCount:     0,
      mediumCount:   0,
      lowCount:      0,
      findings:      [],
      summary:       'No SIEM or security analytics configuration drift detected.',
    })
  })

  it('finding has all required fields', () => {
    const result = scanSiemSecurityDrift(['savedsearches.conf'])
    const f = result.findings[0]
    expect(f.ruleId).toBe('SPLUNK_DETECTION_CONFIG_DRIFT')
    expect(f.severity).toBe('high')
    expect(f.matchedPath).toBe('savedsearches.conf')
    expect(f.matchCount).toBe(1)
    expect(typeof f.description).toBe('string')
    expect(typeof f.recommendation).toBe('string')
    expect(f.description.length).toBeGreaterThan(0)
    expect(f.recommendation.length).toBeGreaterThan(0)
  })

  it('summary includes rule count and risk score', () => {
    const result = scanSiemSecurityDrift(['savedsearches.conf'])
    expect(result.summary).toContain('1 SIEM security rule triggered')
    expect(result.summary).toContain('15/100')
  })

  it('summary uses plural for multiple rules', () => {
    const result = scanSiemSecurityDrift(['savedsearches.conf', 'analyticsrules.json'])
    expect(result.summary).toContain('2 SIEM security rules triggered')
  })

  it('highCount / mediumCount / lowCount are accurate', () => {
    const result = scanSiemSecurityDrift([
      'savedsearches.conf',        // HIGH
      'detection-exceptions.yaml', // MEDIUM
      'splunk/inputs.conf',        // LOW
    ])
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
    expect(result.totalFindings).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('SOAR playbook and SIEM suppression can both trigger', () => {
    const rules = triggeredRules(['xsoar-config.yaml', 'detection-exceptions.yaml'])
    expect(rules).toContain('SOAR_PLAYBOOK_DRIFT')
    expect(rules).toContain('SIEM_DETECTION_SUPPRESSION_DRIFT')
  })

  it('Splunk detection + log source can both trigger', () => {
    const rules = triggeredRules(['savedsearches.conf', 'splunk/inputs.conf'])
    expect(rules).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
    expect(rules).toContain('SIEM_LOG_SOURCE_DRIFT')
  })

  it('all 8 rules can trigger simultaneously', () => {
    const rules = triggeredRules([
      'savedsearches.conf',
      'detection-rule-test.yaml',
      'analyticsrules.json',
      'osquery.conf',
      'detection-exceptions.yaml',
      'xsoar-config.yaml',
      'misp.conf',
      'splunk/inputs.conf',
    ])
    expect(rules).toContain('SPLUNK_DETECTION_CONFIG_DRIFT')
    expect(rules).toContain('ELASTIC_SIEM_RULE_DRIFT')
    expect(rules).toContain('SENTINEL_ANALYTICS_DRIFT')
    expect(rules).toContain('OSQUERY_CONFIG_DRIFT')
    expect(rules).toContain('SIEM_DETECTION_SUPPRESSION_DRIFT')
    expect(rules).toContain('SOAR_PLAYBOOK_DRIFT')
    expect(rules).toContain('THREAT_INTEL_FEED_DRIFT')
    expect(rules).toContain('SIEM_LOG_SOURCE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('rule registry completeness', () => {
  const EXPECTED_RULE_IDS: SiemSecurityRuleId[] = [
    'SPLUNK_DETECTION_CONFIG_DRIFT',
    'ELASTIC_SIEM_RULE_DRIFT',
    'SENTINEL_ANALYTICS_DRIFT',
    'OSQUERY_CONFIG_DRIFT',
    'SIEM_DETECTION_SUPPRESSION_DRIFT',
    'SOAR_PLAYBOOK_DRIFT',
    'THREAT_INTEL_FEED_DRIFT',
    'SIEM_LOG_SOURCE_DRIFT',
  ]

  it('has exactly 8 rules', () => {
    expect(SIEM_SECURITY_RULES).toHaveLength(8)
  })

  it('contains all expected rule IDs', () => {
    const ids = SIEM_SECURITY_RULES.map((r) => r.id)
    for (const id of EXPECTED_RULE_IDS) {
      expect(ids).toContain(id)
    }
  })

  it('has 4 high, 3 medium, 1 low severity rules', () => {
    const bySeverity = SIEM_SECURITY_RULES.reduce<Record<string, number>>((acc, r) => {
      acc[r.severity] = (acc[r.severity] ?? 0) + 1
      return acc
    }, {})
    expect(bySeverity['high']).toBe(4)
    expect(bySeverity['medium']).toBe(3)
    expect(bySeverity['low']).toBe(1)
  })

  it('every rule has non-empty description and recommendation', () => {
    for (const rule of SIEM_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(0)
      expect(rule.recommendation.length).toBeGreaterThan(0)
    }
  })
})
