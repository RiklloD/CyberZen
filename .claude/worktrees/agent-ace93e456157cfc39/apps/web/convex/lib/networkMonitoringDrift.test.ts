import { describe, it, expect } from 'vitest'
import {
  scanNetworkMonitoringDrift,
  isNetworkNmsConfig,
} from './networkMonitoringDrift'

// ---------------------------------------------------------------------------
// Rule 1: SNMPD_DAEMON_DRIFT (high)
// ---------------------------------------------------------------------------

describe('SNMPD_DAEMON_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'snmpd.conf',
      'snmp.conf',
      'snmpd.conf.local',
      'snmpd-v3.conf',
      'snmp-v3.conf',
      'snmp.conf.local',
      'snmpd-listen.conf',
      'snmpd.conf.d',
      'snmp-access.conf',
      'snmpd-access.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(true)
    })
  })

  describe('gated exact names', () => {
    it.each(['community.conf', 'users.conf', 'access.conf', 'mibs.conf'])(
      '%s alone does NOT match',
      (file) => {
        const r = scanNetworkMonitoringDrift([file])
        expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(false)
      },
    )

    it.each([
      ['snmp/community.conf', 'snmp/'],
      ['etc/snmp/users.conf', 'etc/snmp/'],
      ['snmpd/access.conf', 'snmpd/'],
    ])('%s matches in %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each(['snmpd-custom.conf', 'snmpd-v2.cfg', 'snmp-config-v3.yaml'])(
      'matches %s',
      (file) => {
        const r = scanNetworkMonitoringDrift([file])
        expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(true)
      },
    )
  })

  describe('directory-based', () => {
    it.each([
      'snmp/daemon.conf',
      'etc/snmp/settings.yaml',
      'snmp-config/main.ini',
      'monitoring/snmp/polling.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanNetworkMonitoringDrift(['node_modules/snmpd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: NAGIOS_NRPE_DRIFT (high)
// ---------------------------------------------------------------------------

describe('NAGIOS_NRPE_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'nagios.cfg',
      'nagios.conf',
      'nagios3.cfg',
      'nagios4.cfg',
      'nrpe.cfg',
      'nrpe.conf',
      'nrpe_local.cfg',
      'nrpe-local.cfg',
      'icinga.cfg',
      'icinga2.conf',
      'icingaweb2.ini',
      'nagios-commands.cfg',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NAGIOS_NRPE_DRIFT')).toBe(true)
    })
  })

  describe('gated exact names', () => {
    it('objects.cfg alone does NOT match', () => {
      const r = scanNetworkMonitoringDrift(['objects.cfg'])
      expect(r.findings.some((f) => f.ruleId === 'NAGIOS_NRPE_DRIFT')).toBe(false)
    })

    it.each([
      ['nagios/objects.cfg', 'nagios/'],
      ['etc/nagios/hosts.cfg', 'etc/nagios/'],
      ['nagios4/services.cfg', 'nagios4/'],
      ['icinga2/contacts.cfg', 'icinga2/'],
    ])('%s matches in %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NAGIOS_NRPE_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'nagios-local.cfg',
      'nrpe-checks.conf',
      'icinga-hostgroups.yaml',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NAGIOS_NRPE_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'nagios/local.cfg',
      'nrpe/custom-checks.conf',
      'icinga2/conf.d/services.yaml',
      'nagios-config/hosts.ini',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NAGIOS_NRPE_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 3: ZABBIX_MONITORING_DRIFT (high)
// ---------------------------------------------------------------------------

describe('ZABBIX_MONITORING_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'zabbix_server.conf',
      'zabbix_agentd.conf',
      'zabbix_proxy.conf',
      'zabbix_agent.conf',
      'zabbix_agent2.conf',
      'zabbix.conf',
      'zabbix-server.conf',
      'zabbix-agent.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ZABBIX_MONITORING_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'zabbix-proxy-config.conf',
      'zabbix-templates.yaml',
      'zabbix_agentd-custom.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ZABBIX_MONITORING_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'zabbix/agent.conf',
      'etc/zabbix/agent-custom.conf',
      'zabbix-config/userparams.conf',
      'zabbix-agent2/agent2.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ZABBIX_MONITORING_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanNetworkMonitoringDrift(['vendor/zabbix_server.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ZABBIX_MONITORING_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: NETFLOW_ANALYSIS_DRIFT (high)
// ---------------------------------------------------------------------------

describe('NETFLOW_ANALYSIS_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'pmacct.conf',
      'pmacctd.conf',
      'nfdump.conf',
      'ntopng.conf',
      'nprobe.conf',
      'softflowd.conf',
      'fprobe.conf',
      'ipt-netflow.conf',
      'flowctl.conf',
      'nfsen.conf',
      'fastnetmon.conf',
      'fastnetmon.lua',
      'sflowtool.conf',
      'sflow.conf',
      'netflow.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETFLOW_ANALYSIS_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'pmacct-bgp.conf',
      'ntopng-community.conf',
      'netflow-collector.yaml',
      'sflow-analyzer.conf',
      'fastnetmon-advanced.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETFLOW_ANALYSIS_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'pmacct/bgp.conf',
      'netflow/collector.yaml',
      'sflow/exporter.conf',
      'traffic-analysis/main.toml',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETFLOW_ANALYSIS_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 5: LIBRENMS_OXIDIZED_DRIFT (medium) — isNetworkNmsConfig unit tests
// ---------------------------------------------------------------------------

describe('isNetworkNmsConfig', () => {
  describe('ungated exact names', () => {
    it.each([
      ['oxidized.conf', 'oxidized.conf'],
      ['oxidized.yaml', 'oxidized.yaml'],
      ['oxidized.yml', 'oxidized.yml'],
      ['netdisco.conf', 'netdisco.conf'],
      ['netdisco.yml', 'netdisco.yml'],
      ['rancid.conf', 'rancid.conf'],
      ['.rancid.conf', '.rancid.conf'],
    ])('%s matches', (path, base) => {
      expect(isNetworkNmsConfig(path, base)).toBe(true)
    })
  })

  describe('config.php — gated on NMS directory', () => {
    it('config.php in librenms/ matches', () => {
      expect(isNetworkNmsConfig('librenms/config.php', 'config.php')).toBe(true)
    })
    it('config.php in cacti/ matches', () => {
      expect(isNetworkNmsConfig('cacti/config.php', 'config.php')).toBe(true)
    })
    it('config.php in observium/ matches', () => {
      expect(isNetworkNmsConfig('observium/config.php', 'config.php')).toBe(true)
    })
    it('config.custom.php in librenms/ matches', () => {
      expect(isNetworkNmsConfig('librenms/config.custom.php', 'config.custom.php')).toBe(true)
    })
    it('config.php at root does NOT match', () => {
      expect(isNetworkNmsConfig('config.php', 'config.php')).toBe(false)
    })
    it('config.php in app/config/ does NOT match', () => {
      expect(isNetworkNmsConfig('app/config/config.php', 'config.php')).toBe(false)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      ['librenms-config.yaml', 'librenms-config.yaml'],
      ['oxidized-extra.conf', 'oxidized-extra.conf'],
      ['cacti-settings.php', 'cacti-settings.php'],
      ['rancid-cloginrc.conf', 'rancid-cloginrc.conf'],
    ])('%s matches', (path, base) => {
      expect(isNetworkNmsConfig(path, base)).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      ['librenms/bootstrap.php', 'bootstrap.php'],
      ['oxidized/router.conf', 'router.conf'],
      ['nms/polling.conf', 'polling.conf'],
      ['network-monitoring/main.yaml', 'main.yaml'],
    ])('%s matches in NMS dir', (path, base) => {
      expect(isNetworkNmsConfig(path, base)).toBe(true)
    })
  })

  it('generic config.yaml not in NMS dir does NOT match', () => {
    expect(isNetworkNmsConfig('src/config.yaml', 'config.yaml')).toBe(false)
  })
})

describe('LIBRENMS_OXIDIZED_DRIFT scanner rule', () => {
  it('triggers for oxidized.conf', () => {
    const r = scanNetworkMonitoringDrift(['oxidized.conf'])
    expect(r.findings.some((f) => f.ruleId === 'LIBRENMS_OXIDIZED_DRIFT')).toBe(true)
  })

  it('triggers for librenms/config.php', () => {
    const r = scanNetworkMonitoringDrift(['librenms/config.php'])
    expect(r.findings.some((f) => f.ruleId === 'LIBRENMS_OXIDIZED_DRIFT')).toBe(true)
  })

  it('does NOT trigger for config.php at root', () => {
    const r = scanNetworkMonitoringDrift(['config.php'])
    expect(r.findings.some((f) => f.ruleId === 'LIBRENMS_OXIDIZED_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: NETDATA_STREAMING_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('NETDATA_STREAMING_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'netdata.conf',
      'health_alarm_notify.conf',
      'exporting.conf',
      'netdata-exporters.conf',
      'go.d.conf',
      'apps_groups.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETDATA_STREAMING_DRIFT')).toBe(true)
    })
  })

  describe('gated exact names', () => {
    it('stream.conf alone does NOT match', () => {
      const r = scanNetworkMonitoringDrift(['stream.conf'])
      expect(r.findings.some((f) => f.ruleId === 'NETDATA_STREAMING_DRIFT')).toBe(false)
    })

    it('stream.conf in netdata/ matches', () => {
      const r = scanNetworkMonitoringDrift(['netdata/stream.conf'])
      expect(r.findings.some((f) => f.ruleId === 'NETDATA_STREAMING_DRIFT')).toBe(true)
    })

    it('health.conf in etc/netdata/ matches', () => {
      const r = scanNetworkMonitoringDrift(['etc/netdata/health.conf'])
      expect(r.findings.some((f) => f.ruleId === 'NETDATA_STREAMING_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'netdata-streaming.conf',
      'netdata-health-custom.yaml',
      'health-alarm-custom.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETDATA_STREAMING_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'netdata/python.d/mysql.conf',
      '.netdata/custom.conf',
      'etc/netdata/go.d/nginx.conf',
      'netdata-config/main.yaml',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETDATA_STREAMING_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 7: SNMP_TRAP_RECEIVER_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('SNMP_TRAP_RECEIVER_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'snmptrapd.conf',
      'snmptt.conf',
      'snmptt.ini',
      'trapd.conf',
      'snmp-traps.conf',
      'traphandle.conf',
      'snmptrapd-config.conf',
      'trapd-config.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SNMP_TRAP_RECEIVER_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'snmptrapd-custom.conf',
      'snmptt-extra.ini',
      'trap-handler.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SNMP_TRAP_RECEIVER_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'snmptrap/handler.conf',
      'snmptt/snmptt.ini',
      'traps/definitions.yaml',
      'snmp/traps/custom.conf',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SNMP_TRAP_RECEIVER_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 8: NETWORK_PROBE_CONFIG_DRIFT (low)
// ---------------------------------------------------------------------------

describe('NETWORK_PROBE_CONFIG_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'masscan.conf',
      'masscan.json',
      'unicornscan.conf',
      'zmap.conf',
      'nmap.conf',
      'nmap.ini',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETWORK_PROBE_CONFIG_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'masscan-internal.conf',
      'masscan-external.json',
      'zmap-scan.yaml',
      'nmap-config-full.yaml',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETWORK_PROBE_CONFIG_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'nmap/scan-profile.yaml',
      'masscan/targets.conf',
      'network-scan/schedule.yaml',
      'probe/subnets.json',
    ])('matches %s', (file) => {
      const r = scanNetworkMonitoringDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'NETWORK_PROBE_CONFIG_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Scanner integration tests
// ---------------------------------------------------------------------------

describe('scanNetworkMonitoringDrift — integration', () => {
  it('empty file list returns zero-score result', () => {
    const r = scanNetworkMonitoringDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.highCount).toBe(0)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
  })

  it('clean file paths produce no findings', () => {
    const r = scanNetworkMonitoringDrift([
      'src/index.ts',
      'README.md',
      'package.json',
      'config/app.yaml',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskScore).toBe(0)
  })

  it('summary message for empty result', () => {
    const r = scanNetworkMonitoringDrift([])
    expect(r.summary).toBe('No network monitoring or SNMP security configuration changes detected.')
  })

  it('summary message for single finding (singular)', () => {
    const r = scanNetworkMonitoringDrift(['snmpd.conf'])
    expect(r.summary).toContain('1 network monitoring/SNMP security configuration file modified')
    expect(r.summary).toContain('15/100')
  })

  it('summary message for multiple findings (plural)', () => {
    const r = scanNetworkMonitoringDrift(['snmpd.conf', 'nagios.cfg'])
    expect(r.summary).toContain('2 network monitoring/SNMP security configuration files modified')
  })
})

// ---------------------------------------------------------------------------
// Risk score + level boundary tests
// ---------------------------------------------------------------------------

describe('risk score and level boundaries', () => {
  it('1 LOW finding → score 4 → low', () => {
    const r = scanNetworkMonitoringDrift(['masscan.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('1 MEDIUM finding → score 8 → low', () => {
    const r = scanNetworkMonitoringDrift(['oxidized.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('1 HIGH finding → score 15 → medium (15 is not < 15)', () => {
    const r = scanNetworkMonitoringDrift(['snmpd.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('2 HIGH findings → score 30 → medium', () => {
    const r = scanNetworkMonitoringDrift(['snmpd.conf', 'nagios.cfg'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('3 HIGH findings → score 45 → high (45 is not < 45)', () => {
    const r = scanNetworkMonitoringDrift(['snmpd.conf', 'nagios.cfg', 'zabbix_server.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('4 HIGH findings → score capped at 45 → high', () => {
    const r = scanNetworkMonitoringDrift([
      'snmpd.conf', 'nagios.cfg', 'zabbix_server.conf', 'pmacct.conf',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
    expect(r.highCount).toBe(4)
  })

  it('all 8 rules triggered → score 73 → high (not critical)', () => {
    const files = [
      'snmpd.conf',        // SNMPD_DAEMON_DRIFT (high)
      'nagios.cfg',        // NAGIOS_NRPE_DRIFT (high)
      'zabbix_server.conf',// ZABBIX_MONITORING_DRIFT (high)
      'pmacct.conf',       // NETFLOW_ANALYSIS_DRIFT (high)
      'oxidized.conf',     // LIBRENMS_OXIDIZED_DRIFT (medium)
      'netdata.conf',      // NETDATA_STREAMING_DRIFT (medium)
      'snmptrapd.conf',    // SNMP_TRAP_RECEIVER_DRIFT (medium)
      'masscan.conf',      // NETWORK_PROBE_CONFIG_DRIFT (low)
    ]
    const r = scanNetworkMonitoringDrift(files)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
    // min(4*15,45) + min(3*8,25) + min(1*4,15) = 45 + 24 + 4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
  })
})

// ---------------------------------------------------------------------------
// Deduplication and matchCount
// ---------------------------------------------------------------------------

describe('deduplication and matchCount', () => {
  it('multiple SNMP files produce 1 finding with correct matchCount', () => {
    const files = ['snmpd.conf', 'snmp.conf', 'snmpd-v3.conf', 'snmp/community.conf']
    const r = scanNetworkMonitoringDrift(files)
    const f = r.findings.find((x) => x.ruleId === 'SNMPD_DAEMON_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(4)
    expect(r.findings.filter((x) => x.ruleId === 'SNMPD_DAEMON_DRIFT')).toHaveLength(1)
  })

  it('matchedPath is the first matched file', () => {
    const files = ['nagios3.cfg', 'nrpe.cfg']
    const r = scanNetworkMonitoringDrift(files)
    const f = r.findings.find((x) => x.ruleId === 'NAGIOS_NRPE_DRIFT')
    expect(f!.matchedPath).toBe('nagios3.cfg')
  })

  it('multiple Zabbix files produce 1 finding', () => {
    const files = ['zabbix_server.conf', 'zabbix_agentd.conf', 'zabbix_proxy.conf']
    const r = scanNetworkMonitoringDrift(files)
    const f = r.findings.find((x) => x.ruleId === 'ZABBIX_MONITORING_DRIFT')
    expect(f!.matchCount).toBe(3)
    expect(r.findings.filter((x) => x.ruleId === 'ZABBIX_MONITORING_DRIFT')).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('vendor path exclusion', () => {
  it.each([
    'node_modules/snmpd.conf',
    'vendor/nagios.cfg',
    '.git/zabbix_server.conf',
    'dist/pmacct.conf',
    'build/netdata.conf',
    '.cache/oxidized.conf',
  ])('excludes %s', (file) => {
    const r = scanNetworkMonitoringDrift([file])
    expect(r.totalFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('path normalisation', () => {
  it('normalises backslashes', () => {
    const r = scanNetworkMonitoringDrift(['snmp\\snmpd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SNMPD_DAEMON_DRIFT')).toBe(true)
  })

  it('strips leading ./ prefix', () => {
    const r = scanNetworkMonitoringDrift(['./nagios.cfg'])
    expect(r.findings.some((f) => f.ruleId === 'NAGIOS_NRPE_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Finding shape
// ---------------------------------------------------------------------------

describe('finding shape', () => {
  it('finding has all required fields', () => {
    const r = scanNetworkMonitoringDrift(['snmpd.conf'])
    const f = r.findings[0]
    expect(f).toHaveProperty('ruleId', 'SNMPD_DAEMON_DRIFT')
    expect(f).toHaveProperty('severity', 'high')
    expect(f).toHaveProperty('matchedPath', 'snmpd.conf')
    expect(f).toHaveProperty('matchCount', 1)
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
})
