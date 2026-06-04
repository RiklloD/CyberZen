import { describe, it, expect } from 'vitest'
import {
  scanVoipSecurityDrift,
  isWebConferenceServerConfig,
} from './voipSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: ASTERISK_PBX_DRIFT (high)
// ---------------------------------------------------------------------------

describe('ASTERISK_PBX_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'sip.conf',
      'pjsip.conf',
      'asterisk.conf',
      'extensions.conf',
      'voicemail.conf',
      'queues.conf',
      'agents.conf',
      'sip_notify.conf',
      'iax.conf',
      'iax2.conf',
      'extensions_custom.conf',
      'pjsip_wizard.conf',
      'pjsip_notify.conf',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
    })
  })

  describe('gated exact names — only match inside ASTERISK_DIRS', () => {
    it.each([
      'manager.conf',
      'rtp.conf',
      'modules.conf',
      'logger.conf',
      'res_odbc.conf',
      'cdr.conf',
      'cel.conf',
    ])('%s alone does NOT match', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(false)
    })

    it.each([
      ['asterisk/manager.conf', 'asterisk/'],
      ['etc/asterisk/rtp.conf', 'etc/asterisk/'],
      ['freepbx/modules.conf', 'freepbx/'],
      ['pbx/logger.conf', 'pbx/'],
      ['asterisk-config/cdr.conf', 'asterisk-config/'],
    ])('%s matches (in %s)', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'asterisk-sip-settings.conf',
      'asterisk-main.cfg',
      'asterisk-pjsip.json',
      'asterisk-peers.yaml',
      'freepbx-main.conf',
      'freepbx-modules.cfg',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
    })

    it('asterisk prefix without matching extension does NOT match', () => {
      const r = scanVoipSecurityDrift(['asterisk-notes.txt'])
      expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(false)
    })
  })

  describe('directory-based', () => {
    it.each([
      'asterisk/sip_custom.conf',
      'asterisk/res_pjsip.conf',
      '.asterisk/local.cfg',
      'freepbx/amportal.conf',
      'pbx/dialplan.ael',
      'asterisk-conf/local.lua',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
    })
  })

  it('vendor path is excluded', () => {
    const r = scanVoipSecurityDrift(['node_modules/asterisk/sip.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: KAMAILIO_OPENSIPS_DRIFT (high)
// ---------------------------------------------------------------------------

describe('KAMAILIO_OPENSIPS_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'kamailio.cfg',
      'opensips.cfg',
      'opensips.conf',
      'kamailio.json',
      'opensips.json',
      'kamailio.conf',
      'kamailio-local.cfg',
      'opensips-local.cfg',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'KAMAILIO_OPENSIPS_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'kamailio-routing.cfg',
      'kamailio-tls.conf',
      'kamailio-auth.yaml',
      'opensips-dispatcher.cfg',
      'opensips-modules.conf',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'KAMAILIO_OPENSIPS_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'kamailio/auth.conf',
      'opensips/dispatcher.cfg',
      'sip-proxy/routing.yaml',
      'sip-server/tls.conf',
      'sip-registrar/modules.xml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'KAMAILIO_OPENSIPS_DRIFT')).toBe(true)
    })
  })

  it('vendor path is excluded', () => {
    const r = scanVoipSecurityDrift(['vendor/kamailio.cfg'])
    expect(r.findings.some((f) => f.ruleId === 'KAMAILIO_OPENSIPS_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: FREESWITCH_DRIFT (high)
// ---------------------------------------------------------------------------

describe('FREESWITCH_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'freeswitch.xml',
      'freeswitch.conf',
      'switch.conf.xml',
      'freeswitch.json',
      'freeswitch.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'FREESWITCH_DRIFT')).toBe(true)
    })
  })

  describe('gated exact names', () => {
    it.each([
      'vars.xml',
      'dialplan.xml',
      'directory.xml',
      'sofia.conf.xml',
      'event_socket.conf.xml',
    ])('%s alone does NOT match', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'FREESWITCH_DRIFT')).toBe(false)
    })

    it.each([
      ['freeswitch/vars.xml', 'freeswitch/'],
      ['etc/freeswitch/dialplan.xml', 'etc/freeswitch/'],
      ['freeswitch-conf/directory.xml', 'freeswitch-conf/'],
      ['fs-config/sofia.conf.xml', 'fs-config/'],
    ])('%s matches (in %s)', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'FREESWITCH_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'freeswitch-dialplan.xml',
      'freeswitch-sip-profile.conf',
      'fs-config.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'FREESWITCH_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'freeswitch/sofia-profile.conf',
      'etc/freeswitch/autoload_configs/modules.conf.xml',
      'freeswitch-config/sounds.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'FREESWITCH_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 4: SIP_TRUNK_CREDENTIALS_DRIFT (high)
// ---------------------------------------------------------------------------

describe('SIP_TRUNK_CREDENTIALS_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'sip-trunk.conf',
      'sip-trunk.yaml',
      'sip-trunk.yml',
      'sip-trunk.json',
      'sip-provider.conf',
      'sip-provider.json',
      'sip-provider.yaml',
      'sip-credentials.conf',
      'sip-credentials.json',
      'voip-credentials.conf',
      'voip-credentials.json',
      'trunk-config.conf',
      'trunk-config.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SIP_TRUNK_CREDENTIALS_DRIFT')).toBe(true)
    })
  })

  describe('gated exact names', () => {
    it.each([
      'trunk.conf',
      'trunk.json',
      'trunk.yaml',
      'trunk.yml',
      'provider.conf',
      'provider.json',
    ])('%s alone does NOT match', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SIP_TRUNK_CREDENTIALS_DRIFT')).toBe(false)
    })

    it.each([
      ['sip/trunk.conf', 'sip/'],
      ['voip/trunk.yaml', 'voip/'],
      ['trunks/provider.json', 'trunks/'],
      ['sip-trunk/provider.conf', 'sip-trunk/'],
    ])('%s matches (in %s)', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SIP_TRUNK_CREDENTIALS_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'sip-trunk-primary.json',
      'sip-provider-twilio.yaml',
      'voip-trunk-backup.conf',
      'voip-credentials-prod.json',
      'sip-credentials-main.conf',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SIP_TRUNK_CREDENTIALS_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'sip/settings.yaml',
      'voip/config.conf',
      'sip-config/main.json',
      'voip-trunks/carrier.cfg',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SIP_TRUNK_CREDENTIALS_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 5: JITSI_WEBRTC_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('JITSI_WEBRTC_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'jitsi-meet.conf',
      'coturn.conf',
      'turnserver.conf',
      'jicofo.conf',
      'jvb.conf',
      'jvb.yaml',
      'coturn.yaml',
      'turn.conf',
      'stun.conf',
      'prosody.cfg.lua',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'JITSI_WEBRTC_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'jitsi-config.yaml',
      'coturn-extra.conf',
      'turn-server-settings.cfg',
      'stun-relay.json',
      'webrtc-media.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'JITSI_WEBRTC_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'jitsi/meet.conf',
      'jitsi-meet/settings.yaml',
      'coturn/turnserver.conf',
      'webrtc/ice.yaml',
      'turn/relay.conf',
      'jvb/config.conf',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'JITSI_WEBRTC_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 6: VOIP_GATEWAY_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('VOIP_GATEWAY_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'voip-gateway.conf',
      'voip-gateway.yaml',
      'voip-gateway.yml',
      'voip-gateway.json',
      'sip-gateway.conf',
      'sip-gateway.json',
      'ata-config.conf',
      'ata-config.json',
      'ata-config.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VOIP_GATEWAY_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated (vendor hardware)', () => {
    it.each([
      'sangoma-gw200.conf',
      'sangoma-sbc.yaml',
      'audiocodes-mp118.json',
      'audiocodes-m1k.cfg',
      'patton-smartnode.conf',
      'grandstream-ht814.xml',
      'grandstream-ucm.yaml',
      'voip-gateway-primary.conf',
      'sip-gateway-backup.json',
      'ata-legacy.cfg',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VOIP_GATEWAY_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'voip-gateway/device.cfg',
      'gateway/sip.conf',
      'sip-gateway/routing.yaml',
      'ata/analog.json',
      'voip/gateway-settings.xml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VOIP_GATEWAY_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 7: WEBCONFERENCE_SECURITY_DRIFT (medium) — isWebConferenceServerConfig
// ---------------------------------------------------------------------------

describe('isWebConferenceServerConfig', () => {
  describe('ungated exact names', () => {
    it.each([
      ['bigbluebutton.properties', 'bigbluebutton.properties'],
      ['bbb-conf.conf', 'bbb-conf.conf'],
      ['bbb-web.properties', 'bbb-web.properties'],
      ['synapse.yaml', 'synapse.yaml'],
      ['synapse.conf', 'synapse.conf'],
      ['synapse.json', 'synapse.json'],
      ['rocketchat.conf', 'rocketchat.conf'],
      ['rocket.chat.conf', 'rocket.chat.conf'],
      ['rocketchat.yaml', 'rocketchat.yaml'],
      ['mattermost.json', 'mattermost.json'],
      ['mattermost.yaml', 'mattermost.yaml'],
      ['mattermost.conf', 'mattermost.conf'],
    ])('%s matches', (path, base) => {
      expect(isWebConferenceServerConfig(path, base)).toBe(true)
    })
  })

  describe('homeserver.yaml — gated on matrix/ or synapse/ dir', () => {
    it('matches in matrix/ directory', () => {
      expect(isWebConferenceServerConfig('matrix/homeserver.yaml', 'homeserver.yaml')).toBe(true)
    })
    it('matches in synapse/ directory', () => {
      expect(isWebConferenceServerConfig('synapse/homeserver.yml', 'homeserver.yml')).toBe(true)
    })
    it('matches homeserver.json in matrix/ dir', () => {
      expect(isWebConferenceServerConfig('config/matrix/homeserver.json', 'homeserver.json')).toBe(true)
    })
    it('does NOT match homeserver.yaml at root', () => {
      expect(isWebConferenceServerConfig('homeserver.yaml', 'homeserver.yaml')).toBe(false)
    })
    it('does NOT match homeserver.yaml in unrelated directory', () => {
      expect(isWebConferenceServerConfig('server/homeserver.yaml', 'homeserver.yaml')).toBe(false)
    })
    it('does NOT match homeserver.yaml in app/ directory', () => {
      expect(isWebConferenceServerConfig('app/config/homeserver.yaml', 'homeserver.yaml')).toBe(false)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      ['synapse-config.yaml', 'synapse-config.yaml'],
      ['synapse-workers.conf', 'synapse-workers.conf'],
      ['matrix-appservice.json', 'matrix-appservice.json'],
      ['bbb-settings.conf', 'bbb-settings.conf'],
      ['bbb-greenlight.env', 'bbb-greenlight.env'],
      ['mattermost-config.yaml', 'mattermost-config.yaml'],
      ['rocketchat-env.conf', 'rocketchat-env.conf'],
      ['nextcloud-talk-config.json', 'nextcloud-talk-config.json'],
    ])('matches %s', (path, base) => {
      expect(isWebConferenceServerConfig(path, base)).toBe(true)
    })

    it('synapse prefix without matching extension does NOT match', () => {
      expect(isWebConferenceServerConfig('synapse-readme.txt', 'synapse-readme.txt')).toBe(false)
    })
  })

  describe('directory-based', () => {
    it.each([
      ['matrix/registration.yaml', 'registration.yaml'],
      ['synapse/log_config.yaml', 'log_config.yaml'],
      ['bigbluebutton/settings.conf', 'settings.conf'],
      ['bbb/nginx.conf', 'nginx.conf'],
      ['rocketchat/settings.json', 'settings.json'],
      ['mattermost/config.json', 'config.json'],
      ['nextcloud-talk/config.yaml', 'config.yaml'],
      ['webconference/main.cfg', 'main.cfg'],
    ])('matches %s in dir context', (path, base) => {
      expect(isWebConferenceServerConfig(path, base)).toBe(true)
    })
  })

  it('generic config.json outside webconf dirs does NOT match', () => {
    expect(isWebConferenceServerConfig('src/config.json', 'config.json')).toBe(false)
  })
})

describe('WEBCONFERENCE_SECURITY_DRIFT scanner rule', () => {
  it('triggers for synapse.yaml', () => {
    const r = scanVoipSecurityDrift(['synapse.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'WEBCONFERENCE_SECURITY_DRIFT')).toBe(true)
  })

  it('triggers for bigbluebutton.properties', () => {
    const r = scanVoipSecurityDrift(['bigbluebutton.properties'])
    expect(r.findings.some((f) => f.ruleId === 'WEBCONFERENCE_SECURITY_DRIFT')).toBe(true)
  })

  it('triggers for matrix/homeserver.yaml', () => {
    const r = scanVoipSecurityDrift(['matrix/homeserver.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'WEBCONFERENCE_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT trigger for homeserver.yaml at root', () => {
    const r = scanVoipSecurityDrift(['homeserver.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'WEBCONFERENCE_SECURITY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: VOIP_CDR_MONITORING_DRIFT (low)
// ---------------------------------------------------------------------------

describe('VOIP_CDR_MONITORING_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'homer.cfg',
      'homer.conf',
      'homer.yaml',
      'homer.yml',
      'sngrep.conf',
      'sngrep.yaml',
      'sipcapture.conf',
      'heplify.yml',
      'heplify.yaml',
      'heplify-server.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VOIP_CDR_MONITORING_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'homer-api.conf',
      'homer-bootstrap.yaml',
      'sngrep-capture.conf',
      'heplify-relay.yml',
      'sipcapture-filters.toml',
      'voip-monitor-alerts.json',
      'voip-cdr-export.conf',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VOIP_CDR_MONITORING_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'homer/capture.yaml',
      'cdr/export.conf',
      'voip-monitor/alerts.toml',
      'sngrep/filters.cfg',
      'heplify/relay.json',
      'voip-cdr/pipeline.yaml',
    ])('matches %s', (file) => {
      const r = scanVoipSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VOIP_CDR_MONITORING_DRIFT')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Scanner integration tests
// ---------------------------------------------------------------------------

describe('scanVoipSecurityDrift — integration', () => {
  it('empty file list returns zero-score result', () => {
    const r = scanVoipSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.highCount).toBe(0)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
  })

  it('clean file paths produce no findings', () => {
    const r = scanVoipSecurityDrift([
      'src/index.ts',
      'README.md',
      'package.json',
      'config/app.yaml',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskScore).toBe(0)
  })

  it('summary message for empty result', () => {
    const r = scanVoipSecurityDrift([])
    expect(r.summary).toBe('No VoIP or unified communications security configuration changes detected.')
  })

  it('summary message for non-empty result (singular)', () => {
    const r = scanVoipSecurityDrift(['sip.conf'])
    expect(r.summary).toContain('1 VoIP/UC security configuration file modified')
    expect(r.summary).toContain('15/100')
  })

  it('summary message for non-empty result (plural)', () => {
    const r = scanVoipSecurityDrift(['sip.conf', 'kamailio.cfg'])
    expect(r.summary).toContain('2 VoIP/UC security configuration files modified')
  })
})

// ---------------------------------------------------------------------------
// Risk score + level boundary tests
// ---------------------------------------------------------------------------

describe('risk score and level boundaries', () => {
  it('1 LOW finding → score 4 → low', () => {
    const r = scanVoipSecurityDrift(['homer.cfg'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('2 LOW findings (dedup) → still 1 finding → score 4 → low', () => {
    const r = scanVoipSecurityDrift(['homer.cfg', 'homer.conf'])
    expect(r.findings.filter((f) => f.ruleId === 'VOIP_CDR_MONITORING_DRIFT')).toHaveLength(1)
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('1 MEDIUM finding → score 8 → low', () => {
    const r = scanVoipSecurityDrift(['coturn.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('1 HIGH finding → score 15 → medium (15 is not < 15)', () => {
    const r = scanVoipSecurityDrift(['sip.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('2 HIGH findings → score 30 → medium', () => {
    const r = scanVoipSecurityDrift(['sip.conf', 'kamailio.cfg'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('3 HIGH findings → score 45 → high (45 is not < 45)', () => {
    const r = scanVoipSecurityDrift(['sip.conf', 'kamailio.cfg', 'freeswitch.xml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('4 HIGH findings → score capped at 45 → high', () => {
    const r = scanVoipSecurityDrift(['sip.conf', 'kamailio.cfg', 'freeswitch.xml', 'sip-trunk.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
    expect(r.highCount).toBe(4)
  })

  it('all 8 rules triggered → score 73 → high (not critical)', () => {
    const files = [
      'sip.conf',          // ASTERISK_PBX_DRIFT (high)
      'kamailio.cfg',      // KAMAILIO_OPENSIPS_DRIFT (high)
      'freeswitch.xml',    // FREESWITCH_DRIFT (high)
      'sip-trunk.conf',    // SIP_TRUNK_CREDENTIALS_DRIFT (high)
      'coturn.conf',       // JITSI_WEBRTC_DRIFT (medium)
      'voip-gateway.conf', // VOIP_GATEWAY_DRIFT (medium)
      'synapse.yaml',      // WEBCONFERENCE_SECURITY_DRIFT (medium)
      'homer.cfg',         // VOIP_CDR_MONITORING_DRIFT (low)
    ]
    const r = scanVoipSecurityDrift(files)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
    // min(4*15, 45) + min(3*8, 25) + min(1*4, 15) = 45 + 24 + 4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
  })
})

// ---------------------------------------------------------------------------
// Deduplication and matchCount
// ---------------------------------------------------------------------------

describe('deduplication and matchCount', () => {
  it('multiple Asterisk files produce 1 finding with correct matchCount', () => {
    const files = ['sip.conf', 'pjsip.conf', 'extensions.conf', 'asterisk/manager.conf']
    const r = scanVoipSecurityDrift(files)
    const f = r.findings.find((x) => x.ruleId === 'ASTERISK_PBX_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(4)
    expect(r.findings.filter((x) => x.ruleId === 'ASTERISK_PBX_DRIFT')).toHaveLength(1)
  })

  it('matchedPath is the first matched file', () => {
    const files = ['pjsip.conf', 'sip.conf', 'extensions.conf']
    const r = scanVoipSecurityDrift(files)
    const f = r.findings.find((x) => x.ruleId === 'ASTERISK_PBX_DRIFT')
    expect(f!.matchedPath).toBe('pjsip.conf')
  })

  it('multiple CDR files produce 1 finding with correct matchCount', () => {
    const files = ['homer.cfg', 'homer.conf', 'homer.yaml', 'homer/capture.yaml']
    const r = scanVoipSecurityDrift(files)
    const f = r.findings.find((x) => x.ruleId === 'VOIP_CDR_MONITORING_DRIFT')
    expect(f!.matchCount).toBe(4)
  })

  it('each rule fires independently even with same directory', () => {
    const files = ['sip.conf', 'kamailio.cfg']
    const r = scanVoipSecurityDrift(files)
    expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'KAMAILIO_OPENSIPS_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('vendor path exclusion', () => {
  it.each([
    'node_modules/asterisk/sip.conf',
    'vendor/kamailio.cfg',
    '.git/freeswitch.xml',
    'dist/sip-trunk.conf',
    'build/coturn.conf',
    '.cache/voip-gateway.conf',
  ])('excludes %s', (file) => {
    const r = scanVoipSecurityDrift([file])
    expect(r.totalFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('path normalisation', () => {
  it('normalises backslashes', () => {
    const r = scanVoipSecurityDrift(['asterisk\\sip.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
  })

  it('strips leading ./ prefix', () => {
    const r = scanVoipSecurityDrift(['./sip.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ASTERISK_PBX_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Finding shape
// ---------------------------------------------------------------------------

describe('finding shape', () => {
  it('finding has all required fields', () => {
    const r = scanVoipSecurityDrift(['sip.conf'])
    const f = r.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
    expect(f.severity).toBe('high')
    expect(f.ruleId).toBe('ASTERISK_PBX_DRIFT')
  })
})
