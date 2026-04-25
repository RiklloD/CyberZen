// WS-91 — IoT & Embedded Device Security Configuration Drift Detector: tests.

import { describe, expect, it } from 'vitest'
import {
  isZigbeeControllerConfig,
  scanIotEmbeddedSecurityDrift,
} from './iotEmbeddedSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: BALENA_IOT_FLEET_DRIFT (high)
// ---------------------------------------------------------------------------

describe('BALENA_IOT_FLEET_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'BALENA_IOT_FLEET_DRIFT')

  it('matches balena.yml ungated', () => {
    expect(trigger(['balena.yml'])).toBeDefined()
  })
  it('matches balena.yaml ungated', () => {
    expect(trigger(['balena.yaml'])).toBeDefined()
  })
  it('matches balena.json ungated', () => {
    expect(trigger(['balena.json'])).toBeDefined()
  })
  it('matches balena-compose.yml ungated', () => {
    expect(trigger(['balena-compose.yml'])).toBeDefined()
  })
  it('matches balena-compose.yaml ungated', () => {
    expect(trigger(['balena-compose.yaml'])).toBeDefined()
  })
  it('matches balena-*.yml prefix', () => {
    expect(trigger(['balena-fleet.yml'])).toBeDefined()
  })
  it('matches balena-*.json prefix', () => {
    expect(trigger(['balena-app-config.json'])).toBeDefined()
  })
  it('matches any yml in balena/ dir', () => {
    expect(trigger(['balena/app.yml'])).toBeDefined()
  })
  it('matches any json in .balena/ dir', () => {
    expect(trigger(['.balena/balena.json'])).toBeDefined()
  })
  it('matches yaml in balenacloud/ dir', () => {
    expect(trigger(['balenacloud/fleet.yaml'])).toBeDefined()
  })
  it('does not match docker-compose.yml outside balena dirs', () => {
    expect(trigger(['docker-compose.yml'])).toBeUndefined()
  })
  it('does not match random app.yml outside balena dirs', () => {
    expect(trigger(['src/app.yml'])).toBeUndefined()
  })
  it('skips node_modules', () => {
    expect(trigger(['node_modules/balena/balena.yml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 2: GREENGRASS_IOT_DRIFT (high)
// ---------------------------------------------------------------------------

describe('GREENGRASS_IOT_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'GREENGRASS_IOT_DRIFT')

  it('matches greengrass-config.json ungated', () => {
    expect(trigger(['greengrass-config.json'])).toBeDefined()
  })
  it('matches gg-config.json ungated', () => {
    expect(trigger(['gg-config.json'])).toBeDefined()
  })
  it('matches gg-group-config.json ungated', () => {
    expect(trigger(['gg-group-config.json'])).toBeDefined()
  })
  it('matches greengrass-config.yaml ungated', () => {
    expect(trigger(['greengrass-config.yaml'])).toBeDefined()
  })
  it('matches iot-policy.json ungated', () => {
    expect(trigger(['iot-policy.json'])).toBeDefined()
  })
  it('matches iot-policy-*.json prefix', () => {
    expect(trigger(['iot-policy-devices.json'])).toBeDefined()
  })
  it('matches greengrass*.json prefix', () => {
    expect(trigger(['greengrass-edge.json'])).toBeDefined()
  })
  it('matches config.json in greengrass/ dir', () => {
    expect(trigger(['greengrass/config.json'])).toBeDefined()
  })
  it('matches deployments.json in aws-iot/ dir', () => {
    expect(trigger(['aws-iot/deployments.json'])).toBeDefined()
  })
  it('matches subscriptions.json in iot-greengrass/ dir', () => {
    expect(trigger(['iot-greengrass/subscriptions.json'])).toBeDefined()
  })
  it('matches any yaml in greengrass-config/ dir', () => {
    expect(trigger(['greengrass-config/thing-policy.yaml'])).toBeDefined()
  })
  it('does not match random config.json outside IoT dirs', () => {
    expect(trigger(['src/config.json'])).toBeUndefined()
  })
  it('skips vendor/', () => {
    expect(trigger(['vendor/greengrass/config.json'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 3: FIRMWARE_SIGNING_DRIFT (high)
// ---------------------------------------------------------------------------

describe('FIRMWARE_SIGNING_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'FIRMWARE_SIGNING_DRIFT')

  it('matches signing_config.json ungated', () => {
    expect(trigger(['signing_config.json'])).toBeDefined()
  })
  it('matches signing_config.yaml ungated', () => {
    expect(trigger(['signing_config.yaml'])).toBeDefined()
  })
  it('matches mcuboot.config.yaml ungated', () => {
    expect(trigger(['mcuboot.config.yaml'])).toBeDefined()
  })
  it('matches mcuboot.config.yml ungated', () => {
    expect(trigger(['mcuboot.config.yml'])).toBeDefined()
  })
  it('matches mcuboot.config.json ungated', () => {
    expect(trigger(['mcuboot.config.json'])).toBeDefined()
  })
  it('matches mflt.conf ungated', () => {
    expect(trigger(['mflt.conf'])).toBeDefined()
  })
  it('matches esptool.cfg ungated', () => {
    expect(trigger(['esptool.cfg'])).toBeDefined()
  })
  it('matches fwsign.conf ungated', () => {
    expect(trigger(['fwsign.conf'])).toBeDefined()
  })
  it('matches imgtool-signing.conf ungated', () => {
    expect(trigger(['imgtool-signing.conf'])).toBeDefined()
  })
  it('matches bootloader-keys.json ungated', () => {
    expect(trigger(['bootloader-keys.json'])).toBeDefined()
  })
  it('matches firmware-*.conf prefix', () => {
    expect(trigger(['firmware-sign.conf'])).toBeDefined()
  })
  it('matches signing-*.yaml prefix', () => {
    expect(trigger(['signing-keys.yaml'])).toBeDefined()
  })
  it('matches mcuboot*.yaml prefix', () => {
    expect(trigger(['mcuboot-build.yaml'])).toBeDefined()
  })
  it('matches secure-boot*.conf prefix', () => {
    expect(trigger(['secure-boot-config.conf'])).toBeDefined()
  })
  it('matches .conf in firmware/ dir', () => {
    expect(trigger(['firmware/keys.conf'])).toBeDefined()
  })
  it('matches .json in ota-config/ dir', () => {
    expect(trigger(['ota-config/signing.json'])).toBeDefined()
  })
  it('matches .pem in mcuboot/ dir', () => {
    expect(trigger(['mcuboot/root-rsa-2048.pem'])).toBeDefined()
  })
  it('does not match random config.yaml outside firmware dirs', () => {
    expect(trigger(['config.yaml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 4: MENDER_OTA_DRIFT (high)
// ---------------------------------------------------------------------------

describe('MENDER_OTA_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'MENDER_OTA_DRIFT')

  it('matches mender.conf ungated', () => {
    expect(trigger(['mender.conf'])).toBeDefined()
  })
  it('matches mender-artifact.conf ungated', () => {
    expect(trigger(['mender-artifact.conf'])).toBeDefined()
  })
  it('matches artifact_info ungated', () => {
    expect(trigger(['artifact_info'])).toBeDefined()
  })
  it('matches mender-update.conf ungated', () => {
    expect(trigger(['mender-update.conf'])).toBeDefined()
  })
  it('matches mender-identity.conf ungated', () => {
    expect(trigger(['mender-identity.conf'])).toBeDefined()
  })
  it('matches mender-connect.conf ungated', () => {
    expect(trigger(['mender-connect.conf'])).toBeDefined()
  })
  it('matches mender-*.yaml prefix', () => {
    expect(trigger(['mender-server.yaml'])).toBeDefined()
  })
  it('matches mender*.conf prefix', () => {
    expect(trigger(['menderconf.conf'])).toBeDefined()
  })
  it('matches yaml in mender/ dir', () => {
    expect(trigger(['mender/server.yaml'])).toBeDefined()
  })
  it('matches json in .mender/ dir', () => {
    expect(trigger(['.mender/auth.json'])).toBeDefined()
  })
  it('does not match artifact.json outside mender dirs', () => {
    expect(trigger(['artifact.json'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 5: ZIGBEE_ZWAVE_CONTROLLER_DRIFT (medium) — user contribution
// ---------------------------------------------------------------------------

describe('isZigbeeControllerConfig (user contribution)', () => {
  it('matches configuration.yaml in zigbee2mqtt/ dir', () => {
    expect(isZigbeeControllerConfig('zigbee2mqtt/configuration.yaml', 'configuration.yaml')).toBe(true)
  })
  it('matches configuration.yml in zigbee2mqtt/ dir', () => {
    expect(isZigbeeControllerConfig('zigbee2mqtt/configuration.yml', 'configuration.yml')).toBe(true)
  })
  it('matches settings.json in zwavejs2mqtt/ dir', () => {
    expect(isZigbeeControllerConfig('zwavejs2mqtt/settings.json', 'settings.json')).toBe(true)
  })
  it('matches settings.json in zwave-js-ui/ dir', () => {
    expect(isZigbeeControllerConfig('zwave-js-ui/settings.json', 'settings.json')).toBe(true)
  })
  it('matches zwavejs*.json prefix', () => {
    expect(isZigbeeControllerConfig('config/zwavejsui-config.json', 'zwavejsui-config.json')).toBe(true)
  })
  it('matches coordinator_backup.json in zigbee2mqtt/ dir', () => {
    expect(isZigbeeControllerConfig('zigbee2mqtt/coordinator_backup.json', 'coordinator_backup.json')).toBe(true)
  })
  it('matches zigbee-*.yaml prefix ungated', () => {
    expect(isZigbeeControllerConfig('config/zigbee-network.yaml', 'zigbee-network.yaml')).toBe(true)
  })
  it('matches zwave-*.conf prefix ungated', () => {
    expect(isZigbeeControllerConfig('config/zwave-config.conf', 'zwave-config.conf')).toBe(true)
  })
  it('does not match configuration.yaml outside zigbee dirs', () => {
    expect(isZigbeeControllerConfig('app/configuration.yaml', 'configuration.yaml')).toBe(false)
  })
  it('does not match settings.json outside zigbee dirs', () => {
    expect(isZigbeeControllerConfig('src/settings.json', 'settings.json')).toBe(false)
  })
})

describe('ZIGBEE_ZWAVE_CONTROLLER_DRIFT (scanner)', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'ZIGBEE_ZWAVE_CONTROLLER_DRIFT')

  it('fires for zigbee2mqtt configuration', () => {
    expect(trigger(['zigbee2mqtt/configuration.yaml'])).toBeDefined()
  })
  it('fires for zwave-js-ui settings', () => {
    expect(trigger(['zwave-js-ui/settings.json'])).toBeDefined()
  })
  it('fires for generic zigbee-*.yaml', () => {
    expect(trigger(['config/zigbee-settings.yaml'])).toBeDefined()
  })
  it('does not fire for random configuration.yaml', () => {
    expect(trigger(['src/app/configuration.yaml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 6: AZURE_IOT_HUB_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('AZURE_IOT_HUB_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'AZURE_IOT_HUB_DRIFT')

  it('matches iothub-connection.json ungated', () => {
    expect(trigger(['iothub-connection.json'])).toBeDefined()
  })
  it('matches dps-config.json ungated', () => {
    expect(trigger(['dps-config.json'])).toBeDefined()
  })
  it('matches device-provisioning.json ungated', () => {
    expect(trigger(['device-provisioning.json'])).toBeDefined()
  })
  it('matches azure-iot.json ungated', () => {
    expect(trigger(['azure-iot.json'])).toBeDefined()
  })
  it('matches iotedge-config.yaml ungated', () => {
    expect(trigger(['iotedge-config.yaml'])).toBeDefined()
  })
  it('matches azure-iot*.yaml prefix', () => {
    expect(trigger(['azure-iot-hub.yaml'])).toBeDefined()
  })
  it('matches iot-hub-*.json prefix', () => {
    expect(trigger(['iot-hub-config.json'])).toBeDefined()
  })
  it('matches dps-*.json prefix', () => {
    expect(trigger(['dps-enrollment.json'])).toBeDefined()
  })
  it('matches iotedge*.toml prefix', () => {
    expect(trigger(['iotedge.toml'])).toBeDefined()
  })
  it('matches deployment.json in azure-iot/ dir', () => {
    expect(trigger(['azure-iot/deployment.json'])).toBeDefined()
  })
  it('matches deployment.template.json in iot-edge/ dir', () => {
    expect(trigger(['iot-edge/deployment.template.json'])).toBeDefined()
  })
  it('matches config.yaml in iot-edge/ dir', () => {
    expect(trigger(['iot-edge/config.yaml'])).toBeDefined()
  })
  it('does not match random deployment.json outside IoT dirs', () => {
    expect(trigger(['k8s/deployment.json'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 7: DEVICE_MANAGEMENT_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('DEVICE_MANAGEMENT_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'DEVICE_MANAGEMENT_DRIFT')

  it('matches thingsboard.yml ungated', () => {
    expect(trigger(['thingsboard.yml'])).toBeDefined()
  })
  it('matches thingsboard.yaml ungated', () => {
    expect(trigger(['thingsboard.yaml'])).toBeDefined()
  })
  it('matches thingsboard.json ungated', () => {
    expect(trigger(['thingsboard.json'])).toBeDefined()
  })
  it('matches hawkbit.yml ungated', () => {
    expect(trigger(['hawkbit.yml'])).toBeDefined()
  })
  it('matches hawkbit.yaml ungated', () => {
    expect(trigger(['hawkbit.yaml'])).toBeDefined()
  })
  it('matches edgex-configuration.toml ungated', () => {
    expect(trigger(['edgex-configuration.toml'])).toBeDefined()
  })
  it('matches pelion-config.json ungated', () => {
    expect(trigger(['pelion-config.json'])).toBeDefined()
  })
  it('matches thingsboard-*.yml prefix', () => {
    expect(trigger(['thingsboard-edge.yml'])).toBeDefined()
  })
  it('matches hawkbit-*.yaml prefix', () => {
    expect(trigger(['hawkbit-server.yaml'])).toBeDefined()
  })
  it('matches edgex-*.toml prefix', () => {
    expect(trigger(['edgex-device-service.toml'])).toBeDefined()
  })
  it('matches pelion-*.json prefix', () => {
    expect(trigger(['pelion-credentials.json'])).toBeDefined()
  })
  it('matches yaml in thingsboard/ dir', () => {
    expect(trigger(['thingsboard/config.yaml'])).toBeDefined()
  })
  it('matches toml in edgex/ dir', () => {
    expect(trigger(['edgex/core-data.toml'])).toBeDefined()
  })
  it('matches json in device-management/ dir', () => {
    expect(trigger(['device-management/settings.json'])).toBeDefined()
  })
  it('does not match server.yml outside device mgmt dirs', () => {
    expect(trigger(['src/server.yml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 8: IOT_NETWORK_GATEWAY_DRIFT (low)
// ---------------------------------------------------------------------------

describe('IOT_NETWORK_GATEWAY_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanIotEmbeddedSecurityDrift(paths).findings.find((f) => f.ruleId === 'IOT_NETWORK_GATEWAY_DRIFT')

  it('matches chirpstack.toml ungated', () => {
    expect(trigger(['chirpstack.toml'])).toBeDefined()
  })
  it('matches chirpstack-gateway-bridge.toml ungated', () => {
    expect(trigger(['chirpstack-gateway-bridge.toml'])).toBeDefined()
  })
  it('matches chirpstack-gateway-os.toml ungated', () => {
    expect(trigger(['chirpstack-gateway-os.toml'])).toBeDefined()
  })
  it('matches chirpstack-application-server.toml ungated', () => {
    expect(trigger(['chirpstack-application-server.toml'])).toBeDefined()
  })
  it('matches the-things-stack.yml ungated', () => {
    expect(trigger(['the-things-stack.yml'])).toBeDefined()
  })
  it('matches the-things-stack.yaml ungated', () => {
    expect(trigger(['the-things-stack.yaml'])).toBeDefined()
  })
  it('matches tts-stack.yml ungated', () => {
    expect(trigger(['tts-stack.yml'])).toBeDefined()
  })
  it('matches lorawan-server.toml ungated', () => {
    expect(trigger(['lorawan-server.toml'])).toBeDefined()
  })
  it('matches chirpstack-*.toml prefix', () => {
    expect(trigger(['chirpstack-network-server.toml'])).toBeDefined()
  })
  it('matches lorawan-*.yaml prefix', () => {
    expect(trigger(['lorawan-config.yaml'])).toBeDefined()
  })
  it('matches ttn-*.yaml prefix', () => {
    expect(trigger(['ttn-stack.yaml'])).toBeDefined()
  })
  it('matches yaml in lorawan/ dir', () => {
    expect(trigger(['lorawan/server.yaml'])).toBeDefined()
  })
  it('matches toml in chirpstack/ dir', () => {
    expect(trigger(['chirpstack/chirpstack.toml'])).toBeDefined()
  })
  it('matches yaml in ttn/ dir', () => {
    expect(trigger(['ttn/config.yaml'])).toBeDefined()
  })
  it('does not match server.toml outside lorawan dirs', () => {
    expect(trigger(['server.toml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Scanner integration tests
// ---------------------------------------------------------------------------

describe('scanIotEmbeddedSecurityDrift integration', () => {
  it('returns clean result for empty path list', () => {
    const r = scanIotEmbeddedSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toContain('No IoT')
  })

  it('returns clean result for paths with no IoT config files', () => {
    const r = scanIotEmbeddedSecurityDrift(['src/index.ts', 'package.json', 'README.md'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('deduplicates — multiple balena.yml changes count as one finding with matchCount', () => {
    const r = scanIotEmbeddedSecurityDrift(['balena.yml', 'balena.yaml', 'balena.json'])
    const f = r.findings.find((x) => x.ruleId === 'BALENA_IOT_FLEET_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
    expect(r.findings.length).toBe(1)
  })

  it('scores a single HIGH finding at 15', () => {
    const r = scanIotEmbeddedSecurityDrift(['mender.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('scores a single MEDIUM finding at 8', () => {
    const r = scanIotEmbeddedSecurityDrift(['zigbee2mqtt/configuration.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('scores a single LOW finding at 4', () => {
    const r = scanIotEmbeddedSecurityDrift(['chirpstack.toml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('scores 2 HIGH findings at 30', () => {
    const r = scanIotEmbeddedSecurityDrift(['balena.yml', 'greengrass-config.json'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('scores 3 HIGH findings at 45 (high, not medium — 45 is not < 45)', () => {
    const r = scanIotEmbeddedSecurityDrift([
      'balena.yml',               // BALENA_IOT_FLEET_DRIFT
      'greengrass-config.json',   // GREENGRASS_IOT_DRIFT
      'signing_config.json',      // FIRMWARE_SIGNING_DRIFT
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('caps HIGH contributions at 45 even with 4 HIGH rules', () => {
    const r = scanIotEmbeddedSecurityDrift([
      'balena.yml',             // BALENA_IOT_FLEET_DRIFT
      'greengrass-config.json', // GREENGRASS_IOT_DRIFT
      'signing_config.json',    // FIRMWARE_SIGNING_DRIFT
      'mender.conf',            // MENDER_OTA_DRIFT
    ])
    expect(r.highCount).toBe(4)
    expect(r.riskScore).toBe(45) // capped at 45
    expect(r.riskLevel).toBe('high')
  })

  it('scores all 8 rules at 73 → high (4H capped + 3M×8 + 1L×4)', () => {
    const r = scanIotEmbeddedSecurityDrift([
      'balena.yml',                      // BALENA_IOT_FLEET_DRIFT (H)
      'greengrass-config.json',          // GREENGRASS_IOT_DRIFT (H)
      'signing_config.json',             // FIRMWARE_SIGNING_DRIFT (H)
      'mender.conf',                     // MENDER_OTA_DRIFT (H)
      'zigbee2mqtt/configuration.yaml',  // ZIGBEE_ZWAVE_CONTROLLER_DRIFT (M)
      'dps-config.json',                 // AZURE_IOT_HUB_DRIFT (M)
      'thingsboard.yml',                 // DEVICE_MANAGEMENT_DRIFT (M)
      'chirpstack.toml',                 // IOT_NETWORK_GATEWAY_DRIFT (L)
    ])
    // 4H × 15 = 60 → cap 45; 3M × 8 = 24 (cap is 25, not hit); 1L × 4 = 4
    // Total = 45 + 24 + 4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
  })

  it('skips vendor directory paths', () => {
    const r = scanIotEmbeddedSecurityDrift([
      'node_modules/balena/balena.yml',
      'vendor/greengrass/greengrass-config.json',
      '.git/signing_config.json',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskScore).toBe(0)
  })

  it('summary reports correct finding count', () => {
    const r = scanIotEmbeddedSecurityDrift(['balena.yml', 'mender.conf'])
    expect(r.summary).toContain('2 IoT/embedded')
    expect(r.summary).toContain('30/100')
  })

  it('summary uses singular for single finding', () => {
    const r = scanIotEmbeddedSecurityDrift(['chirpstack.toml'])
    expect(r.summary).toMatch(/1 IoT\/embedded security configuration file/)
  })

  it('matchedPath is the first triggered file', () => {
    const r = scanIotEmbeddedSecurityDrift(['balena/app.yml', 'balena.yml'])
    const f = r.findings.find((x) => x.ruleId === 'BALENA_IOT_FLEET_DRIFT')
    expect(f!.matchedPath).toBe('balena/app.yml')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundary tests
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scanIotEmbeddedSecurityDrift([]).riskLevel).toBe('none')
  })
  it('score 4 (1 LOW) → low', () => {
    expect(scanIotEmbeddedSecurityDrift(['chirpstack.toml']).riskLevel).toBe('low')
  })
  it('score 8 (1 MEDIUM) → low', () => {
    expect(scanIotEmbeddedSecurityDrift(['thingsboard.yml']).riskLevel).toBe('low')
  })
  it('score 15 (1 HIGH) → medium (15 is not < 15)', () => {
    expect(scanIotEmbeddedSecurityDrift(['balena.yml']).riskLevel).toBe('medium')
  })
  it('score 30 (2 HIGH) → medium', () => {
    const r = scanIotEmbeddedSecurityDrift(['balena.yml', 'mender.conf'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 45 (3 HIGH) → high (45 is not < 45)', () => {
    const r = scanIotEmbeddedSecurityDrift([
      'balena.yml',
      'greengrass-config.json',
      'signing_config.json',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })
  it('max score 73 (all 8 rules) → high (not critical)', () => {
    const r = scanIotEmbeddedSecurityDrift([
      'balena.yml',
      'greengrass-config.json',
      'signing_config.json',
      'mender.conf',
      'zigbee2mqtt/configuration.yaml',
      'dps-config.json',
      'thingsboard.yml',
      'chirpstack.toml',
    ])
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
  })
})
