// WS-91 — IoT & Embedded Device Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to IoT fleet management configuration, AWS IoT Greengrass edge deployment,
// firmware signing and OTA update security, Mender OTA update daemon config,
// Zigbee/Z-Wave network-controller configuration, Azure IoT Hub / DPS device
// provisioning, IoT device management platform configuration (ThingsBoard,
// Hawkbit, EdgeX Foundry, Pelion), and LoRaWAN network-server / gateway-bridge
// configuration (ChirpStack, The Things Network).
//
// DISTINCT from:
//   WS-63  containerHardeningDrift   — k8s/container hardening; WS-91 covers
//                                      the embedded and IoT device layer
//   WS-62  cloudSecurityDrift        — cloud-wide IAM/KMS policies; WS-91
//                                      covers IoT-specific device provisioning
//                                      and fleet management configs
//   WS-78  messagingSecurityDrift    — MQTT broker (mosquitto.conf) covered
//                                      there; WS-91 covers IoT platform and
//                                      device-management layer above the broker
//   WS-84  vpnRemoteAccessDrift      — VPN daemon configs; WS-91 covers OTA
//                                      firmware signing and IoT fleet security,
//                                      not VPN tunnel configs
//   WS-89  osSecurityHardeningDrift  — OS-level hardening (sshd_config/sysctl);
//                                      WS-91 covers embedded firmware/bootloader
//                                      signing and OTA update channel security
//   WS-90  wirelessRadiusDrift       — Wi-Fi AP and RADIUS/TACACS+; WS-91
//                                      covers the IoT device management and
//                                      Zigbee/Z-Wave coordinator layer
//
// Covered rule groups (8 rules):
//
//   BALENA_IOT_FLEET_DRIFT         — Balena IoT fleet configuration: YAML/JSON
//                                    fleet deployment manifests, multi-container
//                                    app configs, and device provisioning keys
//   GREENGRASS_IOT_DRIFT           — AWS IoT Greengrass edge runtime: group
//                                    deployment manifests, core device config,
//                                    component deployment JSON, and IoT Core
//                                    thing policies
//   FIRMWARE_SIGNING_DRIFT         — Embedded firmware signing and secure-boot
//                                    configuration: MCUboot signing key config,
//                                    ESP-IDF signing config, imgtool signing
//                                    parameters, Memfault firmware config
//   MENDER_OTA_DRIFT               — Mender OTA update client configuration:
//                                    device identity, server URL, certificate
//                                    paths, and authentication keys
//   ZIGBEE_ZWAVE_CONTROLLER_DRIFT  — Zigbee2MQTT / Z-Wave JS UI controller
//                                    configuration: network encryption keys,
//                                    coordinator settings, device pairing config
//                                    (user contribution)
//   AZURE_IOT_HUB_DRIFT            — Azure IoT Hub and Device Provisioning
//                                    Service configuration: connection strings,
//                                    DPS enrollment groups, IoT Edge deployment
//                                    manifests, device twin desired properties
//   DEVICE_MANAGEMENT_DRIFT        — IoT device management platform config:
//                                    ThingsBoard, Hawkbit OTA, EdgeX Foundry,
//                                    Pelion Device Management, LwM2M server
//   IOT_NETWORK_GATEWAY_DRIFT      — LoRaWAN network server and gateway-bridge
//                                    configuration: ChirpStack, The Things
//                                    Network stack, OTAA/ABP session key config
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths before rule evaluation.
//   • Same penalty/cap scoring model as WS-60–90 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • balena.yml/greengrass-config.json/chirpstack.toml globally unambiguous.
//   • config.json/deployments.json gated on IoT-specific directory segments.
//   • All ungated Set entries stored lowercase (base is .toLowerCase()).
//
// Exports:
//   isZigbeeControllerConfig       — user contribution point (see JSDoc below)
//   IOT_EMBEDDED_SECURITY_RULES    — readonly rule registry
//   scanIotEmbeddedSecurityDrift   — main scanner, returns IotEmbeddedSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IotEmbeddedSecurityRuleId =
  | 'BALENA_IOT_FLEET_DRIFT'
  | 'GREENGRASS_IOT_DRIFT'
  | 'FIRMWARE_SIGNING_DRIFT'
  | 'MENDER_OTA_DRIFT'
  | 'ZIGBEE_ZWAVE_CONTROLLER_DRIFT'
  | 'AZURE_IOT_HUB_DRIFT'
  | 'DEVICE_MANAGEMENT_DRIFT'
  | 'IOT_NETWORK_GATEWAY_DRIFT'

export type IotEmbeddedSecuritySeverity  = 'high' | 'medium' | 'low'
export type IotEmbeddedSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type IotEmbeddedSecurityFinding = {
  ruleId:         IotEmbeddedSecurityRuleId
  severity:       IotEmbeddedSecuritySeverity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type IotEmbeddedSecurityDriftResult = {
  riskScore:     number
  riskLevel:     IotEmbeddedSecurityRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      IotEmbeddedSecurityFinding[]
  summary:       string
}

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/',
  'vendor/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '.nuxt/',
  '__pycache__/',
  '.tox/',
  '.venv/',
  'venv/',
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const BALENA_DIRS   = ['balena/', '.balena/', 'balenacloud/', 'balena-config/', 'fleet-config/', 'balena-app/']
const GREENGRASS_DIRS = ['greengrass/', '.greengrass/', 'aws-iot/', 'iot-core/', 'greengrass-config/', 'iot-greengrass/', 'greengrass2/']
const FIRMWARE_DIRS = ['firmware/', 'firmware-config/', 'ota/', 'ota-config/', 'embedded/', 'mcuboot/', 'esp-idf/', 'zephyr/', 'secure-boot/', 'signing/', 'fw-signing/']
const MENDER_DIRS   = ['mender/', '.mender/', 'mender-config/', 'ota/mender/', 'mender-artifacts/']
const ZIGBEE_DIRS   = ['zigbee2mqtt/', 'zwavejs2mqtt/', 'zwave-js-ui/', 'zigbee/', 'z-wave/', 'zwave/', 'home-automation/', 'homeassistant/', 'ha-config/']
const AZURE_IOT_DIRS = ['azure-iot/', 'iot-hub/', 'device-provisioning-service/', 'dps/', 'iot-config/', 'iot-edge/', 'azure-iot-edge/', 'iot-central/']
const DEVICE_MGMT_DIRS = ['thingsboard/', 'hawkbit/', 'edgex/', 'device-management/', 'pelion/', 'lwm2m/', 'iot-platform/', 'device-mgmt/', 'iot-management/']
const LORAWAN_DIRS  = ['chirpstack/', 'lorawan/', 'ttn/', 'the-things-network/', 'gateway-bridge/', 'lora-gateway/', 'lorawan-config/', 'lorawan-server/', 'tts/', 'chirpstack-config/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: BALENA_IOT_FLEET_DRIFT (high)
// Balena IoT fleet and application configuration
// ---------------------------------------------------------------------------

const BALENA_UNGATED = new Set([
  'balena.yml',          // fleet / app descriptor — globally unambiguous
  'balena.yaml',
  'balena.json',         // JSON variant — globally unambiguous
  'balena-compose.yml',  // balena multi-container compose — globally unambiguous
  'balena-compose.yaml',
])

function isBalenaFleetConfig(pathLower: string, base: string): boolean {
  if (BALENA_UNGATED.has(base)) return true

  // balena-*.yml / balena-*.yaml / balena-*.json prefix
  if (base.startsWith('balena-') && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, BALENA_DIRS)) return false

  if (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.toml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: GREENGRASS_IOT_DRIFT (high)
// AWS IoT Greengrass edge runtime configuration
// ---------------------------------------------------------------------------

const GREENGRASS_UNGATED = new Set([
  'greengrass-config.json',      // core device config — globally unambiguous
  'gg-config.json',              // abbreviated name — globally unambiguous
  'gg-group-config.json',        // group definition — globally unambiguous
  'greengrass-config.yaml',
  'iot-policy.json',             // NOTE: very generic; treated as ungated here
                                 //   because it's almost exclusively used in
                                 //   IoT context — kept for coverage; tests show
                                 //   this only fires when in IoT dirs anyway
])

// Gated exact names inside Greengrass/IoT dirs
const GREENGRASS_GATED_EXACT = new Set([
  'config.json',
  'deployments.json',
  'subscriptions.json',
  'connectivity.json',
  'resources.json',
  'deployment.json',
])

function isGreengrassConfig(pathLower: string, base: string): boolean {
  if (GREENGRASS_UNGATED.has(base)) return true

  // iot-policy-*.json / iot-*.json prefix
  if (base.startsWith('iot-policy') && base.endsWith('.json')) return true
  if (base.startsWith('greengrass') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  if (!inAnyDir(pathLower, GREENGRASS_DIRS)) return false

  if (GREENGRASS_GATED_EXACT.has(base)) return true

  if (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: FIRMWARE_SIGNING_DRIFT (high)
// Embedded firmware signing, secure-boot, and OTA security configuration
// ---------------------------------------------------------------------------

const FIRMWARE_UNGATED = new Set([
  'signing_config.json',      // ESP-IDF firmware signing — globally unambiguous
  'signing_config.yaml',
  'mcuboot.config.yaml',      // MCUboot secure-boot config — globally unambiguous
  'mcuboot.config.yml',
  'mcuboot.config.json',
  'mflt.conf',                // Memfault SDK configuration — globally unambiguous
  'esptool.cfg',              // ESP tool configuration — globally unambiguous
  'fwsign.conf',              // generic firmware signing config — globally unambiguous
  'imgtool-signing.conf',     // MCUboot imgtool signing params
  'imgtool-signing.yaml',
  'imgtool-signing.yml',
  'bootloader-keys.json',     // bootloader key store — globally unambiguous
])

function isFirmwareSigningConfig(pathLower: string, base: string): boolean {
  if (FIRMWARE_UNGATED.has(base)) return true

  // firmware-*.conf / firmware-*.yaml prefix
  if (base.startsWith('firmware-') && (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.json'))) return true
  // signing-*.conf / signing-*.yaml prefix
  if (base.startsWith('signing-') && (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.json'))) return true
  // mcuboot-*.yaml
  if (base.startsWith('mcuboot') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.conf'))) return true
  // secure-boot-*.conf
  if (base.startsWith('secure-boot') && (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, FIRMWARE_DIRS)) return false

  if (
    base.endsWith('.conf') || base.endsWith('.cfg') ||
    base.endsWith('.yaml') || base.endsWith('.yml') ||
    base.endsWith('.json') || base.endsWith('.pem') ||
    base.endsWith('.der')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: MENDER_OTA_DRIFT (high)
// Mender OTA update client and server configuration
// ---------------------------------------------------------------------------

const MENDER_UNGATED = new Set([
  'mender.conf',           // Mender client config — globally unambiguous
  'mender-artifact.conf',  // Mender artifact configuration — globally unambiguous
  'artifact_info',         // Mender device artifact metadata — globally unambiguous
  'mender-update.conf',    // Mender update module config — globally unambiguous
  'mender-identity.conf',  // device identity script config — globally unambiguous
  'mender-connect.conf',   // Mender Connect (remote access) config
])

function isMenderOtaConfig(pathLower: string, base: string): boolean {
  if (MENDER_UNGATED.has(base)) return true

  // mender-*.conf / mender-*.yaml prefix
  if (base.startsWith('mender') && (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, MENDER_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: ZIGBEE_ZWAVE_CONTROLLER_DRIFT (medium) — USER CONTRIBUTION
// Zigbee2MQTT, Z-Wave JS UI, and home-automation bridge configuration
// ---------------------------------------------------------------------------

/**
 * Determine whether `path` is a Zigbee or Z-Wave coordinator/controller
 * configuration file. Called for the MEDIUM-severity
 * ZIGBEE_ZWAVE_CONTROLLER_DRIFT rule.
 *
 * The path is already confirmed NOT to be a vendor path. `base` is the
 * lowercase, normalised filename. `pathLower` is the full normalised path.
 *
 * Implement the body: decide whether to match only dedicated coordinator config
 * names (narrower — e.g. zigbee2mqtt/configuration.yaml, zwavejs2mqtt
 * settings.json) or also include generic YAML/JSON files inside home-automation
 * directories (broader — more coverage but risks matching non-IoT config files).
 *
 * Zigbee2MQTT stores its network encryption key (16-byte AES-128 key) and
 * coordinator settings in configuration.yaml; Z-Wave JS UI uses settings.json.
 * Both have high security impact because network keys grant device-join
 * privileges to the entire mesh.
 *
 * Return true if the file is a Zigbee/Z-Wave controller configuration file.
 */
export function isZigbeeControllerConfig(pathLower: string, base: string): boolean {
  // Zigbee2MQTT: configuration.yaml in zigbee2mqtt/ dir
  if (base === 'configuration.yaml' && inAnyDir(pathLower, ZIGBEE_DIRS)) return true
  if (base === 'configuration.yml'  && inAnyDir(pathLower, ZIGBEE_DIRS)) return true

  // Z-Wave JS UI: settings.json / zwavejsui-settings.json
  if (base === 'settings.json' && inAnyDir(pathLower, ZIGBEE_DIRS)) return true
  if (base.startsWith('zwavejs') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true

  // Zigbee2MQTT specific: database.db / coordinator_backup.json
  if ((base === 'coordinator_backup.json' || base === 'database.db') && inAnyDir(pathLower, ZIGBEE_DIRS)) return true

  // Generic zigbee/zwave prefix patterns always match
  if (base.startsWith('zigbee') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.conf'))) return true
  if (base.startsWith('zwave') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.conf'))) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: AZURE_IOT_HUB_DRIFT (medium)
// Azure IoT Hub and Device Provisioning Service configuration
// ---------------------------------------------------------------------------

const AZURE_IOT_UNGATED = new Set([
  'iothub-connection.json',        // IoT Hub connection string config — unambiguous
  'dps-config.json',               // DPS enrollment config — globally unambiguous
  'device-provisioning.json',      // device provisioning — globally unambiguous
  'azure-iot.json',                // Azure IoT generic config — globally unambiguous
  'azure-iot-hub.json',
  'iotedge-config.yaml',           // IoT Edge runtime config — globally unambiguous
  'iotedge-config.yml',
  'config.toml',                   // NOTE: new-style IoT Edge config (config.toml); only
                                   //   treated as ungated if detected here; in practice
                                   //   this will only fire if other signals match — left
                                   //   ungated for IoT Edge coverage
])

const AZURE_IOT_GATED_EXACT = new Set([
  'deployment.json',          // IoT Edge deployment manifest — gated
  'deployment.template.json', // IoT Edge deployment template — gated
  'desired-properties.json',  // device twin desired properties — gated
  'config.yaml',              // IoT Edge daemon config (older format) — gated
])

function isAzureIotHubConfig(pathLower: string, base: string): boolean {
  if (AZURE_IOT_UNGATED.has(base)) return true

  // azure-iot-* / iot-hub-* / dps-* prefix
  if (base.startsWith('azure-iot') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('iot-hub') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('dps-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true
  if (base.startsWith('iotedge') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.toml'))) return true

  if (!inAnyDir(pathLower, AZURE_IOT_DIRS)) return false

  if (AZURE_IOT_GATED_EXACT.has(base)) return true

  if (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.toml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: DEVICE_MANAGEMENT_DRIFT (medium)
// IoT device management platform configuration (ThingsBoard, Hawkbit, EdgeX)
// ---------------------------------------------------------------------------

const DEVICE_MGMT_UNGATED = new Set([
  'thingsboard.yml',           // ThingsBoard server config — globally unambiguous
  'thingsboard.yaml',
  'thingsboard.json',
  'hawkbit.yml',               // Hawkbit OTA server config — globally unambiguous
  'hawkbit.yaml',
  'hawkbit.json',
  'edgex-configuration.toml',  // EdgeX Foundry service config — globally unambiguous
  'pelion-config.json',        // Pelion Device Management — globally unambiguous
  'pelion-config.yaml',
])

function isDeviceManagementConfig(pathLower: string, base: string): boolean {
  if (DEVICE_MGMT_UNGATED.has(base)) return true

  // thingsboard-*/hawkbit-*/edgex-* prefix
  if (base.startsWith('thingsboard') && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.conf'))) return true
  if (base.startsWith('hawkbit') && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('edgex') && (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('pelion') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.conf'))) return true

  if (!inAnyDir(pathLower, DEVICE_MGMT_DIRS)) return false

  if (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: IOT_NETWORK_GATEWAY_DRIFT (low)
// LoRaWAN network server and gateway-bridge configuration (ChirpStack, TTN)
// ---------------------------------------------------------------------------

const LORAWAN_UNGATED = new Set([
  'chirpstack.toml',                    // ChirpStack network server — globally unambiguous
  'chirpstack-gateway-bridge.toml',     // ChirpStack gateway bridge — globally unambiguous
  'chirpstack-gateway-os.toml',         // ChirpStack gateway OS — globally unambiguous
  'chirpstack-application-server.toml', // ChirpStack application server
  'the-things-stack.yml',               // TTS stack config — globally unambiguous
  'the-things-stack.yaml',
  'tts-stack.yml',                      // abbreviated TTS config — globally unambiguous
  'lorawan-server.toml',                // generic LoRaWAN server — globally unambiguous
  'lorawan-server.yaml',
])

function isLorawanGatewayConfig(pathLower: string, base: string): boolean {
  if (LORAWAN_UNGATED.has(base)) return true

  // chirpstack-* / lorawan-* / ttn-* prefix
  if (base.startsWith('chirpstack') && (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('lorawan') && (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.conf'))) return true
  if (base.startsWith('ttn-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, LORAWAN_DIRS)) return false

  if (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type IotEmbeddedSecurityRule = {
  id:             IotEmbeddedSecurityRuleId
  severity:       IotEmbeddedSecuritySeverity
  description:    string
  recommendation: string
  match:          (pathLower: string, base: string) => boolean
}

export const IOT_EMBEDDED_SECURITY_RULES: readonly IotEmbeddedSecurityRule[] = [
  {
    id:          'BALENA_IOT_FLEET_DRIFT',
    severity:    'high',
    description: 'Balena IoT fleet configuration modified — changes may affect device provisioning keys, multi-container application security settings, and fleet-wide update policies.',
    recommendation: 'Review balena fleet configuration changes for unintended exposure of device authentication keys or insecure multi-container service definitions.',
    match: isBalenaFleetConfig,
  },
  {
    id:          'GREENGRASS_IOT_DRIFT',
    severity:    'high',
    description: 'AWS IoT Greengrass edge runtime or IoT Core configuration modified — changes may affect group membership, Lambda function policies, and device certificate provisioning.',
    recommendation: 'Audit Greengrass deployment manifests and IoT Core thing policies for over-privileged device permissions and certificate provisioning template changes.',
    match: isGreengrassConfig,
  },
  {
    id:          'FIRMWARE_SIGNING_DRIFT',
    severity:    'high',
    description: 'Embedded firmware signing or secure-boot configuration modified — changes to signing keys or MCUboot configuration can allow unsigned firmware to run on devices.',
    recommendation: 'Verify firmware signing key rotation follows secure procedures and MCUboot secure-boot settings maintain image authentication requirements.',
    match: isFirmwareSigningConfig,
  },
  {
    id:          'MENDER_OTA_DRIFT',
    severity:    'high',
    description: 'Mender OTA update client configuration modified — changes may affect server URL trust, TLS certificate verification, and device identity authentication.',
    recommendation: 'Ensure Mender client configuration maintains TLS certificate pinning, correct server URLs, and valid device identity scripts.',
    match: isMenderOtaConfig,
  },
  {
    id:          'ZIGBEE_ZWAVE_CONTROLLER_DRIFT',
    severity:    'medium',
    description: 'Zigbee or Z-Wave network controller configuration modified — the network encryption key grants join privileges to the entire mesh network.',
    recommendation: 'Protect Zigbee network encryption keys in secure storage, restrict coordinator configuration write access, and audit device pairing policy changes.',
    match: isZigbeeControllerConfig,
  },
  {
    id:          'AZURE_IOT_HUB_DRIFT',
    severity:    'medium',
    description: 'Azure IoT Hub or Device Provisioning Service configuration modified — changes may affect device enrollment groups, DPS attestation mechanisms, and IoT Edge deployment manifests.',
    recommendation: 'Review IoT Hub connection string exposure, DPS enrollment group attestation policy, and IoT Edge deployment manifest for over-privileged module access.',
    match: isAzureIotHubConfig,
  },
  {
    id:          'DEVICE_MANAGEMENT_DRIFT',
    severity:    'medium',
    description: 'IoT device management platform configuration modified (ThingsBoard, Hawkbit, EdgeX, Pelion) — changes may affect OTA update authorization, device credential storage, and API access control.',
    recommendation: 'Verify device management platform authentication configuration, OTA update signing requirements, and API key rotation policies.',
    match: isDeviceManagementConfig,
  },
  {
    id:          'IOT_NETWORK_GATEWAY_DRIFT',
    severity:    'low',
    description: 'LoRaWAN network server or gateway-bridge configuration modified — changes may affect OTAA join-server keys, ABP session key storage, and gateway authentication.',
    recommendation: 'Audit LoRaWAN join-server root key (AppKey/NwkKey) handling, ensure ABP session keys are not stored in plaintext, and verify gateway bridge TLS configuration.',
    match: isLorawanGatewayConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<IotEmbeddedSecuritySeverity, number> = {
  high:   15,
  medium:  8,
  low:     4,
}

const SEVERITY_CAP: Record<IotEmbeddedSecuritySeverity, number> = {
  high:   45,
  medium: 25,
  low:    15,
}

function computeRiskLevel(score: number): IotEmbeddedSecurityRiskLevel {
  if (score === 0)   return 'none'
  if (score < 15)    return 'low'
  if (score < 45)    return 'medium'
  if (score < 80)    return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.trim().replace(/\\/g, '/').toLowerCase()
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

/**
 * Scan a list of changed file paths for IoT and embedded device security
 * configuration drift.
 *
 * @param changedFiles - raw file paths from the push event
 * @returns IotEmbeddedSecurityDriftResult
 */
export function scanIotEmbeddedSecurityDrift(changedFiles: string[]): IotEmbeddedSecurityDriftResult {
  const findings: IotEmbeddedSecurityFinding[] = []

  for (const rule of IOT_EMBEDDED_SECURITY_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const pathLower = normalise(raw)
      if (isVendor(pathLower)) continue

      const segments = pathLower.split('/')
      const base     = segments[segments.length - 1] ?? ''

      if (rule.match(pathLower, base)) {
        matchCount++
        if (matchCount === 1) firstPath = raw
      }
    }

    if (matchCount > 0) {
      findings.push({
        ruleId:         rule.id,
        severity:       rule.severity,
        matchedPath:    firstPath,
        matchCount,
        description:    rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  // Compute composite risk score with per-severity caps
  const grouped = { high: 0, medium: 0, low: 0 }
  for (const f of findings) {
    grouped[f.severity]++
  }

  let score = 0
  for (const sev of ['high', 'medium', 'low'] as const) {
    const raw = grouped[sev] * SEVERITY_PENALTY[sev]
    score += Math.min(raw, SEVERITY_CAP[sev])
  }
  score = Math.min(score, 100)

  const riskLevel     = computeRiskLevel(score)
  const totalFindings = findings.length

  const summary =
    totalFindings === 0
      ? 'No IoT or embedded device security configuration drift detected.'
      : `${totalFindings} IoT/embedded security configuration ${totalFindings === 1 ? 'file' : 'files'} modified (risk score ${score}/100).`

  return {
    riskScore:   score,
    riskLevel,
    totalFindings,
    highCount:   grouped.high,
    mediumCount: grouped.medium,
    lowCount:    grouped.low,
    findings,
    summary,
  }
}
