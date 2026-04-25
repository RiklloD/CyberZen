// WS-78 — Messaging & Event Streaming Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to message broker and event streaming security configuration files. This
// scanner focuses on the *data transport layer* — configurations that govern
// authentication, authorisation, TLS/encryption, and access control for the
// messaging infrastructure that connects services.
//
// DISTINCT from:
//   WS-60  securityConfigDrift       — application-level JWT/CORS/session
//                                      configs inside backend service code
//   WS-62  cloudSecurityDrift        — cloud-wide IAM resource policies,
//                                      KMS keys; WS-78 covers per-broker
//                                      authentication and access control
//   WS-66  certPkiDrift              — certificate and PKI key material;
//                                      WS-78 covers broker TLS configuration
//                                      parameters (cipher suites, truststore
//                                      paths), not the certificates themselves
//   WS-70  identityAccessDrift       — identity provider and PAM configs;
//                                      WS-78 covers broker-level ACL/user files
//   WS-77  serverlessFaasDrift       — serverless function deployment configs;
//                                      WS-78 covers persistent broker processes
//
// Covered rule groups (8 rules):
//
//   KAFKA_SECURITY_DRIFT             — Apache Kafka broker, producer, consumer
//                                      and SASL/JAAS authentication configs
//   RABBITMQ_SECURITY_DRIFT          — RabbitMQ AMQP broker and definitions
//   NATS_SECURITY_DRIFT              — NATS.io server and operator configs
//   MQTT_BROKER_DRIFT                — Mosquitto and HiveMQ MQTT broker configs
//   STREAM_TLS_CONFIG_DRIFT          — TLS/SSL configuration for messaging
//                                      transports (cipher suites, cert paths)
//   MESSAGE_AUTH_POLICY_DRIFT        — broker-level ACL and authorisation files
//   SCHEMA_REGISTRY_DRIFT            — Confluent and Apicurio schema registry
//   PUBSUB_BROKER_DRIFT              — ActiveMQ, Apache Pulsar, and other
//                                      messaging systems
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–77 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • kafka-*.properties prefix is self-unambiguous (file names its own tool).
//   • rabbitmq.conf / nats-server.conf / mosquitto.conf are globally unambiguous.
//   • server.properties / consumer.properties are gated on KAFKA_DIRS because
//     these names are too generic to detect ungated.
//   • kafka-ssl.properties is dual-matched by KAFKA_SECURITY and STREAM_TLS
//     (intentional — it is both a Kafka config and a TLS config).
//   • isMessageAuthPolicyFile is the user contribution — see JSDoc below.
//
// Exports:
//   isMessageAuthPolicyFile   — user contribution point (see JSDoc below)
//   MESSAGING_SECURITY_RULES  — readonly rule registry
//   scanMessagingSecurityDrift — main scanner, returns MessagingSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MessagingSecurityRuleId =
  | 'KAFKA_SECURITY_DRIFT'
  | 'RABBITMQ_SECURITY_DRIFT'
  | 'NATS_SECURITY_DRIFT'
  | 'MQTT_BROKER_DRIFT'
  | 'STREAM_TLS_CONFIG_DRIFT'
  | 'MESSAGE_AUTH_POLICY_DRIFT'
  | 'SCHEMA_REGISTRY_DRIFT'
  | 'PUBSUB_BROKER_DRIFT'

export type MessagingSecuritySeverity = 'high' | 'medium' | 'low'
export type MessagingSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type MessagingSecurityDriftFinding = {
  ruleId: MessagingSecurityRuleId
  severity: MessagingSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type MessagingSecurityDriftResult = {
  riskScore: number
  riskLevel: MessagingSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: MessagingSecurityDriftFinding[]
  summary: string
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
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const KAFKA_DIRS    = ['kafka/', 'kafka-broker/', 'kafka/config/', 'config/kafka/']
const RABBITMQ_DIRS = ['rabbitmq/', 'rabbit/', 'rmq/', 'rabbitmq/config/']
const NATS_DIRS     = ['nats/', 'nats-server/', 'nats/config/']
const MOSQUITTO_DIRS = ['mosquitto/', 'mqtt/', 'mqtt-broker/']
const PULSAR_DIRS   = ['pulsar/', 'apache-pulsar/', 'pulsar/conf/']
const ACTIVEMQ_DIRS = ['activemq/', 'apache-activemq/', 'activemq/conf/']
const SCHEMA_REGISTRY_DIRS = ['schema-registry/', 'registry/', 'schema/']
const MESSAGING_DIRS = [
  'messaging/', 'message-broker/', 'mq/', 'event-streaming/',
  'broker/', 'amqp/', 'pubsub/', 'streaming/',
]

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: KAFKA_SECURITY_DRIFT (high)
// Apache Kafka broker and client security configuration
// ---------------------------------------------------------------------------

function isKafkaSecurityConfig(pathLower: string, base: string): boolean {
  // kafka-*.properties / kafka-*.conf prefix: file names its own tool — unambiguous
  if (base.startsWith('kafka-') && base.endsWith('.properties')) return true
  if (base.startsWith('kafka-') && base.endsWith('.conf')) return true

  // Everything below requires a kafka-specific directory
  if (!inAnyDir(pathLower, KAFKA_DIRS)) return false

  // Canonical Kafka broker and client property files
  if (
    base === 'server.properties' ||
    base === 'consumer.properties' ||
    base === 'producer.properties' ||
    base === 'kraft.properties' ||         // KRaft mode controller config
    base === 'controller.properties' ||    // KRaft controller
    base === 'zookeeper.properties' ||     // ZooKeeper connection config
    base === 'jaas.conf'                   // SASL/JAAS authentication
  ) return true

  // Any .properties file in kafka dirs (covers custom broker overrides)
  if (base.endsWith('.properties')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: RABBITMQ_SECURITY_DRIFT (high)
// RabbitMQ AMQP broker configuration files
// ---------------------------------------------------------------------------

const RABBITMQ_UNGATED = new Set([
  'rabbitmq.conf',      // Modern ini-style config (RabbitMQ 3.7+)
  'rabbitmq-env.conf',  // Environment variable overrides
  'rabbitmq.config',    // Legacy Erlang-term config
])

function isRabbitMqSecurityConfig(pathLower: string, base: string): boolean {
  if (RABBITMQ_UNGATED.has(base)) return true

  if (!inAnyDir(pathLower, RABBITMQ_DIRS)) return false

  // Runtime broker configuration and user/permission definitions
  if (
    base === 'advanced.config' ||    // Erlang advanced config
    base === 'definitions.json' ||   // Exported user/vhost/permission definitions
    base === 'definitions.yaml' ||   // YAML definitions (Management plugin)
    base === 'enabled_plugins'        // Plugin list (affects auth features)
  ) return true

  // Any .conf file in rabbitmq directories
  if (base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: NATS_SECURITY_DRIFT (high)
// NATS.io messaging server configuration
// ---------------------------------------------------------------------------

const NATS_UNGATED = new Set([
  'nats-server.conf', // Canonical NATS server config
  'nats.conf',        // Short-form variant
])

function isNatsSecurityConfig(pathLower: string, base: string): boolean {
  if (NATS_UNGATED.has(base)) return true

  // Stage/environment NATS configs: nats-cluster.conf, nats-routes.conf
  if (base.startsWith('nats-') && base.endsWith('.conf')) return true

  // NATS operator JWT and resolver configs
  if (!inAnyDir(pathLower, NATS_DIRS)) return false
  if (
    base === 'resolver.conf' ||  // NATS operator resolver (account JWTs)
    base.endsWith('.conf') ||
    base.endsWith('.creds') ||   // NATS credentials file
    base.endsWith('.jwt')        // NATS operator/account JWT
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: MQTT_BROKER_DRIFT (high)
// Mosquitto and HiveMQ MQTT broker configuration
// ---------------------------------------------------------------------------

const MQTT_UNGATED = new Set([
  'mosquitto.conf',   // Mosquitto MQTT broker config — globally unambiguous
  'mosquitto.passwd', // Mosquitto password file (htpasswd-style)
  'hivemq-config.xml', // HiveMQ enterprise broker config
])

function isMqttBrokerConfig(pathLower: string, base: string): boolean {
  if (MQTT_UNGATED.has(base)) return true

  if (!inAnyDir(pathLower, MOSQUITTO_DIRS)) return false

  // ACL file and any .conf inside mosquitto directories
  if (
    base === 'acl' ||              // Mosquitto ACL (no extension)
    base === 'acl.conf' ||
    base.endsWith('.conf') ||
    base.endsWith('.passwd')        // Additional password file variants
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: STREAM_TLS_CONFIG_DRIFT (medium)
// TLS/SSL configuration parameters for messaging transports
// ---------------------------------------------------------------------------

const STREAM_TLS_UNGATED = new Set([
  'kafka-ssl.properties',   // Kafka SSL configuration
  'kafka-tls.properties',   // Kafka TLS configuration (alt naming)
  'amqp-ssl.conf',          // AMQP SSL configuration
  'amqp-tls.conf',          // AMQP TLS configuration
])

function isStreamingTlsConfig(pathLower: string, base: string): boolean {
  if (STREAM_TLS_UNGATED.has(base)) return true

  // TLS/SSL named files within any messaging directory
  const ALL_MSG_DIRS = [
    ...KAFKA_DIRS, ...RABBITMQ_DIRS, ...NATS_DIRS,
    ...MOSQUITTO_DIRS, ...MESSAGING_DIRS,
  ]
  if (!inAnyDir(pathLower, ALL_MSG_DIRS)) return false

  if (base.includes('ssl') || base.includes('tls')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: MESSAGE_AUTH_POLICY_DRIFT (medium)  — USER CONTRIBUTION
//
// Detects changes to message broker authorisation and access control files.
// Misconfigured broker ACLs are a common cause of message queue compromise:
// a topic with no publish restriction lets any client inject malicious events;
// a wildcard subscription ACL leaks all messages to unintended consumers.
//
// User contribution: implement the detection logic for your broker auth/ACL
// file naming conventions.
//
// Considerations when implementing:
//   1. Ungated path (broker prefix + auth keyword in filename): files like
//      `kafka-acl.yaml` or `rabbitmq-auth.json` include the broker name, so
//      they are unambiguous without directory context.
//   2. Directory-gated path: generic auth files like `users.json` or
//      `authorization.yaml` must be inside a messaging directory to avoid
//      false positives from application-level RBAC configs.
//   3. Extension guard: restrict to structured config extensions (.conf,
//      .properties, .yaml, .yml, .json, .xml) — not source code.
//   4. Trade-off: a loose AUTH_KEYWORDS list catches more patterns but risks
//      false positives; a strict list (acl, auth, permission, credential)
//      reduces noise at the cost of missing non-standard naming conventions.
//
// Parameters:
//   pathLower — fully lowercased, forward-slash normalised path
//   base      — lowercased basename (filename without directory)
//
// Returns true if the file looks like a message broker authorisation or
// access control policy file.
// ---------------------------------------------------------------------------

export function isMessageAuthPolicyFile(pathLower: string, base: string): boolean {
  const BROKER_PREFIXES  = ['kafka-', 'rabbitmq-', 'nats-', 'mqtt-', 'amqp-', 'pulsar-']
  const AUTH_KEYWORDS    = [
    'acl', 'auth', 'access', 'permission', 'policy',
    'user', 'password', 'credential', 'principal', 'role',
  ]
  const CONFIG_EXTS = ['.conf', '.properties', '.yaml', '.yml', '.json', '.xml']

  // Ungated: filename includes both a broker prefix and an auth keyword
  if (
    BROKER_PREFIXES.some((p) => base.startsWith(p)) &&
    AUTH_KEYWORDS.some((kw) => base.includes(kw))
  ) return true

  // Directory-gated: file must be inside a messaging directory
  const ALL_MSG_DIRS = [
    ...KAFKA_DIRS, ...RABBITMQ_DIRS, ...NATS_DIRS,
    ...MOSQUITTO_DIRS, ...MESSAGING_DIRS, ...PULSAR_DIRS,
  ]
  if (!inAnyDir(pathLower, ALL_MSG_DIRS)) return false

  // Must be a structured config/data file (not source code)
  if (!CONFIG_EXTS.some((ext) => base.endsWith(ext))) return false

  // Filename must contain an auth/policy-related keyword
  return AUTH_KEYWORDS.some((kw) => base.includes(kw))
}

// ---------------------------------------------------------------------------
// Rule 7: SCHEMA_REGISTRY_DRIFT (medium)
// Confluent Schema Registry and Apicurio Registry configuration
// ---------------------------------------------------------------------------

const SCHEMA_REG_UNGATED = new Set([
  'schema-registry.properties',  // Confluent Schema Registry
  'schema-registry.yml',
  'schema-registry.yaml',
  'apicurio-registry.properties', // Red Hat Apicurio Registry
  'apicurio-registry.yml',
])

function isSchemaRegistryConfig(pathLower: string, base: string): boolean {
  if (SCHEMA_REG_UNGATED.has(base)) return true

  // schema-registry-*.properties / schema-registry-*.yml stage configs
  if (
    base.startsWith('schema-registry-') &&
    (base.endsWith('.properties') || base.endsWith('.yml') || base.endsWith('.yaml'))
  ) return true

  // Generic config files inside schema registry directories
  if (
    inAnyDir(pathLower, SCHEMA_REGISTRY_DIRS) &&
    (base.endsWith('.properties') || base.endsWith('.yml') || base.endsWith('.yaml'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: PUBSUB_BROKER_DRIFT (low)
// Apache ActiveMQ, Pulsar, and other messaging systems
// ---------------------------------------------------------------------------

const PUBSUB_UNGATED = new Set([
  'activemq.xml',       // ActiveMQ main broker descriptor — globally unambiguous
  'pulsar-broker.conf', // Apache Pulsar broker config — globally unambiguous
])

function isPubSubBrokerConfig(pathLower: string, base: string): boolean {
  if (PUBSUB_UNGATED.has(base)) return true

  // ActiveMQ configs in activemq directories
  if (
    inAnyDir(pathLower, ACTIVEMQ_DIRS) &&
    (base.endsWith('.xml') || base.endsWith('.properties') || base === 'jetty-realm.properties')
  ) return true

  // Apache Pulsar broker and ZooKeeper configs in pulsar directories
  if (
    inAnyDir(pathLower, PULSAR_DIRS) &&
    (
      base.endsWith('.conf') ||
      base === 'bookkeeper.conf' ||
      base === 'proxy.conf' ||
      base === 'websocket.conf'
    )
  ) return true

  // IBM MQ configuration files — globally unambiguous naming
  if (base === 'mq.ini' || base === 'ibmmq.ini') return true
  if (base.startsWith('ibmmq-') && (base.endsWith('.conf') || base.endsWith('.json'))) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const MESSAGING_SECURITY_RULES: ReadonlyArray<{
  id: MessagingSecurityRuleId
  severity: MessagingSecuritySeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'KAFKA_SECURITY_DRIFT',
    severity: 'high',
    description: 'Apache Kafka broker or client security configuration change detected.',
    recommendation:
      'Audit SASL mechanism and credential settings, verify inter-broker encryption (ssl.keystore / ssl.truststore), review ACL configurations, and confirm PLAINTEXT listeners are not exposed externally.',
    match: isKafkaSecurityConfig,
  },
  {
    id: 'RABBITMQ_SECURITY_DRIFT',
    severity: 'high',
    description: 'RabbitMQ broker configuration or permission definition change detected.',
    recommendation:
      'Review vhost permissions, verify TLS listener settings, ensure the guest user is disabled or password-protected, and audit any changes to user/permission definitions.',
    match: isRabbitMqSecurityConfig,
  },
  {
    id: 'NATS_SECURITY_DRIFT',
    severity: 'high',
    description: 'NATS.io server configuration or account credential change detected.',
    recommendation:
      'Verify operator and account JWT trust chains, review subject-level publish/subscribe permissions, ensure TLS is required for client connections, and audit cluster route authentication.',
    match: isNatsSecurityConfig,
  },
  {
    id: 'MQTT_BROKER_DRIFT',
    severity: 'high',
    description: 'MQTT broker (Mosquitto/HiveMQ) configuration or access control change detected.',
    recommendation:
      'Review ACL rules for topic publish/subscribe access, verify TLS listener configuration, ensure anonymous access is disabled, and audit password file changes.',
    match: isMqttBrokerConfig,
  },
  {
    id: 'STREAM_TLS_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Messaging transport TLS/SSL configuration change detected.',
    recommendation:
      'Verify that strong cipher suites are retained, TLS 1.2+ is enforced, truststore and keystore paths are correct, and no self-signed certificates are being introduced in production.',
    match: isStreamingTlsConfig,
  },
  {
    id: 'MESSAGE_AUTH_POLICY_DRIFT',
    severity: 'medium',
    description: 'Message broker authorisation or access control policy file change detected.',
    recommendation:
      'Audit ACL changes for overly broad topic/queue permissions, verify that wildcard subscriptions are intentional, and ensure per-consumer permissions follow least privilege.',
    match: isMessageAuthPolicyFile,
  },
  {
    id: 'SCHEMA_REGISTRY_DRIFT',
    severity: 'medium',
    description: 'Schema registry configuration change detected (Confluent/Apicurio).',
    recommendation:
      'Review schema compatibility mode changes, verify authentication settings for schema registry API access, and ensure backward/forward compatibility is enforced for security-relevant schemas.',
    match: isSchemaRegistryConfig,
  },
  {
    id: 'PUBSUB_BROKER_DRIFT',
    severity: 'low',
    description: 'Messaging broker configuration change detected (ActiveMQ/Pulsar/IBM MQ).',
    recommendation:
      'Review broker authentication settings, verify that management web consoles require strong credentials, and confirm TLS is enabled for client and broker-to-broker communication.',
    match: isPubSubBrokerConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<MessagingSecuritySeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: MessagingSecurityDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): MessagingSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanMessagingSecurityDrift(changedFiles: string[]): MessagingSecurityDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: MessagingSecurityDriftFinding[] = []

  for (const rule of MESSAGING_SECURITY_RULES) {
    let firstPath = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const p    = normalise(raw)
      const base = p.split('/').pop() ?? p

      if (isVendor(p)) continue
      if (!rule.match(p, base)) continue

      matchCount++
      if (!firstPath) firstPath = raw
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

  // Sort: high → medium → low
  const ORDER: Record<MessagingSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore = computeRiskScore(findings)
  const riskLevel = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No messaging or event streaming security configuration changes detected.'
      : `${findings.length} messaging security rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`     : '',
          mediumCount ? `${mediumCount} medium`  : '',
          lowCount    ? `${lowCount} low`        : '',
        ].filter(Boolean).join(', ')}); risk score ${riskScore}/100.`

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
