// WS-78 — Messaging & Event Streaming Security Configuration Drift Detector: test suite.
import { describe, expect, it } from 'vitest'
import {
  MESSAGING_SECURITY_RULES,
  isMessageAuthPolicyFile,
  scanMessagingSecurityDrift,
} from './messagingSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: KAFKA_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('KAFKA_SECURITY_DRIFT', () => {
  it('flags kafka-ssl.properties (kafka- prefix + .properties = ungated)', () => {
    const r = scanMessagingSecurityDrift(['kafka-ssl.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka-broker.properties (kafka- prefix variant)', () => {
    const r = scanMessagingSecurityDrift(['kafka-broker.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka-security.conf (kafka- prefix + .conf)', () => {
    const r = scanMessagingSecurityDrift(['kafka-security.conf'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/server.properties (canonical broker config in kafka/ dir)', () => {
    const r = scanMessagingSecurityDrift(['kafka/server.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/consumer.properties (consumer config in kafka/ dir)', () => {
    const r = scanMessagingSecurityDrift(['kafka/consumer.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/producer.properties (producer config in kafka/ dir)', () => {
    const r = scanMessagingSecurityDrift(['kafka/producer.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/jaas.conf (SASL/JAAS authentication config)', () => {
    const r = scanMessagingSecurityDrift(['kafka/jaas.conf'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/kraft.properties (KRaft mode controller config)', () => {
    const r = scanMessagingSecurityDrift(['kafka/kraft.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/zookeeper.properties (ZooKeeper connection config in kafka/ dir)', () => {
    const r = scanMessagingSecurityDrift(['kafka/zookeeper.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('flags kafka/config/server.properties (nested kafka/config/ dir)', () => {
    const r = scanMessagingSecurityDrift(['kafka/config/server.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT flag server.properties outside kafka dirs (too generic)', () => {
    const r = scanMessagingSecurityDrift(['config/server.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag consumer.properties outside kafka dirs', () => {
    const r = scanMessagingSecurityDrift(['consumer.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag broker.yaml (wrong extension, no kafka- prefix)', () => {
    const r = scanMessagingSecurityDrift(['broker.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: RABBITMQ_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('RABBITMQ_SECURITY_DRIFT', () => {
  it('flags rabbitmq.conf (ungated modern ini-style config)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq.conf'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq-env.conf (ungated environment variable overrides)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq-env.conf'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq.config (ungated legacy Erlang-term config)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq.config'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq/advanced.config (Erlang advanced config in rabbitmq/ dir)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq/advanced.config'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq/definitions.json (exported user/vhost/permission definitions)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq/definitions.json'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq/definitions.yaml (YAML definitions via Management plugin)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq/definitions.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq/enabled_plugins (plugin list affects auth features)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq/enabled_plugins'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('flags rabbit/custom.conf (.conf file in rabbit/ dir)', () => {
    const r = scanMessagingSecurityDrift(['rabbit/custom.conf'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT flag advanced.config outside rabbitmq dirs', () => {
    const r = scanMessagingSecurityDrift(['config/advanced.config'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag definitions.json outside rabbitmq dirs', () => {
    const r = scanMessagingSecurityDrift(['definitions.json'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: NATS_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('NATS_SECURITY_DRIFT', () => {
  it('flags nats-server.conf (ungated canonical NATS server config)', () => {
    const r = scanMessagingSecurityDrift(['nats-server.conf'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags nats.conf (ungated short-form variant)', () => {
    const r = scanMessagingSecurityDrift(['nats.conf'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags nats-cluster.conf (nats- prefix cluster config)', () => {
    const r = scanMessagingSecurityDrift(['nats-cluster.conf'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags nats-routes.conf (nats- prefix routes config)', () => {
    const r = scanMessagingSecurityDrift(['nats-routes.conf'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags nats/resolver.conf (operator resolver in nats/ dir)', () => {
    const r = scanMessagingSecurityDrift(['nats/resolver.conf'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags nats/operator.jwt (operator JWT credential file)', () => {
    const r = scanMessagingSecurityDrift(['nats/operator.jwt'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT flag resolver.conf outside nats dirs (too generic)', () => {
    const r = scanMessagingSecurityDrift(['config/resolver.conf'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag nats.js (not a config format)', () => {
    const r = scanMessagingSecurityDrift(['nats.js'])
    expect(r.findings.some((f) => f.ruleId === 'NATS_SECURITY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: MQTT_BROKER_DRIFT
// ---------------------------------------------------------------------------

describe('MQTT_BROKER_DRIFT', () => {
  it('flags mosquitto.conf (ungated Mosquitto broker config)', () => {
    const r = scanMessagingSecurityDrift(['mosquitto.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })

  it('flags mosquitto.passwd (ungated Mosquitto password file)', () => {
    const r = scanMessagingSecurityDrift(['mosquitto.passwd'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })

  it('flags hivemq-config.xml (ungated HiveMQ enterprise broker config)', () => {
    const r = scanMessagingSecurityDrift(['hivemq-config.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })

  it('flags mosquitto/acl.conf (ACL file in mosquitto/ dir)', () => {
    const r = scanMessagingSecurityDrift(['mosquitto/acl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })

  it('flags mqtt/broker.conf (.conf in mqtt/ dir)', () => {
    const r = scanMessagingSecurityDrift(['mqtt/broker.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })

  it('flags mqtt/acl (bare ACL file in mqtt/ dir)', () => {
    const r = scanMessagingSecurityDrift(['mqtt/acl'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })

  it('does NOT flag broker.conf outside mqtt dirs (too generic)', () => {
    const r = scanMessagingSecurityDrift(['config/broker.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(false)
  })

  it('does NOT flag acl.conf outside mqtt/mosquitto dirs', () => {
    const r = scanMessagingSecurityDrift(['acl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: STREAM_TLS_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('STREAM_TLS_CONFIG_DRIFT', () => {
  it('flags kafka-ssl.properties (ungated Kafka SSL config)', () => {
    const r = scanMessagingSecurityDrift(['kafka-ssl.properties'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags kafka-tls.properties (ungated Kafka TLS config)', () => {
    const r = scanMessagingSecurityDrift(['kafka-tls.properties'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags amqp-ssl.conf (ungated AMQP SSL config)', () => {
    const r = scanMessagingSecurityDrift(['amqp-ssl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags amqp-tls.conf (ungated AMQP TLS config)', () => {
    const r = scanMessagingSecurityDrift(['amqp-tls.conf'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags kafka/ssl.properties (ssl in name, inside kafka/ dir)', () => {
    const r = scanMessagingSecurityDrift(['kafka/ssl.properties'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags rabbitmq/tls.conf (tls in name, inside rabbitmq/ dir)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq/tls.conf'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags nats/ssl-ciphers.conf (ssl in name, inside nats/ dir)', () => {
    const r = scanMessagingSecurityDrift(['nats/ssl-ciphers.conf'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('flags messaging/tls-config.yaml (tls in name, inside messaging/ dir)', () => {
    const r = scanMessagingSecurityDrift(['messaging/tls-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT flag ssl.properties outside messaging dirs', () => {
    const r = scanMessagingSecurityDrift(['config/ssl.properties'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(false)
  })

  it('does NOT flag tls.conf at repo root (no messaging dir context)', () => {
    const r = scanMessagingSecurityDrift(['tls.conf'])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: MESSAGE_AUTH_POLICY_DRIFT — integration tests
// ---------------------------------------------------------------------------

describe('MESSAGE_AUTH_POLICY_DRIFT', () => {
  it('flags kafka-acl.yaml (kafka- prefix + acl keyword = ungated)', () => {
    const r = scanMessagingSecurityDrift(['kafka-acl.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq-auth.json (rabbitmq- prefix + auth keyword = ungated)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq-auth.json'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
  })

  it('flags nats-permissions.conf (nats- prefix + permission keyword)', () => {
    const r = scanMessagingSecurityDrift(['nats-permissions.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
  })

  it('flags kafka/users.json (kafka/ dir + user keyword + .json ext)', () => {
    const r = scanMessagingSecurityDrift(['kafka/users.json'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
  })

  it('flags rabbitmq/permissions.yaml (rabbitmq/ dir + permission keyword)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq/permissions.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
  })

  it('flags messaging/authorization.yaml (messaging/ dir + auth in authorization)', () => {
    const r = scanMessagingSecurityDrift(['messaging/authorization.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT flag kafka/server.properties (no auth keyword in filename)', () => {
    const r = scanMessagingSecurityDrift(['kafka/server.properties'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(false)
  })

  it('does NOT flag auth.yaml at repo root (not in messaging dir)', () => {
    const r = scanMessagingSecurityDrift(['auth.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(false)
  })

  it('does NOT flag kafka/acl.js (wrong extension)', () => {
    const r = scanMessagingSecurityDrift(['kafka/acl.js'])
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isMessageAuthPolicyFile — unit tests for the exported user contribution
// ---------------------------------------------------------------------------

describe('isMessageAuthPolicyFile (unit)', () => {
  const check = (path: string) => {
    const p    = path.toLowerCase()
    const base = p.split('/').pop() ?? p
    return isMessageAuthPolicyFile(p, base)
  }

  it('returns true for kafka-acl.yaml (broker prefix + acl keyword)', () => {
    expect(check('kafka-acl.yaml')).toBe(true)
  })

  it('returns true for rabbitmq-auth.json (broker prefix + auth keyword)', () => {
    expect(check('rabbitmq-auth.json')).toBe(true)
  })

  it('returns true for amqp-policy.json (broker prefix + policy keyword)', () => {
    expect(check('amqp-policy.json')).toBe(true)
  })

  it('returns true for kafka/users.json (kafka/ dir + user keyword + json ext)', () => {
    expect(check('kafka/users.json')).toBe(true)
  })

  it('returns true for rabbitmq/credentials.yaml (rabbitmq/ dir + credential keyword)', () => {
    expect(check('rabbitmq/credentials.yaml')).toBe(true)
  })

  it('returns true for messaging/access-policy.conf (messaging/ dir + access keyword)', () => {
    expect(check('messaging/access-policy.conf')).toBe(true)
  })

  it('returns false for auth.yaml at root (no broker prefix, not in messaging dir)', () => {
    expect(check('auth.yaml')).toBe(false)
  })

  it('returns false for kafka/server.properties (no auth keyword in filename)', () => {
    expect(check('kafka/server.properties')).toBe(false)
  })

  it('returns false for kafka/acl.js (wrong extension)', () => {
    expect(check('kafka/acl.js')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: SCHEMA_REGISTRY_DRIFT
// ---------------------------------------------------------------------------

describe('SCHEMA_REGISTRY_DRIFT', () => {
  it('flags schema-registry.properties (ungated Confluent Schema Registry)', () => {
    const r = scanMessagingSecurityDrift(['schema-registry.properties'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('flags schema-registry.yml (ungated YAML variant)', () => {
    const r = scanMessagingSecurityDrift(['schema-registry.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('flags schema-registry.yaml (ungated YAML variant)', () => {
    const r = scanMessagingSecurityDrift(['schema-registry.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('flags apicurio-registry.properties (ungated Apicurio Registry)', () => {
    const r = scanMessagingSecurityDrift(['apicurio-registry.properties'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('flags schema-registry-ssl.properties (schema-registry- prefix)', () => {
    const r = scanMessagingSecurityDrift(['schema-registry-ssl.properties'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('flags schema-registry/config.properties (.properties in schema-registry/ dir)', () => {
    const r = scanMessagingSecurityDrift(['schema-registry/config.properties'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('flags registry/schema-config.yml (.yml in registry/ dir)', () => {
    const r = scanMessagingSecurityDrift(['registry/schema-config.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
  })

  it('does NOT flag registry.properties (no schema-registry prefix, no registry/ dir)', () => {
    const r = scanMessagingSecurityDrift(['registry.properties'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(false)
  })

  it('does NOT flag config.properties outside schema-registry dirs', () => {
    const r = scanMessagingSecurityDrift(['config.properties'])
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: PUBSUB_BROKER_DRIFT
// ---------------------------------------------------------------------------

describe('PUBSUB_BROKER_DRIFT', () => {
  it('flags activemq.xml (ungated ActiveMQ main broker descriptor)', () => {
    const r = scanMessagingSecurityDrift(['activemq.xml'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags pulsar-broker.conf (ungated Apache Pulsar broker config)', () => {
    const r = scanMessagingSecurityDrift(['pulsar-broker.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags activemq/broker.xml (.xml in activemq/ dir)', () => {
    const r = scanMessagingSecurityDrift(['activemq/broker.xml'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags activemq/activemq.properties (.properties in activemq/ dir)', () => {
    const r = scanMessagingSecurityDrift(['activemq/activemq.properties'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags pulsar/broker.conf (.conf in pulsar/ dir)', () => {
    const r = scanMessagingSecurityDrift(['pulsar/broker.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags pulsar/bookkeeper.conf (bookkeeper config in pulsar/ dir)', () => {
    const r = scanMessagingSecurityDrift(['pulsar/bookkeeper.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags mq.ini (IBM MQ config — globally unambiguous)', () => {
    const r = scanMessagingSecurityDrift(['mq.ini'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('flags ibmmq-security.conf (ibmmq- prefix)', () => {
    const r = scanMessagingSecurityDrift(['ibmmq-security.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(true)
  })

  it('does NOT flag broker.xml outside activemq dirs (too generic)', () => {
    const r = scanMessagingSecurityDrift(['deploy/broker.xml'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(false)
  })

  it('does NOT flag broker.conf at repo root (no activemq/pulsar dir)', () => {
    const r = scanMessagingSecurityDrift(['broker.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PUBSUB_BROKER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor directory exclusion', () => {
  it('does not flag rabbitmq.conf in node_modules/', () => {
    const r = scanMessagingSecurityDrift(['node_modules/amqp/rabbitmq.conf'])
    expect(r.findings).toHaveLength(0)
  })

  it('does not flag mosquitto.conf in vendor/', () => {
    const r = scanMessagingSecurityDrift(['vendor/mqtt/mosquitto.conf'])
    expect(r.findings).toHaveLength(0)
  })

  it('does not flag kafka/server.properties in .git/', () => {
    const r = scanMessagingSecurityDrift(['.git/hooks/kafka/server.properties'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes before matching (kafka\\server.properties)', () => {
    const r = scanMessagingSecurityDrift(['kafka\\server.properties'])
    expect(r.findings.some((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')).toBe(true)
  })

  it('normalises nested Windows paths (rabbitmq\\advanced.config)', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq\\advanced.config'])
    expect(r.findings.some((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')).toBe(true)
  })

  it('normalises mosquitto paths (mosquitto\\acl.conf)', () => {
    const r = scanMessagingSecurityDrift(['mosquitto\\acl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MQTT_BROKER_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule regardless of matched-file count
// ---------------------------------------------------------------------------

describe('deduplication per rule', () => {
  it('produces one finding for multiple RabbitMQ config files', () => {
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf',
      'rabbitmq-env.conf',
      'rabbitmq.config',
    ])
    const rbFindings = r.findings.filter((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')
    expect(rbFindings).toHaveLength(1)
    expect(rbFindings[0].matchCount).toBe(3)
  })

  it('records the first matched path', () => {
    const r = scanMessagingSecurityDrift([
      'kafka/server.properties',
      'kafka/consumer.properties',
      'kafka/producer.properties',
    ])
    const f = r.findings.find((f) => f.ruleId === 'KAFKA_SECURITY_DRIFT')!
    expect(f.matchedPath).toBe('kafka/server.properties')
    expect(f.matchCount).toBe(3)
  })

  it('does not double-count a file across two different rules', () => {
    // rabbitmq.conf triggers RABBITMQ only; nats-server.conf triggers NATS only.
    const r = scanMessagingSecurityDrift(['rabbitmq.conf', 'nats-server.conf'])
    const rbFindings   = r.findings.filter((f) => f.ruleId === 'RABBITMQ_SECURITY_DRIFT')
    const natsFindings = r.findings.filter((f) => f.ruleId === 'NATS_SECURITY_DRIFT')
    expect(rbFindings).toHaveLength(1)
    expect(natsFindings).toHaveLength(1)
    expect(rbFindings[0].matchCount).toBe(1)
    expect(natsFindings[0].matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and level none for empty input', () => {
    const r = scanMessagingSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('returns score 0 and level none when no files match', () => {
    const r = scanMessagingSecurityDrift(['src/app.ts', 'README.md', 'package.json'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('HIGH × 1 match → score 15 → level low', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH × 3 matches → score 45 → level high (cap=45 applied)', () => {
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf',
      'rabbitmq-env.conf',
      'rabbitmq.config',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('MEDIUM × 1 match → score 8 → level low', () => {
    const r = scanMessagingSecurityDrift(['schema-registry.properties'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('MEDIUM × 4 matches → score 25 (capped at MEDIUM cap=25) → level medium', () => {
    const r = scanMessagingSecurityDrift([
      'schema-registry.properties',
      'schema-registry.yml',
      'schema-registry.yaml',
      'apicurio-registry.properties',
    ])
    expect(r.riskScore).toBe(25)
    expect(r.riskLevel).toBe('medium')
  })

  it('LOW × 1 match → score 4 → level low', () => {
    const r = scanMessagingSecurityDrift(['activemq.xml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH cap (45) + MEDIUM cap (25) = 70 → level critical', () => {
    const r = scanMessagingSecurityDrift([
      // 3 RabbitMQ HIGH matches → cap 45
      'rabbitmq.conf', 'rabbitmq-env.conf', 'rabbitmq.config',
      // 4 Schema Registry MEDIUM matches → cap 25
      'schema-registry.properties', 'schema-registry.yml',
      'schema-registry.yaml', 'apicurio-registry.properties',
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })

  it('total clamped at 100 even when sum exceeds 100', () => {
    const r = scanMessagingSecurityDrift([
      // KAFKA (HIGH): 3 matches → 45
      'kafka/server.properties', 'kafka/consumer.properties', 'kafka/producer.properties',
      // RABBITMQ (HIGH): 3 matches → 45
      'rabbitmq.conf', 'rabbitmq-env.conf', 'rabbitmq.config',
      // NATS (HIGH): 3 matches → 45
      'nats-server.conf', 'nats.conf', 'nats-cluster.conf',
      // MQTT (HIGH): 3 matches → 45
      'mosquitto.conf', 'mosquitto.passwd', 'hivemq-config.xml',
    ])
    expect(r.riskScore).toBe(100)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Risk levels (boundary checks)
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 16 → low', () => {
    // SCHEMA_REGISTRY (MEDIUM=8) + STREAM_TLS (MEDIUM=8) = 16
    const r = scanMessagingSecurityDrift(['schema-registry.properties', 'amqp-ssl.conf'])
    expect(r.riskScore).toBe(16)
    expect(r.riskLevel).toBe('low')
  })

  it('score 42 → medium', () => {
    // HIGH (15) + HIGH (15) + MEDIUM (8) + LOW (4) = 42
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf',              // RABBITMQ HIGH → 15
      'mosquitto.conf',             // MQTT HIGH → 15
      'schema-registry.properties', // SCHEMA MEDIUM → 8
      'activemq.xml',               // PUBSUB LOW → 4
    ])
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high (3 RabbitMQ configs capped)', () => {
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf', 'rabbitmq-env.conf', 'rabbitmq.config',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 69 → high', () => {
    // 3 RabbitMQ (45) + 3 schema-registry (24, not capped) = 69
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf', 'rabbitmq-env.conf', 'rabbitmq.config', // RabbitMQ × 3 → 45
      'schema-registry.properties',  // SCHEMA MEDIUM × 1 → 8
      'schema-registry.yml',         // SCHEMA MEDIUM × 1 → 8 (matchCount=2 → 16)
      'schema-registry.yaml',        // SCHEMA MEDIUM × 1 → 8 (matchCount=3 → 24)
    ])
    expect(r.riskScore).toBe(69)
    expect(r.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering — high first
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('orders findings high → medium → low', () => {
    const r = scanMessagingSecurityDrift([
      'activemq.xml',                // LOW
      'schema-registry.properties',  // MEDIUM
      'rabbitmq.conf',               // HIGH
    ])
    const severities = r.findings.map((f) => f.severity)
    expect(severities[0]).toBe('high')
    const lastMediumIndex = severities.lastIndexOf('medium')
    const firstLowIndex   = severities.indexOf('low')
    if (lastMediumIndex !== -1 && firstLowIndex !== -1) {
      expect(lastMediumIndex).toBeLessThan(firstLowIndex)
    }
  })
})

// ---------------------------------------------------------------------------
// Summary and result shape
// ---------------------------------------------------------------------------

describe('result shape and summary', () => {
  it('clean push: correct shape with empty findings', () => {
    const r = scanMessagingSecurityDrift(['src/index.ts'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.highCount).toBe(0)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toBe('No messaging or event streaming security configuration changes detected.')
  })

  it('summary contains rule count, severity breakdown, and score', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq.conf', 'schema-registry.properties'])
    expect(r.summary).toContain('2 messaging security rules triggered')
    expect(r.summary).toContain('1 high')
    expect(r.summary).toContain('1 medium')
    expect(r.summary).toContain(`${r.riskScore}/100`)
  })

  it('summary uses singular "rule" when exactly 1 finding', () => {
    const r = scanMessagingSecurityDrift(['mosquitto.conf'])
    expect(r.summary).toContain('1 messaging security rule triggered')
  })

  it('totalFindings equals findings array length', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq.conf', 'nats-server.conf', 'schema-registry.properties'])
    expect(r.totalFindings).toBe(r.findings.length)
  })

  it('highCount, mediumCount, lowCount sum to totalFindings', () => {
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf', 'schema-registry.properties', 'activemq.xml',
    ])
    expect(r.highCount + r.mediumCount + r.lowCount).toBe(r.totalFindings)
  })

  it('each finding has all required fields', () => {
    const r = scanMessagingSecurityDrift(['rabbitmq.conf'])
    const f = r.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule push scenario
// ---------------------------------------------------------------------------

describe('multi-rule push scenario', () => {
  it('Kafka + RabbitMQ + NATS → 3 distinct HIGH findings', () => {
    const r = scanMessagingSecurityDrift([
      'kafka/server.properties', // KAFKA_SECURITY_DRIFT (HIGH)
      'rabbitmq.conf',           // RABBITMQ_SECURITY_DRIFT (HIGH)
      'nats-server.conf',        // NATS_SECURITY_DRIFT (HIGH)
    ])
    expect(r.findings).toHaveLength(3)
    const ids = r.findings.map((f) => f.ruleId)
    expect(ids).toContain('KAFKA_SECURITY_DRIFT')
    expect(ids).toContain('RABBITMQ_SECURITY_DRIFT')
    expect(ids).toContain('NATS_SECURITY_DRIFT')
  })

  it('multiple schema registry configs → SCHEMA_REGISTRY_DRIFT fired once (dedup)', () => {
    const r = scanMessagingSecurityDrift([
      'schema-registry.properties',
      'schema-registry.yml',
      'apicurio-registry.properties',
    ])
    const schemaFindings = r.findings.filter((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')
    expect(schemaFindings).toHaveLength(1)
    expect(schemaFindings[0].matchCount).toBe(3)
  })

  it('TLS + auth policy + schema push → all three MEDIUM rules fire, HIGH first in sort', () => {
    const r = scanMessagingSecurityDrift([
      'rabbitmq.conf',              // HIGH
      'amqp-ssl.conf',              // STREAM_TLS MEDIUM
      'kafka-acl.yaml',             // MESSAGE_AUTH MEDIUM
      'schema-registry.properties', // SCHEMA MEDIUM
      'activemq.xml',               // PUBSUB LOW
    ])
    expect(r.findings.some((f) => f.ruleId === 'STREAM_TLS_CONFIG_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'MESSAGE_AUTH_POLICY_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'SCHEMA_REGISTRY_DRIFT')).toBe(true)
    const severities = r.findings.map((f) => f.severity)
    expect(severities[0]).toBe('high')
    expect(severities[severities.length - 1]).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry completeness', () => {
  const ALL_RULE_IDS = [
    'KAFKA_SECURITY_DRIFT',
    'RABBITMQ_SECURITY_DRIFT',
    'NATS_SECURITY_DRIFT',
    'MQTT_BROKER_DRIFT',
    'STREAM_TLS_CONFIG_DRIFT',
    'MESSAGE_AUTH_POLICY_DRIFT',
    'SCHEMA_REGISTRY_DRIFT',
    'PUBSUB_BROKER_DRIFT',
  ]

  it('registry contains exactly 8 rules', () => {
    expect(MESSAGING_SECURITY_RULES).toHaveLength(8)
  })

  it('every rule ID appears in the registry', () => {
    const registryIds = MESSAGING_SECURITY_RULES.map((r) => r.id)
    for (const id of ALL_RULE_IDS) {
      expect(registryIds).toContain(id)
    }
  })

  it('every rule has a non-empty description and recommendation', () => {
    for (const rule of MESSAGING_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity distribution: 4 high, 3 medium, 1 low', () => {
    const high   = MESSAGING_SECURITY_RULES.filter((r) => r.severity === 'high').length
    const medium = MESSAGING_SECURITY_RULES.filter((r) => r.severity === 'medium').length
    const low    = MESSAGING_SECURITY_RULES.filter((r) => r.severity === 'low').length
    expect(high).toBe(4)
    expect(medium).toBe(3)
    expect(low).toBe(1)
  })
})
