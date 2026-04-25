import { describe, it, expect } from 'vitest'
import {
  scanServiceMeshSecurityDrift,
  isCniNetworkPolicyConfig,
  SERVICE_MESH_SECURITY_RULES,
} from './serviceMeshSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]) {
  return scanServiceMeshSecurityDrift(files)
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
    expect(scan(['node_modules/envoy.yaml'])).toMatchObject({ riskLevel: 'none' })
    expect(scan(['vendor/teleport.yaml'])).toMatchObject({ riskLevel: 'none' })
    expect(scan(['.terraform/spire-server.conf'])).toMatchObject({ riskLevel: 'none' })
  })

  it('windows backslash paths normalised', () => {
    expect(hasRule(['istio\\peer-authentication.yaml'], 'ISTIO_AUTH_POLICY_DRIFT')).toBe(true)
    expect(hasRule(['envoy\\envoy.yaml'], 'ENVOY_PROXY_SECURITY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// ISTIO_AUTH_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('ISTIO_AUTH_POLICY_DRIFT', () => {
  const RULE = 'ISTIO_AUTH_POLICY_DRIFT'

  it('peer-authentication.yaml exact → flagged', () =>
    expect(hasRule(['peer-authentication.yaml'], RULE)).toBe(true))
  it('authorization-policy.yaml exact → flagged', () =>
    expect(hasRule(['authorization-policy.yaml'], RULE)).toBe(true))
  it('request-authentication.yaml exact → flagged', () =>
    expect(hasRule(['request-authentication.yaml'], RULE)).toBe(true))
  it('authz-policy.yaml exact → flagged', () =>
    expect(hasRule(['authz-policy.yaml'], RULE)).toBe(true))
  it('peerauthentication.yaml exact → flagged', () =>
    expect(hasRule(['peerauthentication.yaml'], RULE)).toBe(true))
  it('authorizationpolicy.yaml exact → flagged', () =>
    expect(hasRule(['authorizationpolicy.yaml'], RULE)).toBe(true))
  it('destination-rule.yaml exact → flagged', () =>
    expect(hasRule(['destination-rule.yaml'], RULE)).toBe(true))
  it('destinationrule.yml exact → flagged', () =>
    expect(hasRule(['destinationrule.yml'], RULE)).toBe(true))

  it('file in istio/ dir → flagged', () =>
    expect(hasRule(['istio/mtls-policy.yaml'], RULE)).toBe(true))
  it('file in mesh-policy/ dir → flagged', () =>
    expect(hasRule(['mesh-policy/auth.yaml'], RULE)).toBe(true))
  it('file in service-mesh/istio/ dir → flagged', () =>
    expect(hasRule(['service-mesh/istio/security.yaml'], RULE)).toBe(true))

  it('peer-auth prefix → flagged', () =>
    expect(hasRule(['peer-auth-default.yaml'], RULE)).toBe(true))

  it('file in k8s/ dir NOT flagged (WS-63)', () =>
    expect(hasRule(['k8s/peer-authentication.yaml'], RULE)).toBe(false))
  it('file in helm/ dir NOT flagged (WS-63)', () =>
    expect(hasRule(['helm/charts/istio/authz.yaml'], RULE)).toBe(false))
  it('generic config.yaml NOT flagged', () =>
    expect(hasRule(['config/config.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// ENVOY_PROXY_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('ENVOY_PROXY_SECURITY_DRIFT', () => {
  const RULE = 'ENVOY_PROXY_SECURITY_DRIFT'

  it('envoy.yaml exact → flagged', () => expect(hasRule(['envoy.yaml'], RULE)).toBe(true))
  it('envoy.yml exact → flagged', () => expect(hasRule(['envoy.yml'], RULE)).toBe(true))
  it('envoy.json exact → flagged', () => expect(hasRule(['envoy.json'], RULE)).toBe(true))
  it('envoy-config.yaml exact → flagged', () =>
    expect(hasRule(['envoy-config.yaml'], RULE)).toBe(true))
  it('envoy-bootstrap.yaml exact → flagged', () =>
    expect(hasRule(['envoy-bootstrap.yaml'], RULE)).toBe(true))
  it('xds-config.yaml exact → flagged', () =>
    expect(hasRule(['xds-config.yaml'], RULE)).toBe(true))
  it('lds.yaml exact → flagged', () => expect(hasRule(['lds.yaml'], RULE)).toBe(true))
  it('cds.yaml exact → flagged', () => expect(hasRule(['cds.yaml'], RULE)).toBe(true))

  it('file in envoy/ dir → flagged', () =>
    expect(hasRule(['envoy/clusters.yaml'], RULE)).toBe(true))
  it('file in xds/ dir → flagged', () =>
    expect(hasRule(['xds/listeners.yaml'], RULE)).toBe(true))

  it('envoy- prefix → flagged', () =>
    expect(hasRule(['envoy-security.yaml'], RULE)).toBe(true))

  it('generic proxy.yaml NOT flagged', () =>
    expect(hasRule(['config/proxy.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// SPIFFE_SPIRE_DRIFT
// ---------------------------------------------------------------------------

describe('SPIFFE_SPIRE_DRIFT', () => {
  const RULE = 'SPIFFE_SPIRE_DRIFT'

  it('spire-server.conf exact → flagged', () =>
    expect(hasRule(['spire-server.conf'], RULE)).toBe(true))
  it('spire-agent.conf exact → flagged', () =>
    expect(hasRule(['spire-agent.conf'], RULE)).toBe(true))
  it('spire-server.yaml exact → flagged', () =>
    expect(hasRule(['spire-server.yaml'], RULE)).toBe(true))
  it('spire-agent.yml exact → flagged', () =>
    expect(hasRule(['spire-agent.yml'], RULE)).toBe(true))
  it('trust-bundle.yaml exact → flagged', () =>
    expect(hasRule(['trust-bundle.yaml'], RULE)).toBe(true))
  it('trust-bundle.json exact → flagged', () =>
    expect(hasRule(['trust-bundle.json'], RULE)).toBe(true))
  it('spiffe-trust.yaml exact → flagged', () =>
    expect(hasRule(['spiffe-trust.yaml'], RULE)).toBe(true))
  it('spire.conf exact → flagged', () =>
    expect(hasRule(['spire.conf'], RULE)).toBe(true))

  it('file in spire/ dir → flagged', () =>
    expect(hasRule(['spire/attestation.yaml'], RULE)).toBe(true))
  it('file in spiffe/ dir → flagged', () =>
    expect(hasRule(['spiffe/config.yaml'], RULE)).toBe(true))

  it('spire- prefix → flagged', () =>
    expect(hasRule(['spire-config.yaml'], RULE)).toBe(true))
  it('spiffe- prefix → flagged', () =>
    expect(hasRule(['spiffe-trust-bundle.yaml'], RULE)).toBe(true))

  it('generic config.conf NOT flagged', () =>
    expect(hasRule(['config/server.conf'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// LINKERD_SECURITY_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('LINKERD_SECURITY_POLICY_DRIFT', () => {
  const RULE = 'LINKERD_SECURITY_POLICY_DRIFT'

  it('serverauthorization.yaml exact → flagged', () =>
    expect(hasRule(['serverauthorization.yaml'], RULE)).toBe(true))
  it('server-authorization.yaml exact → flagged', () =>
    expect(hasRule(['server-authorization.yaml'], RULE)).toBe(true))
  it('linkerd-proxy.yaml exact → flagged', () =>
    expect(hasRule(['linkerd-proxy.yaml'], RULE)).toBe(true))
  it('linkerd-config.yaml exact → flagged', () =>
    expect(hasRule(['linkerd-config.yaml'], RULE)).toBe(true))
  it('linkerd-control-plane.yaml exact → flagged', () =>
    expect(hasRule(['linkerd-control-plane.yaml'], RULE)).toBe(true))

  it('file in linkerd/ dir → flagged', () =>
    expect(hasRule(['linkerd/server.yaml'], RULE)).toBe(true))
  it('file in service-mesh/linkerd/ dir → flagged', () =>
    expect(hasRule(['service-mesh/linkerd/policy.yaml'], RULE)).toBe(true))

  it('linkerd- prefix → flagged', () =>
    expect(hasRule(['linkerd-policy.yaml'], RULE)).toBe(true))

  it('generic server.yaml NOT in linkerd dir NOT flagged', () =>
    expect(hasRule(['config/server.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// CONSUL_CONNECT_DRIFT
// ---------------------------------------------------------------------------

describe('CONSUL_CONNECT_DRIFT', () => {
  const RULE = 'CONSUL_CONNECT_DRIFT'

  it('consul.hcl exact → flagged', () => expect(hasRule(['consul.hcl'], RULE)).toBe(true))
  it('consul.yaml exact → flagged', () => expect(hasRule(['consul.yaml'], RULE)).toBe(true))
  it('intentions.json exact → flagged', () =>
    expect(hasRule(['intentions.json'], RULE)).toBe(true))
  it('service-intentions.yaml exact → flagged', () =>
    expect(hasRule(['service-intentions.yaml'], RULE)).toBe(true))
  it('acl-policy.hcl exact → flagged', () =>
    expect(hasRule(['acl-policy.hcl'], RULE)).toBe(true))
  it('connect-proxy.hcl exact → flagged', () =>
    expect(hasRule(['connect-proxy.hcl'], RULE)).toBe(true))
  it('consul-config.hcl exact → flagged', () =>
    expect(hasRule(['consul-config.hcl'], RULE)).toBe(true))

  it('file in consul/ dir → flagged', () =>
    expect(hasRule(['consul/intentions.hcl'], RULE)).toBe(true))
  it('file in consul/policies/ dir → flagged', () =>
    expect(hasRule(['consul/policies/api-acl.hcl'], RULE)).toBe(true))

  it('consul- prefix → flagged', () =>
    expect(hasRule(['consul-acl.json'], RULE)).toBe(true))

  it('generic policy.json NOT flagged', () =>
    expect(hasRule(['config/policy.json'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// isCniNetworkPolicyConfig (user contribution)
// ---------------------------------------------------------------------------

describe('isCniNetworkPolicyConfig', () => {
  it('k8s/ directory excluded (WS-63)', () =>
    expect(isCniNetworkPolicyConfig('k8s/cilium-policy.yaml')).toBe(false))
  it('kubernetes/ directory excluded', () =>
    expect(isCniNetworkPolicyConfig('kubernetes/calico.yaml')).toBe(false))
  it('helm/ directory excluded', () =>
    expect(isCniNetworkPolicyConfig('helm/charts/cilium/values.yaml')).toBe(false))
  it('charts/ directory excluded', () =>
    expect(isCniNetworkPolicyConfig('charts/calico/config.yaml')).toBe(false))

  // Cilium exact filenames
  it('cilium.yaml exact outside k8s → flagged', () =>
    expect(isCniNetworkPolicyConfig('cilium.yaml')).toBe(true))
  it('cilium-config.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('cilium-config.yaml')).toBe(true))
  it('ciliumnetworkpolicy.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('ciliumnetworkpolicy.yaml')).toBe(true))
  it('clusterwidenetworkpolicy.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('clusterwidenetworkpolicy.yaml')).toBe(true))
  it('cni-config.json exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('cni-config.json')).toBe(true))

  // Calico exact filenames
  it('calicoctl.cfg exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('calicoctl.cfg')).toBe(true))
  it('globalnetworkpolicy.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('globalnetworkpolicy.yaml')).toBe(true))
  it('felixconfiguration.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('felixconfiguration.yaml')).toBe(true))

  // Antrea exact filenames
  it('antrea.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('antrea.yaml')).toBe(true))
  it('antrea-config.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('antrea-config.yaml')).toBe(true))
  it('clusternetworkpolicy.yaml exact → flagged', () =>
    expect(isCniNetworkPolicyConfig('clusternetworkpolicy.yaml')).toBe(true))

  // Directory context
  it('file in cilium/ dir → flagged', () =>
    expect(isCniNetworkPolicyConfig('cilium/policy.yaml')).toBe(true))
  it('file in calico/ dir → flagged', () =>
    expect(isCniNetworkPolicyConfig('calico/network-policy.yaml')).toBe(true))
  it('file in antrea-policies/ dir → flagged', () =>
    expect(isCniNetworkPolicyConfig('antrea-policies/cluster.yaml')).toBe(true))
  it('file in cni/ dir → flagged', () =>
    expect(isCniNetworkPolicyConfig('cni/config.json')).toBe(true))
  it('file in network-policies/ dir → flagged', () =>
    expect(isCniNetworkPolicyConfig('network-policies/egress.yaml')).toBe(true))

  // Prefix patterns
  it('cilium- prefix yaml → flagged', () =>
    expect(isCniNetworkPolicyConfig('cilium-egress-policy.yaml')).toBe(true))
  it('calico- prefix yaml → flagged', () =>
    expect(isCniNetworkPolicyConfig('calico-network.yaml')).toBe(true))
  it('antrea- prefix yaml → flagged', () =>
    expect(isCniNetworkPolicyConfig('antrea-cluster.yaml')).toBe(true))

  it('generic network-policy.yaml not in cni dir NOT flagged', () =>
    expect(isCniNetworkPolicyConfig('config/network-policy.yaml')).toBe(false))
})

describe('CNI_NETWORK_POLICY_DRIFT via scanner', () => {
  const RULE = 'CNI_NETWORK_POLICY_DRIFT'

  it('cilium.yaml (outside k8s) → flagged', () =>
    expect(hasRule(['cilium.yaml'], RULE)).toBe(true))
  it('calico/policy.yaml → flagged', () =>
    expect(hasRule(['calico/policy.yaml'], RULE)).toBe(true))
  it('k8s/cilium-policy.yaml → NOT flagged', () =>
    expect(hasRule(['k8s/cilium-policy.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// ZERO_TRUST_ACCESS_DRIFT
// ---------------------------------------------------------------------------

describe('ZERO_TRUST_ACCESS_DRIFT', () => {
  const RULE = 'ZERO_TRUST_ACCESS_DRIFT'

  it('cloudflared.yaml exact → flagged', () =>
    expect(hasRule(['cloudflared.yaml'], RULE)).toBe(true))
  it('cloudflared.json exact → flagged', () =>
    expect(hasRule(['cloudflared.json'], RULE)).toBe(true))
  it('teleport.yaml exact → flagged', () =>
    expect(hasRule(['teleport.yaml'], RULE)).toBe(true))
  it('teleport-config.yaml exact → flagged', () =>
    expect(hasRule(['teleport-config.yaml'], RULE)).toBe(true))
  it('pomerium.yaml exact → flagged', () =>
    expect(hasRule(['pomerium.yaml'], RULE)).toBe(true))
  it('pomerium-config.yml exact → flagged', () =>
    expect(hasRule(['pomerium-config.yml'], RULE)).toBe(true))
  it('beyondcorp-config.yaml exact → flagged', () =>
    expect(hasRule(['beyondcorp-config.yaml'], RULE)).toBe(true))
  it('tailscale-acl.json exact → flagged', () =>
    expect(hasRule(['tailscale-acl.json'], RULE)).toBe(true))
  it('tailscale.json exact → flagged', () =>
    expect(hasRule(['tailscale.json'], RULE)).toBe(true))

  it('file in cloudflare/ dir → flagged', () =>
    expect(hasRule(['cloudflare/tunnel.yaml'], RULE)).toBe(true))
  it('file in teleport/ dir → flagged', () =>
    expect(hasRule(['teleport/access-policy.yaml'], RULE)).toBe(true))
  it('file in zero-trust/ dir → flagged', () =>
    expect(hasRule(['zero-trust/config.json'], RULE)).toBe(true))
  it('file in ztna/ dir → flagged', () =>
    expect(hasRule(['ztna/access-rules.yaml'], RULE)).toBe(true))

  it('teleport- prefix → flagged', () =>
    expect(hasRule(['teleport-node.yaml'], RULE)).toBe(true))
  it('pomerium- prefix → flagged', () =>
    expect(hasRule(['pomerium-routes.yaml'], RULE)).toBe(true))
  it('cloudflared- prefix → flagged', () =>
    expect(hasRule(['cloudflared-tunnel.json'], RULE)).toBe(true))
  it('tailscale- prefix → flagged', () =>
    expect(hasRule(['tailscale-policy.yaml'], RULE)).toBe(true))

  it('generic access.yaml NOT flagged', () =>
    expect(hasRule(['config/access.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// MESH_GATEWAY_DRIFT
// ---------------------------------------------------------------------------

describe('MESH_GATEWAY_DRIFT', () => {
  const RULE = 'MESH_GATEWAY_DRIFT'

  it('virtualservice.yaml exact → flagged', () =>
    expect(hasRule(['virtualservice.yaml'], RULE)).toBe(true))
  it('virtual-service.yaml exact → flagged', () =>
    expect(hasRule(['virtual-service.yaml'], RULE)).toBe(true))
  it('envoy-gateway.yaml exact → flagged', () =>
    expect(hasRule(['envoy-gateway.yaml'], RULE)).toBe(true))
  it('kong-plugin.yaml exact → flagged', () =>
    expect(hasRule(['kong-plugin.yaml'], RULE)).toBe(true))
  it('serviceentry.yaml exact → flagged', () =>
    expect(hasRule(['serviceentry.yaml'], RULE)).toBe(true))

  it('file in istio/gateway/ dir → flagged', () =>
    expect(hasRule(['istio/gateway/config.yaml'], RULE)).toBe(true))
  it('file in mesh-gateway/ dir → flagged', () =>
    expect(hasRule(['mesh-gateway/tls.yaml'], RULE)).toBe(true))
  it('file in service-mesh/ with gateway.yaml → flagged', () =>
    expect(hasRule(['service-mesh/gateway.yaml'], RULE)).toBe(true))

  it('kong- prefix → flagged', () =>
    expect(hasRule(['kong-security.yaml'], RULE)).toBe(true))
  it('envoy-gateway- prefix → flagged', () =>
    expect(hasRule(['envoy-gateway-routes.yaml'], RULE)).toBe(true))

  it('generic gateway.yaml NOT in mesh dir NOT flagged', () =>
    expect(hasRule(['config/gateway.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 high match → score 15, risk low', () => {
    const r = scan(['envoy.yaml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('3 different high rules → score 45, risk high', () => {
    const r = scan(['envoy.yaml', 'peer-authentication.yaml', 'spire-server.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('3 files for same high rule → score 45 (hits cap), risk high', () => {
    const r = scan(['envoy.yaml', 'envoy-config.yaml', 'envoy-bootstrap.yaml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('1 medium match → score 8, risk low', () => {
    const r = scan(['teleport.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('1 low match → score 4, risk low', () => {
    const r = scan(['virtualservice.yaml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('score < 20 → low', () => {
    const r = scan(['envoy.yaml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('score ≥ 20 → medium', () => {
    const r = scan(['envoy.yaml', 'teleport.yaml'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })

  it('score ≥ 45 → high', () => {
    const r = scan(['envoy.yaml', 'peer-authentication.yaml', 'spire-server.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score ≥ 70 → critical', () => {
    // 3 high (45) + 4 medium (32) = 77
    const r = scan([
      'envoy.yaml',
      'peer-authentication.yaml',
      'spire-server.conf',
      'teleport.yaml',
      'consul.hcl',
      'cilium.yaml',
      'linkerd-config.yaml',
    ])
    expect(r.riskScore).toBeGreaterThanOrEqual(70)
    expect(r.riskLevel).toBe('critical')
  })

  it('score clamped at 100', () => {
    const manyFiles = Array.from({ length: 20 }, (_, i) => `envoy-config-${i}.yaml`)
    manyFiles.push('peer-authentication.yaml', 'spire-server.conf', 'teleport.yaml', 'consul.hcl', 'cilium.yaml', 'virtualservice.yaml')
    expect(scan(manyFiles).riskScore).toBe(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => expect(scan([]).riskLevel).toBe('none'))
  it('score 4 → low', () => expect(scan(['virtualservice.yaml']).riskLevel).toBe('low'))
  it('score 15 → low', () => expect(scan(['envoy.yaml']).riskLevel).toBe('low'))
  it('score 19 → low', () => {
    // 1 high (15) + 1 low (4) = 19
    const r = scan(['envoy.yaml', 'virtualservice.yaml'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })
  it('score 23 → medium', () => {
    // 1 high (15) + 1 medium (8) = 23
    const r = scan(['envoy.yaml', 'teleport.yaml'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 43 → medium (below 45 boundary)', () => {
    // 1 high (15) + 3 medium (24) + 1 low (4) = 43
    const r = scan([
      'envoy.yaml',
      'teleport.yaml', 'consul.hcl', 'cilium.yaml',
      'virtualservice.yaml',
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
    const r = scan(['envoy.yaml', 'envoy-config.yaml', 'envoy-bootstrap.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'ENVOY_PROXY_SECURITY_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
    expect(r.findings).toHaveLength(1)
  })

  it('firstPath is the first matched path', () => {
    const r = scan(['envoy.yaml', 'envoy-config.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'ENVOY_PROXY_SECURITY_DRIFT')
    expect(f!.matchedPath).toBe('envoy.yaml')
  })
})

// ---------------------------------------------------------------------------
// Finding ordering
// ---------------------------------------------------------------------------

describe('finding ordering', () => {
  it('high before medium before low', () => {
    const r = scan(['envoy.yaml', 'teleport.yaml', 'virtualservice.yaml'])
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
    expect(scan([]).summary).toBe('No service mesh or zero-trust network security configuration drift detected.')
  })

  it('findings → includes finding counts', () => {
    const r = scan(['envoy.yaml', 'teleport.yaml'])
    expect(r.summary).toContain('1 high')
    expect(r.summary).toContain('1 medium')
    expect(r.summary).toContain('envoy proxy security drift')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('full service mesh stack drift → 8 findings', () => {
    const r = scan([
      'peer-authentication.yaml',   // ISTIO_AUTH_POLICY_DRIFT
      'envoy.yaml',                  // ENVOY_PROXY_SECURITY_DRIFT
      'spire-server.conf',           // SPIFFE_SPIRE_DRIFT
      'linkerd-config.yaml',         // LINKERD_SECURITY_POLICY_DRIFT
      'consul.hcl',                  // CONSUL_CONNECT_DRIFT
      'cilium.yaml',                 // CNI_NETWORK_POLICY_DRIFT
      'teleport.yaml',               // ZERO_TRUST_ACCESS_DRIFT
      'virtualservice.yaml',         // MESH_GATEWAY_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(3)
    expect(r.mediumCount).toBe(4)
    expect(r.lowCount).toBe(1)
  })

  it('Istio-only drift → correct risk level', () => {
    const r = scan(['peer-authentication.yaml'])
    expect(r.riskLevel).toBe('low')
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0].ruleId).toBe('ISTIO_AUTH_POLICY_DRIFT')
  })

  it('zero-trust + CNI policy → 2 findings', () => {
    const r = scan(['teleport.yaml', 'cilium.yaml'])
    expect(r.totalFindings).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('registry completeness', () => {
  const expectedRuleIds = [
    'ISTIO_AUTH_POLICY_DRIFT',
    'ENVOY_PROXY_SECURITY_DRIFT',
    'SPIFFE_SPIRE_DRIFT',
    'LINKERD_SECURITY_POLICY_DRIFT',
    'CONSUL_CONNECT_DRIFT',
    'CNI_NETWORK_POLICY_DRIFT',
    'ZERO_TRUST_ACCESS_DRIFT',
    'MESH_GATEWAY_DRIFT',
  ] as const

  it('registry has exactly 8 rules', () => {
    expect(SERVICE_MESH_SECURITY_RULES).toHaveLength(8)
  })

  for (const ruleId of expectedRuleIds) {
    it(`registry contains ${ruleId}`, () => {
      expect(SERVICE_MESH_SECURITY_RULES.some((r) => r.id === ruleId)).toBe(true)
    })
  }

  it('all rules have non-empty descriptions and recommendations', () => {
    for (const rule of SERVICE_MESH_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })
})
