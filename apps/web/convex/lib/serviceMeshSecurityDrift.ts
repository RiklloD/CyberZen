// WS-72 — Service Mesh & Zero-Trust Network Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to service mesh and zero-trust network security configuration files. This
// scanner focuses on the *sidecar proxy and CNI policy layer* — the configs
// that enforce mTLS, fine-grained L7 authorization, workload attestation, and
// zero-trust access between services. Drift here can silently downgrade mTLS
// from STRICT to PERMISSIVE, open authorization policies, or break workload
// attestation for an entire cluster.
//
// DISTINCT from:
//   WS-63  containerHardeningDriftResults — Kubernetes NetworkPolicy (base k8s
//                                           resource), RBAC, PodSecurity —
//                                           the k8s control plane security layer
//   WS-67  runtimeSecurityDriftResults    — OPA/Rego policies, Kyverno, Falco,
//                                           seccomp/AppArmor — runtime enforcement
//                                           of container behaviour, not service-to-
//                                           service network policy
//   WS-68  networkFirewallDriftResults    — host-level firewall (iptables/nftables/
//                                           HAProxy/UFW/VPN) — the L3/L4 perimeter
//                                           below the service mesh proxy layer
//
// WS-72 vs WS-63: WS-63 detects k8s NetworkPolicy (the core resource). WS-72
//   detects Istio PeerAuthentication/AuthorizationPolicy (Istio CRDs), Linkerd
//   Server/ServerAuthorization (Linkerd CRDs), and CNI plugin-specific policies
//   (Cilium CiliumNetworkPolicy, Calico NetworkPolicy, Antrea ClusterNetworkPolicy)
//   that live in dedicated policy directories.
//
// WS-72 vs WS-67: WS-67 covers OPA Rego (runtime general enforcement). WS-72
//   covers Istio/Envoy/Linkerd configuration — the service mesh control plane,
//   not a general policy engine.
//
// WS-72 vs WS-68: WS-68 covers host-level network firewalls (iptables/nftables/
//   UFW/VPN). WS-72 covers the sidecar proxy layer (Envoy bootstrap, Istio
//   control plane) and zero-trust access proxies (Teleport/Pomerium/Cloudflare
//   Tunnel) that operate above the host network level.
//
// Covered rule groups (8 rules):
//
//   ISTIO_AUTH_POLICY_DRIFT        — Istio PeerAuthentication/AuthorizationPolicy CRDs
//   ENVOY_PROXY_SECURITY_DRIFT     — Envoy static bootstrap and xDS security configs
//   SPIFFE_SPIRE_DRIFT             — SPIFFE/SPIRE workload attestation configs
//   LINKERD_SECURITY_POLICY_DRIFT  — Linkerd Server/ServerAuthorization/AuthorizationPolicy
//   CONSUL_CONNECT_DRIFT           — Consul service mesh intentions and ACL policies
//   CNI_NETWORK_POLICY_DRIFT       — Cilium/Calico/Antrea CNI plugin policies  ← user contribution
//   ZERO_TRUST_ACCESS_DRIFT        — Teleport / Pomerium / Cloudflare Tunnel configs
//   MESH_GATEWAY_DRIFT             — Service mesh gateway and VirtualService TLS configs
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–71 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Istio CRD YAML files are detected by directory context (istio/, mesh-policy/)
//     or unambiguous exact basenames (peer-authentication.yaml, authz-policy.yaml).
//     Generic .yaml files in k8s/ are NOT flagged here (WS-63 covers those).
//   • Envoy configs are unambiguous by exact basename (envoy.yaml, envoy-config.yaml)
//     or envoy/ directory context.
//   • SPIRE server/agent configs are unambiguous by exact basename.
//   • Consul Connect configs are gated on consul/ directory or consul- prefix to
//     avoid false positives from generic config.hcl files.
//   • Teleport.yaml and pomerium.yaml are unambiguous globally.
//   • CNI plugin policies require careful scoping — the user contribution handles
//     the disambiguation from WS-63 base NetworkPolicy.
//
// Exports:
//   isCniNetworkPolicyConfig       — user contribution point (see JSDoc below)
//   SERVICE_MESH_SECURITY_RULES    — readonly rule registry
//   scanServiceMeshSecurityDrift   — main scanner, returns ServiceMeshSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ServiceMeshSecurityRuleId =
  | 'ISTIO_AUTH_POLICY_DRIFT'
  | 'ENVOY_PROXY_SECURITY_DRIFT'
  | 'SPIFFE_SPIRE_DRIFT'
  | 'LINKERD_SECURITY_POLICY_DRIFT'
  | 'CONSUL_CONNECT_DRIFT'
  | 'CNI_NETWORK_POLICY_DRIFT'
  | 'ZERO_TRUST_ACCESS_DRIFT'
  | 'MESH_GATEWAY_DRIFT'

export type ServiceMeshSecuritySeverity = 'high' | 'medium' | 'low'
export type ServiceMeshSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type ServiceMeshSecurityDriftFinding = {
  ruleId: ServiceMeshSecurityRuleId
  severity: ServiceMeshSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type ServiceMeshSecurityDriftResult = {
  riskScore: number
  riskLevel: ServiceMeshSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: ServiceMeshSecurityDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/', '.git/', 'dist/', 'build/', '.next/', '.nuxt/',
  'vendor/', 'bower_components/', 'coverage/', '__pycache__/',
  '.terraform/', 'cdk.out/', '.cdk/', '.gradle/', '.m2/',
  'target/', 'out/', '.idea/', '.vscode/', '.cache/',
]

const HIGH_PENALTY_PER = 15
const HIGH_PENALTY_CAP = 45
const MED_PENALTY_PER  = 8
const MED_PENALTY_CAP  = 25
const LOW_PENALTY_PER  = 4
const LOW_PENALTY_CAP  = 15

// ---------------------------------------------------------------------------
// Detection helpers — ISTIO_AUTH_POLICY_DRIFT
// ---------------------------------------------------------------------------

// Unambiguous Istio security CRD basenames
const ISTIO_AUTH_EXACT = new Set([
  'peer-authentication.yaml', 'peer-authentication.yml',
  'authorization-policy.yaml', 'authorization-policy.yml',
  'request-authentication.yaml', 'request-authentication.yml',
  'authz-policy.yaml', 'authz-policy.yml',
  'peerauthentication.yaml', 'peerauthentication.yml',
  'authorizationpolicy.yaml', 'authorizationpolicy.yml',
  // Istio service entry and destination rule affect mTLS routing
  'destination-rule.yaml', 'destination-rule.yml',
  'destinationrule.yaml', 'destinationrule.yml',
])

const ISTIO_DIRS = [
  'istio/', 'istio-config/', 'mesh-policy/', 'mesh-security/',
  'istio/security/', 'istio-manifests/', 'service-mesh/', 'service-mesh/istio/',
]

function isIstioPolicyFile(pathLower: string, base: string): boolean {
  // k8s manifest dirs — skip first (WS-63 territory)
  if (pathLower.includes('k8s/') || pathLower.includes('kubernetes/') ||
      pathLower.includes('kustomize/') || pathLower.includes('helm/') ||
      pathLower.includes('charts/')) {
    return false
  }
  if (ISTIO_AUTH_EXACT.has(base)) return true
  for (const dir of ISTIO_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('peer-auth') || base.startsWith('authz-policy') ||
      base.startsWith('istio-auth') || base.startsWith('istio-policy')) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — ENVOY_PROXY_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const ENVOY_EXACT = new Set([
  'envoy.yaml', 'envoy.yml', 'envoy.json',
  'envoy-config.yaml', 'envoy-config.yml',
  'envoy-bootstrap.yaml', 'envoy-bootstrap.yml',
  'envoy-static.yaml', 'envoy-static.yml',
  'envoy-proxy.yaml', 'envoy-proxy.yml',
  'xds-config.yaml', 'xds-config.yml',
  'lds.yaml', 'cds.yaml', 'rds.yaml',             // xDS API fragment files
])

const ENVOY_DIRS = [
  'envoy/', 'envoy-config/', 'envoy-proxy/', 'xds/',
  'envoy/config/', 'service-mesh/envoy/',
]

function isEnvoyProxyFile(pathLower: string, base: string): boolean {
  if (ENVOY_EXACT.has(base)) return true
  for (const dir of ENVOY_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('envoy-') || base.startsWith('envoy_')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — SPIFFE_SPIRE_DRIFT
// ---------------------------------------------------------------------------

const SPIRE_EXACT = new Set([
  'spire-server.conf', 'spire-agent.conf',
  'spire-server.yaml', 'spire-server.yml',
  'spire-agent.yaml', 'spire-agent.yml',
  'spire-config.yaml', 'spire-config.yml',
  'spiffe-trust.yaml', 'spiffe-trust.yml',
  'trust-bundle.yaml', 'trust-bundle.yml', 'trust-bundle.json',
  'spire.conf',
])

const SPIRE_DIRS = ['spire/', 'spiffe/', 'spire-config/', '.spire/']

function isSpireSpiffeFile(pathLower: string, base: string): boolean {
  if (SPIRE_EXACT.has(base)) return true
  for (const dir of SPIRE_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  if (base.startsWith('spire-') || base.startsWith('spiffe-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — LINKERD_SECURITY_POLICY_DRIFT
// ---------------------------------------------------------------------------

const LINKERD_UNGATED_EXACT = new Set([
  'linkerd-proxy.yaml', 'linkerd-proxy.yml',
  'linkerd-config.yaml', 'linkerd-config.yml',
  'linkerd-control-plane.yaml',
  'serverauthorization.yaml', 'serverauthorization.yml',
  'server-authorization.yaml', 'server-authorization.yml',
])

const LINKERD_DIRS = ['linkerd/', 'linkerd-config/', 'service-mesh/linkerd/']

function isLinkerdPolicyFile(pathLower: string, base: string): boolean {
  if (LINKERD_UNGATED_EXACT.has(base)) return true
  for (const dir of LINKERD_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('linkerd-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — CONSUL_CONNECT_DRIFT
// ---------------------------------------------------------------------------

const CONSUL_EXACT = new Set([
  'consul.hcl', 'consul.json', 'consul.yaml', 'consul.yml',
  'consul-config.hcl', 'consul-config.json', 'consul-config.yaml',
  'intentions.json', 'intentions.yaml', 'intentions.hcl',
  'service-intentions.yaml', 'service-intentions.yml',
  'acl-policy.hcl', 'acl-policy.json',
  'connect-proxy.hcl', 'connect-proxy.json',
])

const CONSUL_DIRS = [
  'consul/', 'consul-config/', 'consul/config/',
  'consul/intentions/', 'consul/policies/', 'service-mesh/consul/',
]

function isConsulConnectFile(pathLower: string, base: string): boolean {
  if (CONSUL_EXACT.has(base)) return true
  for (const dir of CONSUL_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  if (base.startsWith('consul-') || base.startsWith('consul_')) return true
  return false
}

// ---------------------------------------------------------------------------
// CNI_NETWORK_POLICY_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isCniNetworkPolicyConfig — determines whether a file path is a CNI plugin-
 * specific network policy configuration that is NOT already covered by:
 *   - WS-63 (containerHardeningDrift): base Kubernetes NetworkPolicy resources
 *     committed as part of k8s manifest sets (k8s/, manifests/, helm/ dirs)
 *
 * Target files: Cilium CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy CRDs,
 * Calico NetworkPolicy/GlobalNetworkPolicy CRDs, Antrea ClusterNetworkPolicy
 * resources — when these live in dedicated CNI policy directories rather than
 * bundled k8s manifests. Also covers CNI plugin configuration files for the
 * network plugin itself (cilium-config.yaml, calico.yaml at CNI install level).
 *
 * Core ambiguity: "network-policy.yaml" can be:
 *   (a) A base k8s NetworkPolicy manifest — already covered by WS-63
 *   (b) A Cilium CiliumNetworkPolicy — target for WS-72 if in cilium/ dir
 *   (c) A Calico NetworkPolicy/GlobalNetworkPolicy — target for WS-72 if in calico/ dir
 *
 * Design trade-offs to consider:
 *
 *   (a) k8s/helm directory exclusion: files inside k8s/, kubernetes/,
 *       kustomize/, helm/, charts/, manifests/ are owned by WS-63. Even if
 *       they are Cilium CRDs, WS-63 covers the k8s manifest layer. WS-72
 *       targets standalone CNI policy directories.
 *
 *   (b) Cilium detection: exact filenames cilium-config.yaml, cilium.yaml,
 *       ciliumnetworkpolicy.yaml, or files in cilium/ / cilium-config/
 *       directories. The CNI configuration (cilium-config ConfigMap) is a
 *       different artifact from the NetworkPolicy CRDs.
 *
 *   (c) Calico detection: exact filenames calico.yaml (full install manifest
 *       is borderline — target when in calico/ dir), calicoctl.cfg,
 *       calico-node.yaml in calico/ dirs; GlobalNetworkPolicy files.
 *
 *   (d) Antrea detection: antrea.yaml/antrea-config.yaml exact + antrea/ dir;
 *       ClusterNetworkPolicy YAML files in antrea-policies/ directories.
 *
 * Implement to return true for CNI plugin security policy files outside k8s
 * manifest directories and false for base k8s NetworkPolicy resources already
 * covered by WS-63.
 */
export function isCniNetworkPolicyConfig(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

  // k8s manifest directories — skip (WS-63 covers these)
  const K8S_DIRS = ['k8s/', 'kubernetes/', 'kustomize/', 'helm/', 'charts/', 'manifests/']
  for (const dir of K8S_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  // Cilium — exact filenames are unambiguous outside k8s dirs
  const CILIUM_EXACT = new Set([
    'cilium.yaml', 'cilium.yml',
    'cilium-config.yaml', 'cilium-config.yml',
    'ciliumnetworkpolicy.yaml', 'ciliumnetworkpolicy.yml',
    'cilium-network-policy.yaml', 'cilium-network-policy.yml',
    'clusterwidenetworkpolicy.yaml', 'clusterwidenetworkpolicy.yml',
    'cni-config.json',                             // CNI plugin config file
  ])
  if (CILIUM_EXACT.has(base)) return true

  // Calico — exact filenames outside k8s dirs
  const CALICO_EXACT = new Set([
    'calicoctl.cfg',
    'calico-config.yaml', 'calico-config.yml',
    'globalnetworkpolicy.yaml', 'globalnetworkpolicy.yml',
    'global-network-policy.yaml', 'global-network-policy.yml',
    'bgpconfiguration.yaml', 'bgpconfiguration.yml',
    'felixconfiguration.yaml', 'felixconfiguration.yml',
  ])
  if (CALICO_EXACT.has(base)) return true

  // Antrea — exact filenames outside k8s dirs
  const ANTREA_EXACT = new Set([
    'antrea.yaml', 'antrea.yml',
    'antrea-config.yaml', 'antrea-config.yml',
    'antreaagentconfig.yaml', 'antreaagentconfig.yml',
    'clusternetworkpolicy.yaml', 'clusternetworkpolicy.yml',
  ])
  if (ANTREA_EXACT.has(base)) return true

  // CNI directory context — any policy YAML in dedicated CNI dirs
  const CNI_DIRS = [
    'cilium/', 'cilium-config/', 'cilium-policies/',
    'calico/', 'calico-config/', 'calico-policies/',
    'antrea/', 'antrea-config/', 'antrea-policies/',
    'cni/', 'cni-config/', 'network-policies/',
  ]
  for (const dir of CNI_DIRS) {
    if (pathLower.includes(dir) && (ext === '.yaml' || ext === '.yml' || ext === '.json')) {
      return true
    }
  }

  // cilium-/calico-/antrea- prefix patterns
  if (base.startsWith('cilium-') || base.startsWith('calico-') || base.startsWith('antrea-')) {
    if (ext === '.yaml' || ext === '.yml' || ext === '.json') return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — ZERO_TRUST_ACCESS_DRIFT
// ---------------------------------------------------------------------------

const ZERO_TRUST_UNGATED = new Set([
  'cloudflared.yaml', 'cloudflared.yml', 'cloudflared.json',
  'teleport.yaml', 'teleport.yml',
  'teleport-config.yaml', 'teleport-config.yml',
  'pomerium.yaml', 'pomerium.yml',
  'pomerium-config.yaml', 'pomerium-config.yml',
  'beyondcorp-config.yaml', 'iap-config.yaml',
  'tailscale-acl.json', 'tailscale-acl.yaml', 'tailscale.json',
])

const ZERO_TRUST_DIRS = [
  'cloudflare/', 'cloudflared/', 'teleport/', 'teleport-config/',
  'pomerium/', 'zero-trust/', 'ztna/', 'access-proxy/',
]

function isZeroTrustAccessFile(pathLower: string, base: string): boolean {
  if (ZERO_TRUST_UNGATED.has(base)) return true
  for (const dir of ZERO_TRUST_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('teleport-') || base.startsWith('pomerium-') ||
      base.startsWith('cloudflared-') || base.startsWith('tailscale-')) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — MESH_GATEWAY_DRIFT
// ---------------------------------------------------------------------------

const GATEWAY_EXACT = new Set([
  'gateway.yaml', 'gateway.yml',                  // gated on istio/mesh dir
  'virtual-service.yaml', 'virtual-service.yml',
  'virtualservice.yaml', 'virtualservice.yml',
  'service-entry.yaml', 'service-entry.yml',
  'serviceentry.yaml', 'serviceentry.yml',
  'envoy-gateway.yaml', 'envoy-gateway.yml',
  'kong.yaml', 'kong.yml',
  'kong-plugin.yaml', 'kong-plugin.yml',
])

const GATEWAY_UNGATED = new Set([
  'virtual-service.yaml', 'virtual-service.yml',
  'virtualservice.yaml', 'virtualservice.yml',
  'service-entry.yaml', 'service-entry.yml',
  'serviceentry.yaml', 'serviceentry.yml',
  'envoy-gateway.yaml', 'envoy-gateway.yml',
  'kong-plugin.yaml', 'kong-plugin.yml',
])

const GATEWAY_DIRS = [
  'istio/gateway/', 'mesh-gateway/', 'api-gateway/',
  'service-mesh/gateway/', 'envoy-gateway/',
]

function isMeshGatewayFile(pathLower: string, base: string): boolean {
  if (GATEWAY_UNGATED.has(base)) return true
  for (const dir of GATEWAY_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  // In istio/ or service-mesh/ dir, gateway.yaml / virtualservice.yaml are relevant
  if ((pathLower.includes('istio/') || pathLower.includes('service-mesh/')) &&
      GATEWAY_EXACT.has(base)) {
    return true
  }
  if (base.startsWith('kong-') || base.startsWith('envoy-gateway-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type ServiceMeshSecurityRule = {
  id: ServiceMeshSecurityRuleId
  severity: ServiceMeshSecuritySeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const SERVICE_MESH_SECURITY_RULES: readonly ServiceMeshSecurityRule[] = [
  {
    id: 'ISTIO_AUTH_POLICY_DRIFT',
    severity: 'high',
    description: 'Istio PeerAuthentication, AuthorizationPolicy, or RequestAuthentication CRD files were modified. PeerAuthentication controls mTLS mode — changing from STRICT to PERMISSIVE silently allows unencrypted traffic; AuthorizationPolicy changes can open access between services that should be isolated.',
    recommendation: 'Verify that PeerAuthentication mode remains STRICT for all production namespaces, that AuthorizationPolicy DENY rules were not removed, and that RequestAuthentication JWT issuer configs were not changed to accept additional token issuers. Istio security policy changes require a security review before merge.',
    matches: (p, b) => isIstioPolicyFile(p, b),
  },
  {
    id: 'ENVOY_PROXY_SECURITY_DRIFT',
    severity: 'high',
    description: 'Envoy proxy static bootstrap or xDS security configuration files were modified. Envoy configuration controls TLS termination, cluster connection settings, and filter chain security — changes can disable TLS verification, allow plaintext connections to upstream clusters, or remove security filter chains.',
    recommendation: 'Confirm that TLS context configurations for clusters and listeners still require certificate verification, transport_socket configurations were not replaced with plaintext alternatives, and that jwt_authn or ext_authz filters were not removed from filter chains. Envoy config changes should be reviewed by the platform security team.',
    matches: (p, b) => isEnvoyProxyFile(p, b),
  },
  {
    id: 'SPIFFE_SPIRE_DRIFT',
    severity: 'high',
    description: 'SPIFFE/SPIRE workload attestation or trust bundle configuration files were modified. SPIRE controls how workload identity is issued — changes to attestation policies can allow unauthorized workloads to obtain valid SVIDs, or trust bundle changes can cause all mTLS connections to fail.',
    recommendation: 'Verify that workload attestation plugins still require strong attestation (not allow-all), that trust bundle rotation was performed through the proper procedure, and that SPIRE server signing keys were not replaced outside of an approved rotation window. SPIRE config changes should be reviewed by the security infrastructure team.',
    matches: (p, b) => isSpireSpiffeFile(p, b),
  },
  {
    id: 'LINKERD_SECURITY_POLICY_DRIFT',
    severity: 'medium',
    description: 'Linkerd Server, ServerAuthorization, or AuthorizationPolicy CRD files were modified. Linkerd policy controls which workloads are permitted to communicate with each service — changes can open unauthorized communication paths or bypass mTLS between services.',
    recommendation: 'Confirm that ServerAuthorization resources still restrict access to the intended identities, that new Server resources were not added without corresponding ServerAuthorizations, and that the mesh mode was not changed from strict to permissive. Linkerd policy changes should be reviewed alongside the service dependency graph.',
    matches: (p, b) => isLinkerdPolicyFile(p, b),
  },
  {
    id: 'CONSUL_CONNECT_DRIFT',
    severity: 'medium',
    description: 'Consul service mesh intention, ACL policy, or Connect proxy configuration files were modified. Service intentions control which services are allowed to communicate — changes can open intentionally closed service-to-service paths or weaken ACL policies protecting sensitive services.',
    recommendation: 'Verify that no deny intentions were removed or converted to allow, that ACL policies were not broadened to grant access to sensitive services, and that Connect proxy configuration changes do not disable mTLS. Intention and ACL changes should be reviewed by the service owner and security team.',
    matches: (p, b) => isConsulConnectFile(p, b),
  },
  {
    id: 'CNI_NETWORK_POLICY_DRIFT',
    severity: 'medium',
    description: 'CNI plugin-specific network policy configuration files (Cilium CiliumNetworkPolicy, Calico GlobalNetworkPolicy, Antrea ClusterNetworkPolicy) were modified. These policies operate at the kernel level below the service mesh and can override or conflict with higher-level mesh policies.',
    recommendation: 'Review whether any egress or ingress rules were broadened, deny policies were removed, or cluster-wide default-deny policies were changed. CNI policy changes should be validated against the service communication model and tested in a non-production cluster first.',
    matches: (p) => isCniNetworkPolicyConfig(p),
  },
  {
    id: 'ZERO_TRUST_ACCESS_DRIFT',
    severity: 'medium',
    description: 'Zero-trust access proxy configuration files (Cloudflare Tunnel, Teleport, Pomerium, Tailscale ACL) were modified. These tools control which users and services can reach internal resources — changes can open access to previously restricted services or bypass multi-factor authentication requirements.',
    recommendation: 'Confirm that access rules were not broadened, that MFA requirements were not removed from privileged access paths, and that tunnel configurations were not changed to expose additional internal services. Zero-trust config changes should be reviewed by the security team and tested before production deployment.',
    matches: (p, b) => isZeroTrustAccessFile(p, b),
  },
  {
    id: 'MESH_GATEWAY_DRIFT',
    severity: 'low',
    description: 'Service mesh gateway or VirtualService configuration files were modified. Gateway and VirtualService resources control ingress TLS termination and traffic routing — changes can expose internal services, downgrade TLS modes, or misconfigure traffic routing in ways that bypass security policies.',
    recommendation: 'Verify that gateway TLS mode was not changed from MUTUAL or SIMPLE to PASSTHROUGH, that VirtualService routing rules were not changed to bypass authentication filters, and that no new ports were exposed without corresponding security policies. Gateway config changes should be reviewed by the platform team.',
    matches: (p, b) => isMeshGatewayFile(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: ServiceMeshSecuritySeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): ServiceMeshSecurityRiskLevel {
  if (score === 0)  return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanServiceMeshSecurityDrift(filePaths: string[]): ServiceMeshSecurityDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<ServiceMeshSecurityRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of SERVICE_MESH_SECURITY_RULES) {
      if (rule.matches(pathLower, base, ext)) {
        const existing = accumulated.get(rule.id)
        if (existing) {
          existing.count += 1
        } else {
          accumulated.set(rule.id, { firstPath: path, count: 1 })
        }
      }
    }
  }

  if (accumulated.size === 0) return emptyResult()

  const SEVERITY_ORDER: Record<ServiceMeshSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: ServiceMeshSecurityDriftFinding[] = []

  for (const rule of SERVICE_MESH_SECURITY_RULES) {
    const match = accumulated.get(rule.id)
    if (!match) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    match.firstPath,
      matchCount:     match.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

  return { riskScore, riskLevel, totalFindings: findings.length, highCount, mediumCount, lowCount, findings, summary }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): ServiceMeshSecurityDriftResult {
  return {
    riskScore: 0, riskLevel: 'none',
    totalFindings: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    findings: [], summary: 'No service mesh or zero-trust network security configuration drift detected.',
  }
}

function buildSummary(
  level: ServiceMeshSecurityRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: ServiceMeshSecurityDriftFinding[],
): string {
  if (level === 'none') return 'No service mesh or zero-trust network security configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'mesh security config'

  return `Service mesh and zero-trust network security drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure mTLS enforcement and network authorization policies remain intact.`
}
