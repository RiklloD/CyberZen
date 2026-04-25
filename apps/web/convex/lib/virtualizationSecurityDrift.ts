// WS-92 — Virtualization & Hypervisor Security Configuration Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to hypervisor-level and VM management security configuration.
//
// Distinct from:
//   WS-63 (Dockerfile / k8s RBAC / container runtime AppArmor–seccomp policies)
//   WS-68 (host-level iptables / nftables / VPN)
//   WS-85 (backup agents: rclone / restic / Borg)
//   WS-87 (NFS / SMB / storage encryption)
//   WS-72 (service mesh: Istio / Envoy / Cilium)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '')
}

const VENDOR_DIRS = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '.cache/',
  '.npm/', '.yarn/', '__pycache__/', '.venv/', 'venv/', 'target/',
]

function isVendorPath(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Rule 1: VSPHERE_ESXI_SECURITY_DRIFT (high)
// ---------------------------------------------------------------------------
// VMware vSphere / ESXi / vCenter configuration files.  Changes here can
// affect ESXi lockdown mode, vCenter permissions, HA/DRS settings, and
// encrypted vMotion policies.

const VSPHERE_UNGATED = new Set([
  'vmware.conf', 'vsphere.conf', 'vcenter.conf', 'esxi.conf',
  'vpxa.cfg', 'vpxd.cfg', 'esx.conf', 'vmca.cfg',
  'vsphere-ha.cfg', 'vpxd-profiler.cfg', 'vcsa.conf',
  'vrealize.conf', 'vcd.conf', 'vmkernel.conf',
])

const VSPHERE_DIRS = [
  'vsphere/', '.vsphere/', 'vcenter/', 'vmware/', 'esxi/',
  'vmc/', 'vcd/', 'vxrail/', 'vrealize/', 'vro/',
  'vsphere-config/', 'vcenter-config/', 'vmware-config/',
]

function isVsphereEsxiConfig(path: string, base: string): boolean {
  if (VSPHERE_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('vsphere-') ||
    base.startsWith('vcenter-') ||
    base.startsWith('vmware-') ||
    base.startsWith('esxi-') ||
    base.startsWith('vro-') ||
    base.startsWith('vrealize-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|xml|toml)$/.test(base)
  }

  return VSPHERE_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|xml|toml|env)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: LIBVIRT_KVM_SECURITY_DRIFT (high)
// ---------------------------------------------------------------------------
// KVM / QEMU / libvirt management configuration.  These files control VM
// resource limits, network isolation, storage permissions, and live-migration
// authentication — misconfig can allow VM-to-VM breakout or privilege escape.

const LIBVIRT_UNGATED = new Set([
  'libvirtd.conf', 'libvirt.conf', 'virtlogd.conf',
  'virtnodedevd.conf', 'virtproxyd.conf', 'virtqemud.conf',
  'virtstoraged.conf', 'virtnetworkd.conf',
])

const LIBVIRT_DIRS = [
  'libvirt/', '.libvirt/', 'qemu/', 'kvm/', 'libvirt-config/',
  'etc/libvirt/', 'etc/qemu/', 'kvm-config/', 'qemu-config/',
]

const LIBVIRT_GATED_EXACT = new Set([
  'qemu.conf', 'networks.xml', 'storage.xml', 'default.xml',
  'network.xml', 'pool.xml', 'domain.xml',
])

function isLibvirtKvmConfig(path: string, base: string): boolean {
  if (LIBVIRT_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (LIBVIRT_GATED_EXACT.has(base) && LIBVIRT_DIRS.some((d) => low.includes(d))) return true

  if (
    base.startsWith('libvirt-') ||
    base.startsWith('kvm-') ||
    base.startsWith('qemu-') ||
    base.startsWith('virt-')
  ) {
    return /\.(conf|cfg|xml|json|yaml|yml)$/.test(base)
  }

  return LIBVIRT_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|xml|json|yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: DOCKER_DAEMON_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------
// Docker daemon and containerd host-level configuration.  daemon.json
// controls TLS enforcement, registry mirrors, allowed insecure registries, and
// log drivers — not to be confused with WS-63 Dockerfile / runtime policy
// detection.

const DOCKER_DAEMON_UNGATED = new Set([
  'docker-daemon.json', 'docker-daemon.yaml', 'docker-daemon.yml',
  'containerd-config.toml', 'docker-daemon.env',
])

const DOCKER_DAEMON_DIRS = [
  'docker/', '.docker/', 'containerd/', 'etc/docker/', 'etc/containerd/',
  'docker-config/', 'containerd-config/', '.containerd/',
]

const DOCKER_DAEMON_GATED_EXACT = new Set([
  'daemon.json', 'config.toml', 'config.json',
])

function isDockerDaemonConfig(path: string, base: string): boolean {
  if (DOCKER_DAEMON_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (DOCKER_DAEMON_GATED_EXACT.has(base) && DOCKER_DAEMON_DIRS.some((d) => low.includes(d))) return true

  if (
    base.startsWith('docker-config-') ||
    base.startsWith('containerd-') ||
    base.startsWith('dockerd-')
  ) {
    return /\.(json|yaml|yml|toml|conf|env)$/.test(base)
  }

  return DOCKER_DAEMON_DIRS.some((d) => low.includes(d)) &&
    /\.(json|yaml|yml|toml|conf|env)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: PROXMOX_CLUSTER_SECURITY_DRIFT (high)
// ---------------------------------------------------------------------------
// Proxmox VE cluster and node configuration.  datacenter.cfg controls VM
// firewall defaults, two-factor auth, and HA behaviour; corosync.conf controls
// cluster quorum and encrypted communication.

const PROXMOX_UNGATED = new Set([
  'datacenter.cfg', 'pve.conf', 'proxmox.conf',
  'pve-manager.conf', 'ha-manager.cfg', 'ha-resources.cfg',
])

const PROXMOX_DIRS = [
  'proxmox/', 'pve/', 'proxmox-config/', 'pve-config/',
  'proxmox-ve/', 'pve-manager/', 'etc/pve/',
]

const PROXMOX_GATED_EXACT = new Set([
  'corosync.conf', 'storage.cfg', 'nodes.cfg', 'users.cfg',
  'access.cfg', 'firewall.cfg', 'cluster.cfg',
])

function isProxmoxClusterConfig(path: string, base: string): boolean {
  if (PROXMOX_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (PROXMOX_GATED_EXACT.has(base) && PROXMOX_DIRS.some((d) => low.includes(d))) return true

  if (base.startsWith('proxmox-') || base.startsWith('pve-')) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return PROXMOX_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: XEN_XENSERVER_DRIFT (medium)
// ---------------------------------------------------------------------------
// Xen hypervisor, XenServer, and XCP-ng configuration.  xl.conf/xend.conf
// control domain isolation, CPU/memory allocation, and toolstack behaviour.

const XEN_UNGATED = new Set([
  'xend.conf', 'xl.conf', 'xen.conf', 'xen4.conf',
  'xapi.conf', 'xen-domains.conf', 'xenguest.cfg',
  'xen-balloon.conf', 'xen-watchdog.conf',
])

const XEN_DIRS = [
  'xen/', 'xenserver/', 'xcp-ng/', 'xen-config/', 'xapi/',
  'xcp/', 'xcpng/', 'xen-tools/',
]

function isXenXenserverConfig(path: string, base: string): boolean {
  if (XEN_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('xen-') ||
    base.startsWith('xenserver-') ||
    base.startsWith('xcp-') ||
    base.startsWith('xapi-')
  ) {
    return /\.(conf|cfg|xml|json|yaml|yml)$/.test(base)
  }

  return XEN_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|xml|json|yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: HYPERV_SECURITY_DRIFT (medium)
// ---------------------------------------------------------------------------
// Microsoft Hyper-V and Windows virtualization configuration.

const HYPERV_UNGATED = new Set([
  'hyperv-config.xml', 'hyper-v-config.xml', 'hyperv-settings.xml',
  'hyperv.conf', 'hyper-v.conf', 'hyperv-network.xml',
  'vmms.conf', 'hyperv-policy.xml', 'hyperv-manager.conf',
])

const HYPERV_DIRS = [
  'hyperv/', 'hyper-v/', 'hyperv-config/', 'microsoft-hyperv/',
  'hyperv-settings/', 'vm-config/', 'hypervconfig/',
]

function isHyperVConfig(path: string, base: string): boolean {
  if (HYPERV_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('hyperv-') || base.startsWith('hyper-v-')) {
    return /\.(xml|json|yaml|yml|conf|cfg|ps1)$/.test(base)
  }

  return HYPERV_DIRS.some((d) => low.includes(d)) &&
    /\.(xml|json|yaml|yml|conf|cfg|ps1)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: VM_CONSOLE_ACCESS_DRIFT (medium) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures remote console access to virtual
// machines (VNC, SPICE, RDP, serial console).  Misconfigured VM console
// access (e.g. VNC without authentication, SPICE without TLS) can allow
// unauthorised VM takeover without going through the hypervisor API.
//
// Trade-offs to consider:
//   - spice.conf / vnc.conf are common names used by multiple tools
//   - Gate on VM-management directory context to reduce false positives
//   - Ungated prefix patterns (spice-*, vnc-*) are safe because they are
//     specific to the protocols even without directory context

const VM_CONSOLE_DIRS = [
  'spice/', 'vnc/', 'console/', 'vm-console/', 'virt-manager/',
  'qemu/', 'libvirt/', 'kvm/', 'proxmox/', 'pve/', 'xen/',
  'hyperv/', 'vsphere/', 'vm/', 'vms/', 'virtual-machines/',
]

const VM_CONSOLE_UNGATED_EXACT = new Set([
  'spice-vdagent.conf', 'spice-webdavd.conf',
  'virt-manager.conf', 'virt-viewer.conf',
  'qemu-display.conf', 'vm-console.conf',
])

export function isVmConsoleAccessConfig(path: string, base: string): boolean {
  if (VM_CONSOLE_UNGATED_EXACT.has(base)) return true

  const low = path.toLowerCase()

  // Prefix-ungated: spice-* and vnc-* are protocol-specific enough
  if (base.startsWith('spice-') || base.startsWith('vnc-') || base.startsWith('serial-console-')) {
    return /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
  }

  // Generic console/vnc/spice names gated on VM-management directories
  if (
    (base === 'spice.conf' || base === 'vnc.conf' || base === 'console.conf' ||
     base === 'rdp.conf' || base === 'vnc.json' || base === 'spice.json')
  ) {
    return VM_CONSOLE_DIRS.some((d) => low.includes(d))
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: VIRTUAL_SWITCH_SDN_DRIFT (low)
// ---------------------------------------------------------------------------
// Open vSwitch and software-defined networking configs for the hypervisor
// data plane.  OVS controls VLAN trunking, VXLAN tunnelling, flow tables,
// and ingress-rate limiting between VMs.

const OVS_UNGATED = new Set([
  'ovs-vswitchd.conf', 'ovsdb.conf', 'openvswitch.conf',
  'ovs.conf', 'ovs-config.yaml', 'ovs-config.yml',
  'nsx-manager.conf', 'nsx.conf', 'nsx-edge.conf',
])

const SDN_DIRS = [
  'ovs/', 'openvswitch/', 'nsx/', 'sdn/', 'virtual-network/',
  'vswitch/', 'vxlan/', 'vnet/', 'ovs-config/', 'openvswitch-config/',
]

function isVirtualSwitchSdnConfig(path: string, base: string): boolean {
  if (OVS_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('ovs-') ||
    base.startsWith('openvswitch-') ||
    base.startsWith('nsx-') ||
    base.startsWith('sdn-') ||
    base.startsWith('vswitch-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return SDN_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml|xml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type VirtSecRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: VirtSecRule[] = [
  {
    id: 'VSPHERE_ESXI_SECURITY_DRIFT',
    severity: 'high',
    description: 'VMware vSphere / ESXi / vCenter security configuration modified.',
    recommendation: 'Review ESXi lockdown mode, vCenter role assignments, and encrypted-vMotion policies after each change.',
    match: isVsphereEsxiConfig,
  },
  {
    id: 'LIBVIRT_KVM_SECURITY_DRIFT',
    severity: 'high',
    description: 'KVM / QEMU / libvirt host security configuration modified.',
    recommendation: 'Audit libvirtd TLS settings, UNIX socket ACLs, SASL authentication, and network isolation rules.',
    match: isLibvirtKvmConfig,
  },
  {
    id: 'DOCKER_DAEMON_CONFIG_DRIFT',
    severity: 'high',
    description: 'Docker daemon or containerd host configuration modified.',
    recommendation: 'Verify TLS enforcement, insecure-registries list, log-driver settings, and user-namespace remapping in daemon.json.',
    match: isDockerDaemonConfig,
  },
  {
    id: 'PROXMOX_CLUSTER_SECURITY_DRIFT',
    severity: 'high',
    description: 'Proxmox VE cluster or node security configuration modified.',
    recommendation: 'Review datacenter.cfg firewall defaults, two-factor enforcement, HA quorum settings, and corosync encryption keys.',
    match: isProxmoxClusterConfig,
  },
  {
    id: 'XEN_XENSERVER_DRIFT',
    severity: 'medium',
    description: 'Xen hypervisor, XenServer, or XCP-ng configuration modified.',
    recommendation: 'Check xl.conf for stub-domain isolation, memory balloon limits, and toolstack security settings.',
    match: isXenXenserverConfig,
  },
  {
    id: 'HYPERV_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Microsoft Hyper-V configuration modified.',
    recommendation: 'Audit VM generation settings, Virtual TPM configuration, Hyper-V firewall rules, and integration service policies.',
    match: isHyperVConfig,
  },
  {
    id: 'VM_CONSOLE_ACCESS_DRIFT',
    severity: 'medium',
    description: 'Virtual machine remote console access configuration modified.',
    recommendation: 'Ensure VNC/SPICE console access requires authentication and TLS; restrict console access to management networks only.',
    match: (p, b) => isVmConsoleAccessConfig(p, b),
  },
  {
    id: 'VIRTUAL_SWITCH_SDN_DRIFT',
    severity: 'low',
    description: 'Open vSwitch or SDN configuration modified.',
    recommendation: 'Review VLAN trunking rules, VXLAN tunnel keys, flow-table ACLs, and ingress-rate limiting policies.',
    match: isVirtualSwitchSdnConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring model (identical to all WS-60+ detectors)
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP:     Record<Severity, number> = { high: 45, medium: 25, low: 15 }

type VirtSecRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

function computeRiskLevel(score: number): VirtSecRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type VirtSecFinding = {
  ruleId:         string
  severity:       Severity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type VirtSecDriftResult = {
  riskScore:     number
  riskLevel:     VirtSecRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      VirtSecFinding[]
  summary:       string
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanVirtualizationSecurityDrift(
  changedFiles: string[],
): VirtSecDriftResult {
  const findings: VirtSecFinding[] = []

  for (const rule of RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const path = normalise(raw)
      if (isVendorPath(path)) continue
      const base = path.split('/').pop() ?? ''
      if (rule.match(path, base)) {
        matchCount++
        if (matchCount === 1) firstPath = path
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

  const grouped = { high: 0, medium: 0, low: 0 }
  for (const f of findings) grouped[f.severity]++

  let score = 0
  for (const sev of ['high', 'medium', 'low'] as Severity[]) {
    score += Math.min(grouped[sev] * SEVERITY_PENALTY[sev], SEVERITY_CAP[sev])
  }
  score = Math.min(score, 100)

  const riskLevel     = computeRiskLevel(score)
  const totalFindings = findings.length

  const summary =
    totalFindings === 0
      ? 'No virtualization or hypervisor security configuration changes detected.'
      : `${totalFindings} virtualization/hypervisor security configuration ${totalFindings === 1 ? 'file' : 'files'} modified (risk score ${score}/100).`

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
