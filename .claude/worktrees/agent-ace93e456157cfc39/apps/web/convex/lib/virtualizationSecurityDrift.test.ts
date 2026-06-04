// WS-92 — Virtualization & Hypervisor Security Configuration Drift Detector: tests.

import { describe, expect, it } from 'vitest'
import {
  isVmConsoleAccessConfig,
  scanVirtualizationSecurityDrift,
} from './virtualizationSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: VSPHERE_ESXI_SECURITY_DRIFT (high)
// ---------------------------------------------------------------------------

describe('VSPHERE_ESXI_SECURITY_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'VSPHERE_ESXI_SECURITY_DRIFT')

  it('matches vmware.conf ungated', () => {
    expect(trigger(['vmware.conf'])).toBeDefined()
  })
  it('matches vsphere.conf ungated', () => {
    expect(trigger(['vsphere.conf'])).toBeDefined()
  })
  it('matches vcenter.conf ungated', () => {
    expect(trigger(['vcenter.conf'])).toBeDefined()
  })
  it('matches esxi.conf ungated', () => {
    expect(trigger(['esxi.conf'])).toBeDefined()
  })
  it('matches vpxa.cfg ungated', () => {
    expect(trigger(['vpxa.cfg'])).toBeDefined()
  })
  it('matches vpxd.cfg ungated', () => {
    expect(trigger(['vpxd.cfg'])).toBeDefined()
  })
  it('matches vsphere-ha.cfg ungated', () => {
    expect(trigger(['vsphere-ha.cfg'])).toBeDefined()
  })
  it('matches vcsa.conf ungated', () => {
    expect(trigger(['vcsa.conf'])).toBeDefined()
  })
  it('matches vsphere-*.conf prefix', () => {
    expect(trigger(['vsphere-security.conf'])).toBeDefined()
  })
  it('matches vcenter-*.json prefix', () => {
    expect(trigger(['vcenter-policy.json'])).toBeDefined()
  })
  it('matches vmware-*.yaml prefix', () => {
    expect(trigger(['vmware-settings.yaml'])).toBeDefined()
  })
  it('matches esxi-*.cfg prefix', () => {
    expect(trigger(['esxi-lockdown.cfg'])).toBeDefined()
  })
  it('matches any .conf in vsphere/ dir', () => {
    expect(trigger(['vsphere/security.conf'])).toBeDefined()
  })
  it('matches any .yaml in vcenter/ dir', () => {
    expect(trigger(['vcenter/ha-policy.yaml'])).toBeDefined()
  })
  it('matches any .cfg in vmware/ dir', () => {
    expect(trigger(['vmware/hosts.cfg'])).toBeDefined()
  })
  it('does not match random config.conf outside vsphere dirs', () => {
    expect(trigger(['config.conf'])).toBeUndefined()
  })
  it('skips node_modules', () => {
    expect(trigger(['node_modules/vmware/vmware.conf'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 2: LIBVIRT_KVM_SECURITY_DRIFT (high)
// ---------------------------------------------------------------------------

describe('LIBVIRT_KVM_SECURITY_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'LIBVIRT_KVM_SECURITY_DRIFT')

  it('matches libvirtd.conf ungated', () => {
    expect(trigger(['libvirtd.conf'])).toBeDefined()
  })
  it('matches libvirt.conf ungated', () => {
    expect(trigger(['libvirt.conf'])).toBeDefined()
  })
  it('matches virtlogd.conf ungated', () => {
    expect(trigger(['virtlogd.conf'])).toBeDefined()
  })
  it('matches virtnodedevd.conf ungated', () => {
    expect(trigger(['virtnodedevd.conf'])).toBeDefined()
  })
  it('matches virtqemud.conf ungated', () => {
    expect(trigger(['virtqemud.conf'])).toBeDefined()
  })
  it('matches qemu.conf gated in libvirt/ dir', () => {
    expect(trigger(['libvirt/qemu.conf'])).toBeDefined()
  })
  it('matches networks.xml gated in qemu/ dir', () => {
    expect(trigger(['qemu/networks.xml'])).toBeDefined()
  })
  it('matches libvirt-*.conf prefix', () => {
    expect(trigger(['libvirt-tls.conf'])).toBeDefined()
  })
  it('matches kvm-*.xml prefix', () => {
    expect(trigger(['kvm-network.xml'])).toBeDefined()
  })
  it('matches qemu-*.conf prefix', () => {
    expect(trigger(['qemu-security.conf'])).toBeDefined()
  })
  it('matches any .conf in kvm/ dir', () => {
    expect(trigger(['kvm/settings.conf'])).toBeDefined()
  })
  it('matches any .xml in etc/libvirt/ dir', () => {
    expect(trigger(['etc/libvirt/domain.xml'])).toBeDefined()
  })
  it('does not match qemu.conf outside libvirt dirs', () => {
    expect(trigger(['qemu.conf'])).toBeUndefined()
  })
  it('skips vendor/', () => {
    expect(trigger(['vendor/libvirt/libvirtd.conf'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 3: DOCKER_DAEMON_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('DOCKER_DAEMON_CONFIG_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'DOCKER_DAEMON_CONFIG_DRIFT')

  it('matches docker-daemon.json ungated', () => {
    expect(trigger(['docker-daemon.json'])).toBeDefined()
  })
  it('matches docker-daemon.yaml ungated', () => {
    expect(trigger(['docker-daemon.yaml'])).toBeDefined()
  })
  it('matches containerd-config.toml ungated', () => {
    expect(trigger(['containerd-config.toml'])).toBeDefined()
  })
  it('matches daemon.json gated in docker/ dir', () => {
    expect(trigger(['docker/daemon.json'])).toBeDefined()
  })
  it('matches daemon.json gated in etc/docker/ dir', () => {
    expect(trigger(['etc/docker/daemon.json'])).toBeDefined()
  })
  it('matches config.toml gated in containerd/ dir', () => {
    expect(trigger(['containerd/config.toml'])).toBeDefined()
  })
  it('matches config.json gated in .docker/ dir', () => {
    expect(trigger(['.docker/config.json'])).toBeDefined()
  })
  it('matches docker-config-*.json prefix', () => {
    expect(trigger(['docker-config-prod.json'])).toBeDefined()
  })
  it('matches containerd-*.toml prefix', () => {
    expect(trigger(['containerd-runtime.toml'])).toBeDefined()
  })
  it('matches dockerd-*.conf prefix', () => {
    expect(trigger(['dockerd-tls.conf'])).toBeDefined()
  })
  it('matches any .yaml in docker/ dir', () => {
    expect(trigger(['docker/settings.yaml'])).toBeDefined()
  })
  it('does not match daemon.json outside docker dirs', () => {
    expect(trigger(['daemon.json'])).toBeUndefined()
  })
  it('does not match config.toml outside containerd dirs', () => {
    expect(trigger(['config.toml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 4: PROXMOX_CLUSTER_SECURITY_DRIFT (high)
// ---------------------------------------------------------------------------

describe('PROXMOX_CLUSTER_SECURITY_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'PROXMOX_CLUSTER_SECURITY_DRIFT')

  it('matches datacenter.cfg ungated', () => {
    expect(trigger(['datacenter.cfg'])).toBeDefined()
  })
  it('matches pve.conf ungated', () => {
    expect(trigger(['pve.conf'])).toBeDefined()
  })
  it('matches proxmox.conf ungated', () => {
    expect(trigger(['proxmox.conf'])).toBeDefined()
  })
  it('matches ha-manager.cfg ungated', () => {
    expect(trigger(['ha-manager.cfg'])).toBeDefined()
  })
  it('matches corosync.conf gated in proxmox/ dir', () => {
    expect(trigger(['proxmox/corosync.conf'])).toBeDefined()
  })
  it('matches storage.cfg gated in pve/ dir', () => {
    expect(trigger(['pve/storage.cfg'])).toBeDefined()
  })
  it('matches users.cfg gated in etc/pve/ dir', () => {
    expect(trigger(['etc/pve/users.cfg'])).toBeDefined()
  })
  it('matches proxmox-*.cfg prefix', () => {
    expect(trigger(['proxmox-firewall.cfg'])).toBeDefined()
  })
  it('matches pve-*.conf prefix', () => {
    expect(trigger(['pve-ha.conf'])).toBeDefined()
  })
  it('matches any .cfg in pve-config/ dir', () => {
    expect(trigger(['pve-config/nodes.cfg'])).toBeDefined()
  })
  it('does not match corosync.conf outside proxmox dirs', () => {
    expect(trigger(['corosync.conf'])).toBeUndefined()
  })
  it('skips vendor/', () => {
    expect(trigger(['vendor/proxmox/datacenter.cfg'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 5: XEN_XENSERVER_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('XEN_XENSERVER_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'XEN_XENSERVER_DRIFT')

  it('matches xend.conf ungated', () => {
    expect(trigger(['xend.conf'])).toBeDefined()
  })
  it('matches xl.conf ungated', () => {
    expect(trigger(['xl.conf'])).toBeDefined()
  })
  it('matches xen.conf ungated', () => {
    expect(trigger(['xen.conf'])).toBeDefined()
  })
  it('matches xapi.conf ungated', () => {
    expect(trigger(['xapi.conf'])).toBeDefined()
  })
  it('matches xen-*.conf prefix', () => {
    expect(trigger(['xen-domains.conf'])).toBeDefined()
  })
  it('matches xenserver-*.xml prefix', () => {
    expect(trigger(['xenserver-policy.xml'])).toBeDefined()
  })
  it('matches xcp-*.conf prefix', () => {
    expect(trigger(['xcp-network.conf'])).toBeDefined()
  })
  it('matches any .cfg in xen/ dir', () => {
    expect(trigger(['xen/domain.cfg'])).toBeDefined()
  })
  it('matches any .xml in xenserver/ dir', () => {
    expect(trigger(['xenserver/roles.xml'])).toBeDefined()
  })
  it('does not match random domain.cfg outside xen dirs', () => {
    expect(trigger(['domain.cfg'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 6: HYPERV_SECURITY_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('HYPERV_SECURITY_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'HYPERV_SECURITY_DRIFT')

  it('matches hyperv-config.xml ungated', () => {
    expect(trigger(['hyperv-config.xml'])).toBeDefined()
  })
  it('matches hyper-v-config.xml ungated', () => {
    expect(trigger(['hyper-v-config.xml'])).toBeDefined()
  })
  it('matches hyperv-settings.xml ungated', () => {
    expect(trigger(['hyperv-settings.xml'])).toBeDefined()
  })
  it('matches hyperv.conf ungated', () => {
    expect(trigger(['hyperv.conf'])).toBeDefined()
  })
  it('matches hyperv-*.xml prefix', () => {
    expect(trigger(['hyperv-network.xml'])).toBeDefined()
  })
  it('matches hyper-v-*.json prefix', () => {
    expect(trigger(['hyper-v-policy.json'])).toBeDefined()
  })
  it('matches any .xml in hyperv/ dir', () => {
    expect(trigger(['hyperv/switch-config.xml'])).toBeDefined()
  })
  it('matches any .ps1 in hyper-v/ dir', () => {
    expect(trigger(['hyper-v/setup.ps1'])).toBeDefined()
  })
  it('does not match random config.xml outside hyperv dirs', () => {
    expect(trigger(['config.xml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 7: VM_CONSOLE_ACCESS_DRIFT (medium) — user contribution
// ---------------------------------------------------------------------------

describe('isVmConsoleAccessConfig (user contribution)', () => {
  it('matches spice-vdagent.conf ungated', () => {
    expect(isVmConsoleAccessConfig('spice-vdagent.conf', 'spice-vdagent.conf')).toBe(true)
  })
  it('matches virt-manager.conf ungated', () => {
    expect(isVmConsoleAccessConfig('virt-manager.conf', 'virt-manager.conf')).toBe(true)
  })
  it('matches spice-*.conf prefix ungated', () => {
    expect(isVmConsoleAccessConfig('config/spice-tls.conf', 'spice-tls.conf')).toBe(true)
  })
  it('matches vnc-*.yaml prefix ungated', () => {
    expect(isVmConsoleAccessConfig('settings/vnc-auth.yaml', 'vnc-auth.yaml')).toBe(true)
  })
  it('matches spice.conf in qemu/ dir', () => {
    expect(isVmConsoleAccessConfig('qemu/spice.conf', 'spice.conf')).toBe(true)
  })
  it('matches vnc.conf in libvirt/ dir', () => {
    expect(isVmConsoleAccessConfig('libvirt/vnc.conf', 'vnc.conf')).toBe(true)
  })
  it('matches console.conf in proxmox/ dir', () => {
    expect(isVmConsoleAccessConfig('proxmox/console.conf', 'console.conf')).toBe(true)
  })
  it('matches vnc.json in vm/ dir', () => {
    expect(isVmConsoleAccessConfig('vm/vnc.json', 'vnc.json')).toBe(true)
  })
  it('does not match spice.conf outside VM dirs', () => {
    expect(isVmConsoleAccessConfig('app/spice.conf', 'spice.conf')).toBe(false)
  })
  it('does not match vnc.conf outside VM dirs', () => {
    expect(isVmConsoleAccessConfig('src/vnc.conf', 'vnc.conf')).toBe(false)
  })
  it('does not match console.conf outside VM dirs', () => {
    expect(isVmConsoleAccessConfig('server/console.conf', 'console.conf')).toBe(false)
  })
})

describe('VM_CONSOLE_ACCESS_DRIFT (scanner)', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'VM_CONSOLE_ACCESS_DRIFT')

  it('fires for spice-tls.conf', () => {
    expect(trigger(['config/spice-tls.conf'])).toBeDefined()
  })
  it('fires for vnc.conf in libvirt/ dir', () => {
    expect(trigger(['libvirt/vnc.conf'])).toBeDefined()
  })
  it('fires for virt-manager.conf', () => {
    expect(trigger(['virt-manager.conf'])).toBeDefined()
  })
  it('does not fire for random console.conf', () => {
    expect(trigger(['server/console.conf'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 8: VIRTUAL_SWITCH_SDN_DRIFT (low)
// ---------------------------------------------------------------------------

describe('VIRTUAL_SWITCH_SDN_DRIFT', () => {
  const trigger = (paths: string[]) =>
    scanVirtualizationSecurityDrift(paths).findings.find((f) => f.ruleId === 'VIRTUAL_SWITCH_SDN_DRIFT')

  it('matches ovs-vswitchd.conf ungated', () => {
    expect(trigger(['ovs-vswitchd.conf'])).toBeDefined()
  })
  it('matches ovsdb.conf ungated', () => {
    expect(trigger(['ovsdb.conf'])).toBeDefined()
  })
  it('matches openvswitch.conf ungated', () => {
    expect(trigger(['openvswitch.conf'])).toBeDefined()
  })
  it('matches nsx-manager.conf ungated', () => {
    expect(trigger(['nsx-manager.conf'])).toBeDefined()
  })
  it('matches ovs-config.yaml ungated', () => {
    expect(trigger(['ovs-config.yaml'])).toBeDefined()
  })
  it('matches ovs-*.toml prefix', () => {
    expect(trigger(['ovs-flows.toml'])).toBeDefined()
  })
  it('matches openvswitch-*.yaml prefix', () => {
    expect(trigger(['openvswitch-ports.yaml'])).toBeDefined()
  })
  it('matches nsx-*.conf prefix', () => {
    expect(trigger(['nsx-edge.conf'])).toBeDefined()
  })
  it('matches any .cfg in ovs/ dir', () => {
    expect(trigger(['ovs/bridge.cfg'])).toBeDefined()
  })
  it('matches any .yaml in sdn/ dir', () => {
    expect(trigger(['sdn/flows.yaml'])).toBeDefined()
  })
  it('matches any .xml in openvswitch/ dir', () => {
    expect(trigger(['openvswitch/controller.xml'])).toBeDefined()
  })
  it('does not match random flow.yaml outside sdn dirs', () => {
    expect(trigger(['src/flow.yaml'])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Scanner integration tests
// ---------------------------------------------------------------------------

describe('scanVirtualizationSecurityDrift integration', () => {
  it('returns clean result for empty path list', () => {
    const r = scanVirtualizationSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toContain('No virtualization')
  })

  it('returns clean result for paths with no virt config files', () => {
    const r = scanVirtualizationSecurityDrift(['src/index.ts', 'package.json', 'README.md'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('deduplicates — multiple vsphere files count as one finding with matchCount', () => {
    const r = scanVirtualizationSecurityDrift(['vmware.conf', 'vsphere.conf', 'vcenter.conf'])
    const f = r.findings.find((x) => x.ruleId === 'VSPHERE_ESXI_SECURITY_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
    expect(r.findings.length).toBe(1)
  })

  it('scores a single HIGH finding at 15', () => {
    const r = scanVirtualizationSecurityDrift(['libvirtd.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('scores a single MEDIUM finding at 8', () => {
    const r = scanVirtualizationSecurityDrift(['xend.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('scores a single LOW finding at 4', () => {
    const r = scanVirtualizationSecurityDrift(['ovsdb.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('scores 2 HIGH findings at 30', () => {
    const r = scanVirtualizationSecurityDrift(['vmware.conf', 'docker-daemon.json'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('scores 3 HIGH findings at 45 (high — 45 is not < 45)', () => {
    const r = scanVirtualizationSecurityDrift([
      'vmware.conf',         // VSPHERE_ESXI_SECURITY_DRIFT
      'libvirtd.conf',       // LIBVIRT_KVM_SECURITY_DRIFT
      'docker-daemon.json',  // DOCKER_DAEMON_CONFIG_DRIFT
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('caps HIGH contributions at 45 even with 4 HIGH rules', () => {
    const r = scanVirtualizationSecurityDrift([
      'vmware.conf',         // VSPHERE_ESXI_SECURITY_DRIFT
      'libvirtd.conf',       // LIBVIRT_KVM_SECURITY_DRIFT
      'docker-daemon.json',  // DOCKER_DAEMON_CONFIG_DRIFT
      'datacenter.cfg',      // PROXMOX_CLUSTER_SECURITY_DRIFT
    ])
    expect(r.highCount).toBe(4)
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('scores all 8 rules at 73 → high (4H capped + 3M×8 + 1L×4)', () => {
    const r = scanVirtualizationSecurityDrift([
      'vmware.conf',              // VSPHERE_ESXI_SECURITY_DRIFT (H)
      'libvirtd.conf',            // LIBVIRT_KVM_SECURITY_DRIFT (H)
      'docker-daemon.json',       // DOCKER_DAEMON_CONFIG_DRIFT (H)
      'datacenter.cfg',           // PROXMOX_CLUSTER_SECURITY_DRIFT (H)
      'xend.conf',                // XEN_XENSERVER_DRIFT (M)
      'hyperv-config.xml',        // HYPERV_SECURITY_DRIFT (M)
      'spice-tls.conf',           // VM_CONSOLE_ACCESS_DRIFT (M)
      'ovs-vswitchd.conf',        // VIRTUAL_SWITCH_SDN_DRIFT (L)
    ])
    // 4H × 15 = 60 → cap 45; 3M × 8 = 24 (cap 25 not hit); 1L × 4 = 4
    // Total = 45 + 24 + 4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
  })

  it('skips vendor directory paths', () => {
    const r = scanVirtualizationSecurityDrift([
      'node_modules/vmware/vmware.conf',
      'vendor/libvirt/libvirtd.conf',
      '.git/docker-daemon.json',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskScore).toBe(0)
  })

  it('summary reports correct finding count', () => {
    const r = scanVirtualizationSecurityDrift(['vmware.conf', 'libvirtd.conf'])
    expect(r.summary).toContain('2 virtualization/hypervisor')
    expect(r.summary).toContain('30/100')
  })

  it('summary uses singular for single finding', () => {
    const r = scanVirtualizationSecurityDrift(['ovs-vswitchd.conf'])
    expect(r.summary).toMatch(/1 virtualization\/hypervisor security configuration file/)
  })

  it('matchedPath is the first triggered file', () => {
    const r = scanVirtualizationSecurityDrift(['vsphere/ha.conf', 'vmware.conf'])
    const f = r.findings.find((x) => x.ruleId === 'VSPHERE_ESXI_SECURITY_DRIFT')
    expect(f!.matchedPath).toBe('vsphere/ha.conf')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundary tests
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scanVirtualizationSecurityDrift([]).riskLevel).toBe('none')
  })
  it('score 4 (1 LOW) → low', () => {
    expect(scanVirtualizationSecurityDrift(['ovsdb.conf']).riskLevel).toBe('low')
  })
  it('score 8 (1 MEDIUM) → low', () => {
    expect(scanVirtualizationSecurityDrift(['xend.conf']).riskLevel).toBe('low')
  })
  it('score 15 (1 HIGH) → medium (15 is not < 15)', () => {
    expect(scanVirtualizationSecurityDrift(['vmware.conf']).riskLevel).toBe('medium')
  })
  it('score 30 (2 HIGH) → medium', () => {
    const r = scanVirtualizationSecurityDrift(['vmware.conf', 'libvirtd.conf'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 45 (3 HIGH) → high (45 is not < 45)', () => {
    const r = scanVirtualizationSecurityDrift([
      'vmware.conf',
      'libvirtd.conf',
      'docker-daemon.json',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })
  it('max score 73 (all 8 rules) → high (not critical)', () => {
    const r = scanVirtualizationSecurityDrift([
      'vmware.conf',
      'libvirtd.conf',
      'docker-daemon.json',
      'datacenter.cfg',
      'xend.conf',
      'hyperv-config.xml',
      'spice-tls.conf',
      'ovs-vswitchd.conf',
    ])
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
  })
})
