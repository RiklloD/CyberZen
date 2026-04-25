// WS-83 — Infrastructure Configuration Management Security Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to infrastructure configuration management security files — the toolchain
// that provisions and manages every host in the fleet.  A misconfigured or
// rotated Ansible vault password file, Chef client key, Puppet CA auth policy,
// or SaltStack master roster can expose privileged access across all managed
// systems in seconds.
//
// DISTINCT from:
//   WS-33  iacScan              — Terraform/Kubernetes/Dockerfile static
//                                 misconfigurations; WS-83 covers the
//                                 configuration management tool's own
//                                 security settings
//   WS-62  cloudSecurityDrift   — cloud-wide IAM/KMS and S3/GCS bucket
//                                 policies; WS-83 covers the agent-based
//                                 push model (Ansible/Chef/Puppet/Salt)
//   WS-70  identityAccessDrift  — Vault policy HCL, LDAP, PAM; WS-83
//                                 covers the CM tool connection security
//                                 (API keys, transport encryption)
//   WS-73  cicdPipelineDrift    — CI/CD pipeline orchestration configs;
//                                 WS-83 covers the CM toolchain itself
//
// Covered rule groups (8 rules):
//
//   ANSIBLE_CONFIG_DRIFT          — Ansible configuration, vault password
//                                   files, and encrypted-variable stores
//   CHEF_WORKSTATION_DRIFT        — Chef workstation API key, client
//                                   certificate, and data bag encryption key
//   PUPPET_MASTER_DRIFT           — Puppet server configuration, r10k
//                                   Puppetfile, and Hiera data-backend config
//   SALTSTACK_MASTER_DRIFT        — SaltStack master/minion config, roster
//                                   (SSH target list), and cloud provider config
//   ANSIBLE_INVENTORY_DRIFT       — Ansible inventory, group/host variable
//                                   files, and environment-specific host lists
//   CHEF_COOKBOOK_SECURITY_DRIFT  — Berkshelf/Policyfile cookbook dependency
//                                   manifests and encrypted data bag stores
//   PUPPET_HIERA_DATA_DRIFT       — Puppet Hiera data files including
//                                   eyaml-encrypted common/site data
//   CFGMGMT_TEST_SECURITY_DRIFT   — Test Kitchen and Molecule CI framework
//                                   configs (include SSH and cloud credentials)
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–82 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • ansible.cfg is globally unambiguous (like Makefile for Ansible).
//   • Puppetfile / puppet.conf / knife.rb / Saltfile / Berksfile / Cheffile
//     are globally unambiguous tool-specific filenames.
//   • hiera.yaml is the Puppet Hiera configuration and is globally unambiguous
//     in the Puppet ecosystem (no other tool uses this exact filename).
//   • vault-password-file and .vault-password are explicitly named for
//     Ansible vault credential storage and match anywhere in a repo.
//   • encrypted_data_bag_secret is the Chef encryption key — globally
//     unambiguous (Chef-specific filename convention).
//   • The ambiguous 'hosts' and 'inventory.yml' filenames need ansible
//     directory context — see isAnsibleInventoryFile (user contribution).
//
// Exports:
//   isAnsibleInventoryFile  — user contribution point (see JSDoc below)
//   CFG_MGMT_SECURITY_RULES — readonly rule registry
//   scanCfgMgmtSecurityDrift — main scanner, returns CfgMgmtSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CfgMgmtSecurityRuleId =
  | 'ANSIBLE_CONFIG_DRIFT'
  | 'CHEF_WORKSTATION_DRIFT'
  | 'PUPPET_MASTER_DRIFT'
  | 'SALTSTACK_MASTER_DRIFT'
  | 'ANSIBLE_INVENTORY_DRIFT'
  | 'CHEF_COOKBOOK_SECURITY_DRIFT'
  | 'PUPPET_HIERA_DATA_DRIFT'
  | 'CFGMGMT_TEST_SECURITY_DRIFT'

export type CfgMgmtSecuritySeverity = 'high' | 'medium' | 'low'
export type CfgMgmtSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type CfgMgmtSecurityDriftFinding = {
  ruleId: CfgMgmtSecurityRuleId
  severity: CfgMgmtSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type CfgMgmtSecurityDriftResult = {
  riskScore: number
  riskLevel: CfgMgmtSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: CfgMgmtSecurityDriftFinding[]
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

const ANSIBLE_DIRS      = ['ansible/', '.ansible/', 'playbooks/', 'ansible-config/', 'ansible-roles/']
const CHEF_DIRS         = ['.chef/', 'chef/', 'chef-repo/']
const PUPPET_DIRS       = ['puppet/', '.puppet/', 'manifests/', 'environments/', 'r10k/']
const SALT_DIRS         = ['salt/', '.salt/', 'saltstack/', 'salt-config/', 'salt-master/']
const INVENTORY_DIRS    = ['ansible/', 'playbooks/', 'inventory/', '.ansible/', 'ansible-config/']
const COOKBOOK_DIRS     = ['cookbooks/', 'site-cookbooks/', 'data_bags/', 'databags/', 'encrypted_data_bags/']
const HIERA_DIRS        = ['hiera/', 'hieradata/', 'puppet/hiera/', 'puppet/hieradata/', 'puppet/data/']
const MOLECULE_DIRS     = ['molecule/', 'test/integration/', 'test/kitchen/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: ANSIBLE_CONFIG_DRIFT (high)
// Ansible configuration, vault password files, and encrypted-variable stores
// ---------------------------------------------------------------------------

const ANSIBLE_UNGATED = new Set([
  'ansible.cfg',            // Ansible's canonical configuration file — globally unambiguous
  'vault-password-file',    // Ansible vault credential file — explicitly named
  '.vault-password',        // Dot-prefixed vault password file
  'ansible-vault.yml',      // Tool-named vault configuration
  'ansible-vault.yaml',
])

function isAnsibleConfig(pathLower: string, base: string): boolean {
  if (ANSIBLE_UNGATED.has(base)) return true

  // ansible-* prefix — filename names its own tool
  if (base.startsWith('ansible-')) {
    if (
      base.endsWith('.cfg') || base.endsWith('.yaml') ||
      base.endsWith('.yml') || base.endsWith('.json')
    ) return true
  }

  if (!inAnyDir(pathLower, ANSIBLE_DIRS)) return false

  if (
    base === 'vault.yml'   || base === 'vault.yaml'   ||
    base === 'secrets.yml' || base === 'secrets.yaml' ||
    base === 'config.yml'  || base === 'config.yaml'  ||
    base === '.env'
  ) return true

  if (base.endsWith('.cfg')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: CHEF_WORKSTATION_DRIFT (high)
// Chef workstation API key, client certificate, and data bag encryption key
// ---------------------------------------------------------------------------

const CHEF_WORKSTATION_UNGATED = new Set([
  'knife.rb',                   // Chef workstation CLI config — globally unambiguous
  'encrypted_data_bag_secret',  // Chef encryption key file — globally unambiguous
])

function isChefWorkstationConfig(pathLower: string, base: string): boolean {
  if (CHEF_WORKSTATION_UNGATED.has(base)) return true

  // knife-* / chef-client-* prefix
  if (base.startsWith('knife-') || base.startsWith('chef-client-')) {
    if (
      base.endsWith('.rb') || base.endsWith('.json') ||
      base.endsWith('.yaml') || base.endsWith('.yml')
    ) return true
  }

  if (!inAnyDir(pathLower, CHEF_DIRS)) return false

  if (
    base === 'client.rb'     ||  // Chef client configuration
    base === 'config.rb'     ||  // Chef configuration (knife/client alias)
    base === 'solo.rb'       ||  // Chef Solo configuration
    base === 'zero.rb'       ||  // Chef Zero configuration
    base === 'bootstrap.json'||  // Node bootstrap configuration
    base === 'credentials'   ||  // Chef credentials file (.chef/credentials)
    base === '.env'
  ) return true

  if (base.endsWith('.pem')) return true  // Chef client/validation key files

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: PUPPET_MASTER_DRIFT (high)
// Puppet server configuration, r10k Puppetfile, and Hiera data-backend config
// ---------------------------------------------------------------------------

const PUPPET_UNGATED = new Set([
  'puppet.conf',       // Puppet main configuration file — globally unambiguous
  'puppetfile',        // r10k module definition — globally unambiguous (actual: Puppetfile)
  'puppetfile.lock',   // Locked module versions (actual: Puppetfile.lock)
  'hiera.yaml',        // Puppet Hiera configuration — globally unambiguous
  'hiera.yml',
])

function isPuppetMasterConfig(pathLower: string, base: string): boolean {
  if (PUPPET_UNGATED.has(base)) return true

  // puppet-* prefix
  if (base.startsWith('puppet-')) {
    if (
      base.endsWith('.conf') || base.endsWith('.yaml') ||
      base.endsWith('.yml')  || base.endsWith('.json')
    ) return true
  }

  if (!inAnyDir(pathLower, PUPPET_DIRS)) return false

  if (
    base === 'auth.conf'       ||  // Puppet CA authorization rules
    base === 'fileserver.conf' ||  // Puppet file server configuration
    base === 'routes.yaml'     ||  // Puppet request routing configuration
    base === 'site.pp'         ||  // Puppet main site manifest
    base === 'config.yaml'     ||
    base === 'config.yml'      ||
    base === '.env'
  ) return true

  if (base.endsWith('.pp')) return true   // Any Puppet manifest in puppet dirs

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: SALTSTACK_MASTER_DRIFT (high)
// SaltStack master/minion config, roster (SSH target list), and cloud config
// ---------------------------------------------------------------------------

const SALT_UNGATED = new Set([
  'saltfile',   // SaltStack CLI aliases configuration — globally unambiguous (actual: Saltfile)
])

function isSaltStackMasterConfig(pathLower: string, base: string): boolean {
  if (SALT_UNGATED.has(base)) return true

  // salt-master-* / salt-minion-* prefix — tool-named
  if (base.startsWith('salt-master-') || base.startsWith('salt-minion-')) {
    if (
      base.endsWith('.yaml') || base.endsWith('.yml') ||
      base.endsWith('.conf') || base.endsWith('.json')
    ) return true
  }

  if (!inAnyDir(pathLower, SALT_DIRS)) return false

  if (
    base === 'master.conf'        ||  // SaltStack master configuration
    base === 'minion.conf'        ||  // SaltStack minion configuration
    base === 'master.yaml'        ||
    base === 'master.yml'         ||
    base === 'minion.yaml'        ||
    base === 'minion.yml'         ||
    base === 'roster'             ||  // Salt SSH roster file (SSH targets + credentials)
    base === 'cloud.conf'         ||  // Salt Cloud provider configuration
    base === 'cloud.providers.conf'|| // Salt Cloud provider definitions
    base === '.env'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: ANSIBLE_INVENTORY_DRIFT (medium) — user contribution
// Ansible inventory files, group variable vaults, and environment host lists
// ---------------------------------------------------------------------------

/**
 * WS-83 user contribution — determines whether a file path is an Ansible
 * inventory file or host-variable store that warrants a security drift alert.
 *
 * The challenge: 'hosts' is the canonical Ansible inventory filename but is
 * also the system hosts file (/etc/hosts), and 'inventory.yml' / 'hosts.yml'
 * are generic names that appear in many non-Ansible contexts.  Reading file
 * content to detect Ansible inventory syntax is not permitted, so we rely on
 * directory context and Ansible-specific path structures.
 *
 * Three disambiguation signals:
 *
 *   1. The file lives in group_vars/ or host_vars/ — these are Ansible-only
 *      variable directory conventions.  Any YAML/JSON inside them is an
 *      inventory-adjacent variable file that may contain vault-encrypted or
 *      plaintext host credentials.
 *
 *   2. The file lives in a recognised Ansible context directory segment
 *      (ansible/, playbooks/, inventory/, .ansible/) AND the basename is one
 *      of the standard inventory names: hosts, inventory, inventory.yml/yaml,
 *      hosts.yml/yaml, production, staging, development, all.yml/yaml.
 *
 *   3. Any YAML file inside an inventory/ subdirectory — Ansible static
 *      inventory splits are commonly stored as a directory of YAML files.
 *
 * Exclusions:
 *   • /etc/ path prefix — the OS hosts file must never match.
 *   • .github/ — GitHub Actions workflows can reference inventory paths but
 *     are not inventory files themselves.
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isAnsibleInventoryFile(pathLower: string, base: string): boolean {
  // OS system paths — never an Ansible inventory
  if (pathLower.startsWith('/etc/') || pathLower.includes('/etc/hosts')) return false

  // GitHub Actions workflow files may reference inventory — not inventory files
  if (pathLower.includes('.github/')) return false

  // Files inside Ansible variable directories are always inventory-adjacent
  if (pathLower.includes('group_vars/') || pathLower.includes('host_vars/')) {
    if (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json')) return true
  }

  // Must be in a recognised Ansible context directory
  if (!inAnyDir(pathLower, INVENTORY_DIRS)) return false

  // Standard Ansible inventory filenames inside recognised dirs
  if (
    base === 'hosts'           ||
    base === 'inventory'       ||
    base === 'inventory.yml'   || base === 'inventory.yaml'  ||
    base === 'inventory.ini'   ||
    base === 'hosts.yml'       || base === 'hosts.yaml'      ||
    base === 'production'      || base === 'staging'         ||
    base === 'development'     || base === 'testing'         ||
    base === 'all.yml'         || base === 'all.yaml'
  ) return true

  // Any YAML inside an inventory/ subdirectory
  if (pathLower.includes('inventory/') && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.ini'))) return true

  return false
}

const ANSIBLE_INVENTORY_PREFIXES = ['inventory-', 'hosts-']

function isAnsibleInventory(pathLower: string, base: string): boolean {
  if (ANSIBLE_INVENTORY_PREFIXES.some((p) => base.startsWith(p))) {
    if (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.ini')) return true
  }
  return isAnsibleInventoryFile(pathLower, base)
}

// ---------------------------------------------------------------------------
// Rule 6: CHEF_COOKBOOK_SECURITY_DRIFT (medium)
// Berkshelf/Policyfile cookbook dependency manifests and encrypted data bag stores
// ---------------------------------------------------------------------------

const CHEF_COOKBOOK_UNGATED = new Set([
  'berksfile',              // Berkshelf cookbook dependency manager — globally unambiguous (actual: Berksfile)
  'berksfile.lock',         // Locked cookbook versions (actual: Berksfile.lock)
  'cheffile',               // Librarian-Chef cookbook manager — globally unambiguous (actual: Cheffile)
  'policyfile.rb',          // Chef Policyfile — globally unambiguous (actual: Policyfile.rb)
  'policyfile.lock.json',   // Locked Policyfile cookbook set (actual: Policyfile.lock.json)
])

function isChefCookbookSecurityConfig(pathLower: string, base: string): boolean {
  if (CHEF_COOKBOOK_UNGATED.has(base)) return true

  // berksfile-* / policyfile-* prefix
  if (base.startsWith('berksfile-') || base.startsWith('policyfile-')) {
    if (base.endsWith('.rb') || base.endsWith('.json') || base.endsWith('.lock')) return true
  }

  if (!inAnyDir(pathLower, COOKBOOK_DIRS)) return false

  if (
    base === 'metadata.rb'   ||  // Cookbook metadata (dependencies, auth scopes)
    base === 'metadata.json' ||
    base === 'attributes.rb' ||  // Default attributes (may set auth configs)
    base === '.env'
  ) return true

  // Any JSON in data_bags directories (encrypted data bag items)
  if (
    (pathLower.includes('data_bags/') || pathLower.includes('databags/') || pathLower.includes('encrypted_data_bags/')) &&
    base.endsWith('.json')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: PUPPET_HIERA_DATA_DRIFT (medium)
// Puppet Hiera data files including eyaml-encrypted common/site data
// ---------------------------------------------------------------------------

function isPuppetHieraData(pathLower: string, base: string): boolean {
  // .eyaml extension — Eye YAML encrypted data format (globally unambiguous)
  if (base.endsWith('.eyaml')) return true

  if (!inAnyDir(pathLower, HIERA_DIRS)) return false

  if (
    base === 'common.yaml'   || base === 'common.yml'   ||
    base === 'site.yaml'     || base === 'site.yml'     ||
    base === 'global.yaml'   || base === 'global.yml'   ||
    base === 'default.yaml'  || base === 'default.yml'  ||
    base === 'secrets.yaml'  || base === 'secrets.yml'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: CFGMGMT_TEST_SECURITY_DRIFT (low)
// Test Kitchen and Molecule CI framework configs (include SSH and cloud credentials)
// ---------------------------------------------------------------------------

const KITCHEN_UNGATED = new Set([
  '.kitchen.yml',       // Test Kitchen configuration — globally unambiguous dot-file
  '.kitchen.yaml',      // YAML variant
  '.kitchen.local.yml', // Local overrides with actual credentials
  '.kitchen.local.yaml',
])

function isCfgMgmtTestConfig(pathLower: string, base: string): boolean {
  if (KITCHEN_UNGATED.has(base)) return true

  // kitchen-* prefix
  if (base.startsWith('kitchen-')) {
    if (base.endsWith('.yml') || base.endsWith('.yaml')) return true
  }

  if (!inAnyDir(pathLower, MOLECULE_DIRS)) return false

  if (
    base === 'molecule.yml'   || base === 'molecule.yaml'  ||
    base === 'converge.yml'   || base === 'converge.yaml'  ||
    base === 'prepare.yml'    || base === 'prepare.yaml'   ||
    base === 'verify.yml'     || base === 'verify.yaml'    ||
    base === 'create.yml'     || base === 'create.yaml'    ||
    base === 'destroy.yml'    || base === 'destroy.yaml'   ||
    base === 'default.yml'    || base === 'default.yaml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const CFG_MGMT_SECURITY_RULES: ReadonlyArray<{
  id: CfgMgmtSecurityRuleId
  severity: CfgMgmtSecuritySeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'ANSIBLE_CONFIG_DRIFT',
    severity: 'high',
    description: 'Ansible configuration or vault password file changed.',
    recommendation:
      'Review ansible.cfg for vault_password_file path exposure or insecure settings (host_key_checking=False, pipelining impacts), verify that vault-password-file references are not committed as plaintext, audit any vault.yml or secrets.yml changes for unencrypted variable values, and confirm that privilege escalation (become settings) is still appropriately restricted.',
    match: (p, b) => isAnsibleConfig(p, b),
  },
  {
    id: 'CHEF_WORKSTATION_DRIFT',
    severity: 'high',
    description: 'Chef workstation, client key, or data bag encryption key configuration changed.',
    recommendation:
      'Verify that knife.rb chef_server_url, node_name, and client_key paths are correct and that the referenced PEM files have not been rotated without re-registering the client on the Chef server, confirm that encrypted_data_bag_secret has not been changed without re-encrypting all dependent data bag items across all environments, and audit .chef/credentials and client.rb for API key path exposure.',
    match: (p, b) => isChefWorkstationConfig(p, b),
  },
  {
    id: 'PUPPET_MASTER_DRIFT',
    severity: 'high',
    description: 'Puppet master or agent configuration, Puppetfile, or Hiera configuration changed.',
    recommendation:
      'Review puppet.conf for certname, server, and environment changes that could redirect agent communication, verify Puppetfile module version pins have not been relaxed to allow unreviewed code, confirm hiera.yaml backend order has not been changed to expose sensitive hierarchy levels, and audit auth.conf CA authorization rules for new certificate signing permissions.',
    match: (p, b) => isPuppetMasterConfig(p, b),
  },
  {
    id: 'SALTSTACK_MASTER_DRIFT',
    severity: 'high',
    description: 'SaltStack master, minion, roster, or cloud provider configuration changed.',
    recommendation:
      'Review master.conf for transport encryption settings (ssl_key, ssl_cert), verify roster changes for unauthorized SSH target additions or credential path changes, confirm that pillar_roots and file_roots have not been extended to include untrusted paths, and audit cloud.providers.conf for unintended provider credential changes.',
    match: (p, b) => isSaltStackMasterConfig(p, b),
  },
  {
    id: 'ANSIBLE_INVENTORY_DRIFT',
    severity: 'medium',
    description: 'Ansible inventory file or host/group variable store changed.',
    recommendation:
      'Review changes to host and group variable files for newly committed plaintext credentials or connection parameters (ansible_password, ansible_become_pass, ansible_ssh_private_key_file), verify that inventory host additions are authorized and reflect the expected environment topology, and confirm that vault-encrypted variable files have not been inadvertently decrypted and recommitted as plaintext.',
    match: (p, b) => isAnsibleInventory(p, b),
  },
  {
    id: 'CHEF_COOKBOOK_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Chef cookbook dependency manifest or encrypted data bag configuration changed.',
    recommendation:
      'Review Berksfile or Policyfile changes for new cookbook sources pointing to untrusted registries or git forks, verify that Berksfile.lock version pins have not been relaxed, audit data bag JSON changes for newly added plaintext secrets, and confirm that metadata.rb dependency version constraints have not been widened in ways that could pull in compromised cookbook releases.',
    match: (p, b) => isChefCookbookSecurityConfig(p, b),
  },
  {
    id: 'PUPPET_HIERA_DATA_DRIFT',
    severity: 'medium',
    description: 'Puppet Hiera data file changed, including eyaml-encrypted common or site data.',
    recommendation:
      'Verify that common.yaml or site.yaml changes do not introduce plaintext secrets that should be eyaml-encrypted, confirm that .eyaml file changes are the result of legitimate key rotation rather than re-encryption with an untrusted key, and audit any expansion of the Hiera hierarchy data directories for unintended data exposure across environments.',
    match: (p, b) => isPuppetHieraData(p, b),
  },
  {
    id: 'CFGMGMT_TEST_SECURITY_DRIFT',
    severity: 'low',
    description: 'Test Kitchen or Molecule configuration management test framework configuration changed.',
    recommendation:
      'Review .kitchen.yml or molecule.yml driver and transport settings for hardcoded SSH keys or cloud API credentials, verify that the test instance configuration does not expose production-grade access credentials, and confirm that the provisioner configuration has not been changed to skip security hardening steps in the converge phase.',
    match: (p, b) => isCfgMgmtTestConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<CfgMgmtSecuritySeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: CfgMgmtSecurityDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): CfgMgmtSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

const MAX_PATHS_PER_SCAN = 500

export function scanCfgMgmtSecurityDrift(changedFiles: string[]): CfgMgmtSecurityDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: CfgMgmtSecurityDriftFinding[] = []

  for (const rule of CFG_MGMT_SECURITY_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles.slice(0, MAX_PATHS_PER_SCAN)) {
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
  const ORDER: Record<CfgMgmtSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No configuration management security drift detected.'
      : `${findings.length} cfg management rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`    : '',
          mediumCount ? `${mediumCount} medium` : '',
          lowCount    ? `${lowCount} low`       : '',
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
