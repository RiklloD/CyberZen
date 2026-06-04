import { describe, expect, it } from 'vitest'
import {
  isAnsibleInventoryFile,
  CFG_MGMT_SECURITY_RULES,
  scanCfgMgmtSecurityDrift,
  type CfgMgmtSecurityDriftResult,
  type CfgMgmtSecurityRuleId,
} from './cfgMgmtSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]): CfgMgmtSecurityDriftResult {
  return scanCfgMgmtSecurityDrift(files)
}

function triggeredRules(files: string[]): CfgMgmtSecurityRuleId[] {
  return scan(files).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Rule 1: ANSIBLE_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('ANSIBLE_CONFIG_DRIFT', () => {
  it('matches ansible.cfg (ungated)', () => {
    expect(triggeredRules(['ansible.cfg'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches vault-password-file (ungated)', () => {
    expect(triggeredRules(['vault-password-file'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches .vault-password (ungated)', () => {
    expect(triggeredRules(['.vault-password'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches ansible-vault.yml (ungated)', () => {
    expect(triggeredRules(['ansible-vault.yml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches ansible-vault.yaml (ungated)', () => {
    expect(triggeredRules(['ansible-vault.yaml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches ansible-prod.cfg via prefix', () => {
    expect(triggeredRules(['ansible-prod.cfg'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches ansible-staging.yaml via prefix', () => {
    expect(triggeredRules(['ansible-staging.yaml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches ansible-config.json via prefix', () => {
    expect(triggeredRules(['ansible-config.json'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches vault.yml inside ansible/ dir', () => {
    expect(triggeredRules(['ansible/vault.yml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches vault.yaml inside playbooks/ dir', () => {
    expect(triggeredRules(['playbooks/vault.yaml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches secrets.yml inside .ansible/ dir', () => {
    expect(triggeredRules(['.ansible/secrets.yml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches config.yaml inside ansible-config/ dir', () => {
    expect(triggeredRules(['ansible-config/config.yaml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('matches any .cfg file inside ansible/ dir', () => {
    expect(triggeredRules(['ansible/local.cfg'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('does NOT match vault.yml outside ansible dirs', () => {
    expect(triggeredRules(['config/vault.yml'])).not.toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('does NOT match vendor path', () => {
    expect(triggeredRules(['vendor/ansible/ansible.cfg'])).not.toContain('ANSIBLE_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: CHEF_WORKSTATION_DRIFT
// ---------------------------------------------------------------------------

describe('CHEF_WORKSTATION_DRIFT', () => {
  it('matches knife.rb (ungated)', () => {
    expect(triggeredRules(['knife.rb'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches encrypted_data_bag_secret (ungated)', () => {
    expect(triggeredRules(['encrypted_data_bag_secret'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches knife-prod.rb via prefix', () => {
    expect(triggeredRules(['knife-prod.rb'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches chef-client-config.rb via prefix', () => {
    expect(triggeredRules(['chef-client-config.rb'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches client.rb inside .chef/ dir', () => {
    expect(triggeredRules(['.chef/client.rb'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches config.rb inside .chef/ dir', () => {
    expect(triggeredRules(['.chef/config.rb'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches credentials inside .chef/ dir', () => {
    expect(triggeredRules(['.chef/credentials'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches solo.rb inside chef/ dir', () => {
    expect(triggeredRules(['chef/solo.rb'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches bootstrap.json inside chef-repo/ dir', () => {
    expect(triggeredRules(['chef-repo/bootstrap.json'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('matches any .pem file inside .chef/ dir', () => {
    expect(triggeredRules(['.chef/client.pem'])).toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('does NOT match client.rb outside chef dirs', () => {
    expect(triggeredRules(['src/client.rb'])).not.toContain('CHEF_WORKSTATION_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: PUPPET_MASTER_DRIFT
// ---------------------------------------------------------------------------

describe('PUPPET_MASTER_DRIFT', () => {
  it('matches puppet.conf (ungated)', () => {
    expect(triggeredRules(['puppet.conf'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches Puppetfile (ungated)', () => {
    expect(triggeredRules(['Puppetfile'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches Puppetfile.lock (ungated)', () => {
    expect(triggeredRules(['Puppetfile.lock'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches hiera.yaml (ungated)', () => {
    expect(triggeredRules(['hiera.yaml'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches hiera.yml (ungated)', () => {
    expect(triggeredRules(['hiera.yml'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches puppet-agent.conf via prefix', () => {
    expect(triggeredRules(['puppet-agent.conf'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches puppet-server.yaml via prefix', () => {
    expect(triggeredRules(['puppet-server.yaml'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches auth.conf inside puppet/ dir', () => {
    expect(triggeredRules(['puppet/auth.conf'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches fileserver.conf inside puppet/ dir', () => {
    expect(triggeredRules(['puppet/fileserver.conf'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches site.pp inside manifests/ dir', () => {
    expect(triggeredRules(['manifests/site.pp'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches any .pp file inside environments/ dir', () => {
    expect(triggeredRules(['environments/production/manifests/nodes.pp'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('matches config.yaml inside r10k/ dir', () => {
    expect(triggeredRules(['r10k/config.yaml'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('does NOT match config.yaml outside puppet dirs', () => {
    expect(triggeredRules(['services/config.yaml'])).not.toContain('PUPPET_MASTER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: SALTSTACK_MASTER_DRIFT
// ---------------------------------------------------------------------------

describe('SALTSTACK_MASTER_DRIFT', () => {
  it('matches Saltfile (ungated)', () => {
    expect(triggeredRules(['Saltfile'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches salt-master-prod.yaml via prefix', () => {
    expect(triggeredRules(['salt-master-prod.yaml'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches salt-master-config.conf via prefix', () => {
    expect(triggeredRules(['salt-master-config.conf'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches salt-minion-prod.conf via prefix', () => {
    expect(triggeredRules(['salt-minion-prod.conf'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches master.conf inside salt/ dir', () => {
    expect(triggeredRules(['salt/master.conf'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches minion.yaml inside saltstack/ dir', () => {
    expect(triggeredRules(['saltstack/minion.yaml'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches roster inside salt/ dir', () => {
    expect(triggeredRules(['salt/roster'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches cloud.conf inside salt-config/ dir', () => {
    expect(triggeredRules(['salt-config/cloud.conf'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches cloud.providers.conf inside salt-master/ dir', () => {
    expect(triggeredRules(['salt-master/cloud.providers.conf'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('matches any yaml inside .salt/ dir', () => {
    expect(triggeredRules(['.salt/grains.yaml'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('does NOT match roster outside salt dirs', () => {
    expect(triggeredRules(['infra/roster'])).not.toContain('SALTSTACK_MASTER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 5: ANSIBLE_INVENTORY_DRIFT + isAnsibleInventoryFile
// ---------------------------------------------------------------------------

describe('ANSIBLE_INVENTORY_DRIFT', () => {
  it('matches inventory-prod.yml via prefix (ungated)', () => {
    expect(triggeredRules(['inventory-prod.yml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches inventory-staging.yaml via prefix (ungated)', () => {
    expect(triggeredRules(['inventory-staging.yaml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches hosts-prod.yml via prefix (ungated)', () => {
    expect(triggeredRules(['hosts-prod.yml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches hosts inside ansible/ dir', () => {
    expect(triggeredRules(['ansible/hosts'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches inventory.yml inside playbooks/ dir', () => {
    expect(triggeredRules(['playbooks/inventory.yml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches inventory.yaml inside inventory/ dir', () => {
    expect(triggeredRules(['inventory/inventory.yaml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches production inside ansible/ dir', () => {
    expect(triggeredRules(['ansible/production'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches staging inside .ansible/ dir', () => {
    expect(triggeredRules(['.ansible/staging'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches any yaml file in group_vars/ dir', () => {
    expect(triggeredRules(['ansible/group_vars/all/main.yml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches vault.yml in host_vars/', () => {
    expect(triggeredRules(['host_vars/server1/vault.yml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('matches any yaml inside inventory/ subdirectory', () => {
    expect(triggeredRules(['ansible/inventory/databases.yml'])).toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('does NOT match hosts outside ansible dirs', () => {
    expect(triggeredRules(['config/hosts'])).not.toContain('ANSIBLE_INVENTORY_DRIFT')
  })
  it('does NOT match inside .github/ dir', () => {
    expect(triggeredRules(['.github/ansible/inventory.yml'])).not.toContain('ANSIBLE_INVENTORY_DRIFT')
  })
})

describe('isAnsibleInventoryFile', () => {
  it('returns true for hosts inside ansible/ dir', () => {
    expect(isAnsibleInventoryFile('ansible/hosts', 'hosts')).toBe(true)
  })
  it('returns true for inventory.yml inside playbooks/ dir', () => {
    expect(isAnsibleInventoryFile('playbooks/inventory.yml', 'inventory.yml')).toBe(true)
  })
  it('returns true for production inside inventory/ dir', () => {
    expect(isAnsibleInventoryFile('inventory/production', 'production')).toBe(true)
  })
  it('returns true for any YAML in group_vars/', () => {
    expect(isAnsibleInventoryFile('ansible/group_vars/all/vars.yml', 'vars.yml')).toBe(true)
  })
  it('returns true for any YAML in host_vars/', () => {
    expect(isAnsibleInventoryFile('host_vars/web01/main.yaml', 'main.yaml')).toBe(true)
  })
  it('returns true for JSON in group_vars/', () => {
    expect(isAnsibleInventoryFile('group_vars/databases/config.json', 'config.json')).toBe(true)
  })
  it('returns true for any yaml inside inventory/ subdir', () => {
    expect(isAnsibleInventoryFile('ansible/inventory/staging.yml', 'staging.yml')).toBe(true)
  })
  it('returns false for /etc/hosts', () => {
    expect(isAnsibleInventoryFile('/etc/hosts', 'hosts')).toBe(false)
  })
  it('returns false for hosts outside ansible dirs', () => {
    expect(isAnsibleInventoryFile('app/config/hosts', 'hosts')).toBe(false)
  })
  it('returns false for .github/ paths', () => {
    expect(isAnsibleInventoryFile('.github/workflows/inventory.yml', 'inventory.yml')).toBe(false)
  })
  it('returns false for inventory.yml outside ansible dirs', () => {
    expect(isAnsibleInventoryFile('services/api/inventory.yml', 'inventory.yml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: CHEF_COOKBOOK_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('CHEF_COOKBOOK_SECURITY_DRIFT', () => {
  it('matches Berksfile (ungated)', () => {
    expect(triggeredRules(['Berksfile'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches Berksfile.lock (ungated)', () => {
    expect(triggeredRules(['Berksfile.lock'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches Cheffile (ungated)', () => {
    expect(triggeredRules(['Cheffile'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches Policyfile.rb (ungated)', () => {
    expect(triggeredRules(['Policyfile.rb'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches Policyfile.lock.json (ungated)', () => {
    expect(triggeredRules(['Policyfile.lock.json'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches metadata.rb inside cookbooks/ dir', () => {
    expect(triggeredRules(['cookbooks/nginx/metadata.rb'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches metadata.json inside site-cookbooks/ dir', () => {
    expect(triggeredRules(['site-cookbooks/app/metadata.json'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches any json in data_bags/ dir', () => {
    expect(triggeredRules(['data_bags/users/admin.json'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('matches any json in encrypted_data_bags/ dir', () => {
    expect(triggeredRules(['encrypted_data_bags/secrets/db.json'])).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
  it('does NOT match metadata.rb outside cookbook dirs', () => {
    expect(triggeredRules(['ruby/metadata.rb'])).not.toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: PUPPET_HIERA_DATA_DRIFT
// ---------------------------------------------------------------------------

describe('PUPPET_HIERA_DATA_DRIFT', () => {
  it('matches any .eyaml file (ungated — eye yaml extension)', () => {
    expect(triggeredRules(['secrets.eyaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches common.eyaml (ungated)', () => {
    expect(triggeredRules(['common.eyaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches path/to/production.eyaml (ungated)', () => {
    expect(triggeredRules(['hiera/prod/production.eyaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches common.yaml inside hiera/ dir', () => {
    expect(triggeredRules(['hiera/common.yaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches common.yml inside hieradata/ dir', () => {
    expect(triggeredRules(['hieradata/common.yml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches site.yaml inside puppet/hiera/ dir', () => {
    expect(triggeredRules(['puppet/hiera/site.yaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches secrets.yaml inside puppet/hieradata/ dir', () => {
    expect(triggeredRules(['puppet/hieradata/secrets.yaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('matches any yaml inside hieradata/ dir', () => {
    expect(triggeredRules(['hieradata/role/webserver.yaml'])).toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('does NOT match common.yaml outside hiera dirs', () => {
    expect(triggeredRules(['config/common.yaml'])).not.toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('does NOT match common.yaml inside regular data/ that is not puppet/data/', () => {
    expect(triggeredRules(['data/common.yaml'])).not.toContain('PUPPET_HIERA_DATA_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: CFGMGMT_TEST_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('CFGMGMT_TEST_SECURITY_DRIFT', () => {
  it('matches .kitchen.yml (ungated)', () => {
    expect(triggeredRules(['.kitchen.yml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches .kitchen.yaml (ungated)', () => {
    expect(triggeredRules(['.kitchen.yaml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches .kitchen.local.yml (ungated local override)', () => {
    expect(triggeredRules(['.kitchen.local.yml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches .kitchen.local.yaml (ungated)', () => {
    expect(triggeredRules(['.kitchen.local.yaml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches kitchen-ec2.yml via prefix', () => {
    expect(triggeredRules(['kitchen-ec2.yml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches kitchen-docker.yaml via prefix', () => {
    expect(triggeredRules(['kitchen-docker.yaml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches molecule.yml inside molecule/ dir', () => {
    expect(triggeredRules(['molecule/default/molecule.yml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches converge.yml inside molecule/ dir', () => {
    expect(triggeredRules(['molecule/default/converge.yml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches prepare.yaml inside molecule/ dir', () => {
    expect(triggeredRules(['molecule/default/prepare.yaml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('matches verify.yml inside test/integration/ dir', () => {
    expect(triggeredRules(['test/integration/default/verify.yml'])).toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
  it('does NOT match molecule.yml outside molecule dirs', () => {
    expect(triggeredRules(['docs/molecule.yml'])).not.toContain('CFGMGMT_TEST_SECURITY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('ignores node_modules paths', () => {
    expect(triggeredRules(['node_modules/chef/knife.rb'])).toHaveLength(0)
  })
  it('ignores vendor/ paths', () => {
    expect(triggeredRules(['vendor/puppet/puppet.conf'])).toHaveLength(0)
  })
  it('ignores .git/ paths', () => {
    expect(triggeredRules(['.git/hooks/ansible.cfg'])).toHaveLength(0)
  })
  it('ignores .venv paths', () => {
    expect(triggeredRules(['.venv/ansible/ansible.cfg'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for ansible.cfg', () => {
    expect(triggeredRules(['ansible\\ansible.cfg'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
  it('normalises backslashes for Puppetfile in puppet dir', () => {
    expect(triggeredRules(['puppet\\Puppetfile'])).toContain('PUPPET_MASTER_DRIFT')
  })
  it('normalises backslashes for roster in salt dir', () => {
    expect(triggeredRules(['salt\\roster'])).toContain('SALTSTACK_MASTER_DRIFT')
  })
  it('normalises backslashes for vault.yml in ansible dir', () => {
    expect(triggeredRules(['ansible\\vault.yml'])).toContain('ANSIBLE_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule regardless of matchCount
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('produces one finding for multiple ansible config files', () => {
    const result = scan(['ansible.cfg', 'ansible-prod.cfg', 'ansible/vault.yml'])
    const ansibleFindings = result.findings.filter((f) => f.ruleId === 'ANSIBLE_CONFIG_DRIFT')
    expect(ansibleFindings).toHaveLength(1)
    expect(ansibleFindings[0].matchCount).toBe(3)
  })
  it('produces separate findings for different tools', () => {
    const result = scan(['ansible.cfg', 'knife.rb', 'puppet.conf', 'Saltfile'])
    expect(result.findings.map((f) => f.ruleId)).toEqual(
      expect.arrayContaining([
        'ANSIBLE_CONFIG_DRIFT',
        'CHEF_WORKSTATION_DRIFT',
        'PUPPET_MASTER_DRIFT',
        'SALTSTACK_MASTER_DRIFT',
      ]),
    )
  })
  it('records firstPath correctly', () => {
    const result = scan(['a/ansible.cfg', 'b/ansible-prod.cfg'])
    const finding = result.findings.find((f) => f.ruleId === 'ANSIBLE_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('a/ansible.cfg')
  })
  it('increments matchCount across all matched paths for a rule', () => {
    const result = scan(['Puppetfile', 'Puppetfile.lock', 'puppet.conf', 'hiera.yaml'])
    const finding = result.findings.find((f) => f.ruleId === 'PUPPET_MASTER_DRIFT')
    expect(finding?.matchCount).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and level none for empty input', () => {
    const result = scan([])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
  })
  it('returns score 15 and level low for 1 high finding', () => {
    const result = scan(['ansible.cfg'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })
  it('returns score 8 and level low for 1 medium finding', () => {
    const result = scan(['ansible/hosts'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })
  it('returns score 4 and level low for 1 low finding', () => {
    const result = scan(['.kitchen.yml'])
    expect(result.riskScore).toBe(4)
    expect(result.riskLevel).toBe('low')
  })
  it('caps per-rule score at 45 when matchCount is high', () => {
    // Single high rule with 5 matches — 5×15=75 but per-rule cap is 45
    const files = [
      'ansible.cfg',
      'ansible-prod.cfg',
      'ansible-staging.cfg',
      'ansible/vault.yml',
      'ansible/secrets.yml',
    ]
    const result = scan(files)
    // min(5×15, 45) = 45; score 45 → high
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
  it('score for 4 separate high rules is 60', () => {
    const result = scan([
      'ansible.cfg',   // ANSIBLE_CONFIG_DRIFT
      'knife.rb',      // CHEF_WORKSTATION_DRIFT
      'puppet.conf',   // PUPPET_MASTER_DRIFT
      'Saltfile',      // SALTSTACK_MASTER_DRIFT
    ])
    expect(result.highCount).toBe(4)
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })
  it('reaches critical at score >= 70', () => {
    // 4 high + 2 medium = 4×15 + 2×8 = 76
    const result = scan([
      'ansible.cfg',
      'knife.rb',
      'puppet.conf',
      'Saltfile',
      'ansible/hosts',
      'Berksfile',
    ])
    expect(result.riskScore).toBeGreaterThanOrEqual(70)
    expect(result.riskLevel).toBe('critical')
  })
  it('score is clamped to 100', () => {
    // All 8 rules — 4×15 + 3×8 + 1×4 = 88
    const result = scan([
      'ansible.cfg',
      'knife.rb',
      'puppet.conf',
      'Saltfile',
      'ansible/hosts',
      'Berksfile',
      'hiera/common.yaml',
      '.kitchen.yml',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })
  it('score 15 (1 high) → low', () => {
    expect(scan(['ansible.cfg']).riskLevel).toBe('low')
  })
  it('score 34 (2 high + 1 low) → medium', () => {
    const result = scan(['ansible.cfg', 'knife.rb', '.kitchen.yml'])
    // 2×15 + 1×4 = 34 → medium
    expect(result.riskScore).toBe(34)
    expect(result.riskLevel).toBe('medium')
  })
  it('score 45 (3 high) → high', () => {
    const result = scan(['ansible.cfg', 'knife.rb', 'puppet.conf'])
    // 3×15=45 — score < 45 is false → high
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
  it('score 60 (4 high) → high', () => {
    const result = scan(['ansible.cfg', 'knife.rb', 'puppet.conf', 'Saltfile'])
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })
  it('score 76 (4 high + 2 medium) → critical', () => {
    const result = scan([
      'ansible.cfg', 'knife.rb', 'puppet.conf', 'Saltfile',
      'ansible/hosts', 'Berksfile',
    ])
    expect(result.riskScore).toBe(76)
    expect(result.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('sorts high before medium before low', () => {
    const result = scan(['.kitchen.yml', 'ansible/hosts', 'ansible.cfg'])
    const severities = result.findings.map((f) => f.severity)
    const highIdx   = severities.indexOf('high')
    const mediumIdx = severities.indexOf('medium')
    const lowIdx    = severities.indexOf('low')
    if (highIdx !== -1 && mediumIdx !== -1) expect(highIdx).toBeLessThan(mediumIdx)
    if (mediumIdx !== -1 && lowIdx !== -1) expect(mediumIdx).toBeLessThan(lowIdx)
  })
  it('high rules appear before medium in findings array', () => {
    const result = scan([
      'Berksfile',     // medium
      'ansible.cfg',   // high
      '.kitchen.yml',  // low
    ])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds.indexOf('ANSIBLE_CONFIG_DRIFT')).toBeLessThan(ruleIds.indexOf('CHEF_COOKBOOK_SECURITY_DRIFT'))
    expect(ruleIds.indexOf('CHEF_COOKBOOK_SECURITY_DRIFT')).toBeLessThan(ruleIds.indexOf('CFGMGMT_TEST_SECURITY_DRIFT'))
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('returns expected shape for empty input', () => {
    const result = scan([])
    expect(result).toMatchObject({
      riskScore: 0,
      riskLevel: 'none',
      totalFindings: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findings: [],
    })
    expect(typeof result.summary).toBe('string')
  })
  it('returns correct counts for mixed input', () => {
    const result = scan(['ansible.cfg', 'ansible/hosts', '.kitchen.yml'])
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
    expect(result.totalFindings).toBe(3)
  })
  it('each finding has all required fields', () => {
    const result = scan(['knife.rb'])
    const f = result.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
  it('summary describes no findings', () => {
    expect(scan([]).summary).toContain('No configuration management security drift')
  })
  it('summary includes finding count and score', () => {
    const result = scan(['ansible.cfg'])
    expect(result.summary).toContain('1')
    expect(result.summary).toContain('15/100')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('full CM stack change triggers all 8 rules', () => {
    const result = scan([
      'ansible.cfg',             // ANSIBLE_CONFIG_DRIFT
      'knife.rb',                // CHEF_WORKSTATION_DRIFT
      'puppet.conf',             // PUPPET_MASTER_DRIFT
      'Saltfile',                // SALTSTACK_MASTER_DRIFT
      'ansible/hosts',           // ANSIBLE_INVENTORY_DRIFT
      'Berksfile',               // CHEF_COOKBOOK_SECURITY_DRIFT
      'hiera/common.yaml',       // PUPPET_HIERA_DATA_DRIFT
      '.kitchen.yml',            // CFGMGMT_TEST_SECURITY_DRIFT
    ])
    expect(result.totalFindings).toBe(8)
  })
  it('Berksfile triggers only CHEF_COOKBOOK, not CHEF_WORKSTATION', () => {
    const rules = triggeredRules(['Berksfile'])
    expect(rules).toContain('CHEF_COOKBOOK_SECURITY_DRIFT')
    expect(rules).not.toContain('CHEF_WORKSTATION_DRIFT')
  })
  it('hiera.yaml triggers PUPPET_MASTER, not PUPPET_HIERA_DATA', () => {
    const rules = triggeredRules(['hiera.yaml'])
    expect(rules).toContain('PUPPET_MASTER_DRIFT')
    expect(rules).not.toContain('PUPPET_HIERA_DATA_DRIFT')
  })
  it('common.eyaml triggers only PUPPET_HIERA_DATA', () => {
    const rules = triggeredRules(['common.eyaml'])
    expect(rules).toContain('PUPPET_HIERA_DATA_DRIFT')
    expect(rules).not.toContain('PUPPET_MASTER_DRIFT')
  })
  it('vendor Puppetfile excluded, non-vendor Puppetfile matched', () => {
    const result = scan(['vendor/puppet/Puppetfile', 'Puppetfile'])
    const finding = result.findings.find((f) => f.ruleId === 'PUPPET_MASTER_DRIFT')
    expect(finding?.matchCount).toBe(1)
  })
  it('Saltfile triggers only SALTSTACK_MASTER', () => {
    const rules = triggeredRules(['Saltfile'])
    expect(rules).toContain('SALTSTACK_MASTER_DRIFT')
    expect(rules).not.toContain('ANSIBLE_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('CFG_MGMT_SECURITY_RULES registry', () => {
  it('has exactly 8 rules', () => {
    expect(CFG_MGMT_SECURITY_RULES).toHaveLength(8)
  })
  it('has 4 high severity rules', () => {
    expect(CFG_MGMT_SECURITY_RULES.filter((r) => r.severity === 'high')).toHaveLength(4)
  })
  it('has 3 medium severity rules', () => {
    expect(CFG_MGMT_SECURITY_RULES.filter((r) => r.severity === 'medium')).toHaveLength(3)
  })
  it('has 1 low severity rule', () => {
    expect(CFG_MGMT_SECURITY_RULES.filter((r) => r.severity === 'low')).toHaveLength(1)
  })
  it('all rule IDs are unique', () => {
    const ids = CFG_MGMT_SECURITY_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
  it('all rules have non-empty description and recommendation', () => {
    for (const rule of CFG_MGMT_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(0)
      expect(rule.recommendation.length).toBeGreaterThan(0)
    }
  })
  it('first 4 rules are high severity', () => {
    const first4 = CFG_MGMT_SECURITY_RULES.slice(0, 4)
    expect(first4.every((r) => r.severity === 'high')).toBe(true)
  })
  it('rules 5-7 are medium severity', () => {
    const middle3 = CFG_MGMT_SECURITY_RULES.slice(4, 7)
    expect(middle3.every((r) => r.severity === 'medium')).toBe(true)
  })
  it('last rule is low severity', () => {
    expect(CFG_MGMT_SECURITY_RULES[7].severity).toBe('low')
  })
})
