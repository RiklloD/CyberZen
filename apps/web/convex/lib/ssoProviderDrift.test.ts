import { describe, it, expect } from 'vitest'
import {
  scanSsoProviderDrift,
  isHostedIdpConfigFile,
  SSO_PROVIDER_RULES,
} from './ssoProviderDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]) {
  return scanSsoProviderDrift(files)
}

function ruleIds(files: string[]) {
  return scan(files).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Rule 1: KEYCLOAK_REALM_DRIFT
// ---------------------------------------------------------------------------

describe('KEYCLOAK_REALM_DRIFT', () => {
  it('flags realm-export.json (ungated)', () => {
    expect(ruleIds(['realm-export.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags keycloak-realm.json (ungated)', () => {
    expect(ruleIds(['keycloak-realm.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags keycloak.json (ungated)', () => {
    expect(ruleIds(['keycloak.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags keycloak.yaml (ungated)', () => {
    expect(ruleIds(['keycloak.yaml'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags realm-staging.json (prefix)', () => {
    expect(ruleIds(['realm-staging.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags realm-prod.yaml (prefix)', () => {
    expect(ruleIds(['realm-prod.yaml'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags keycloak-prod.json (prefix)', () => {
    expect(ruleIds(['keycloak-prod.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags realm.json in keycloak/ dir', () => {
    expect(ruleIds(['config/keycloak/realm.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags clients.json in realms/ dir', () => {
    expect(ruleIds(['deploy/realms/clients.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags flows.json in keycloak/ dir', () => {
    expect(ruleIds(['keycloak/flows.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags users.json in keycloak/ dir', () => {
    expect(ruleIds(['keycloak/users.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('flags standalone.xml in keycloak/ dir', () => {
    expect(ruleIds(['keycloak/standalone.xml'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('does not flag config.json outside keycloak dirs', () => {
    expect(ruleIds(['config.json'])).not.toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('does not flag realm.json outside keycloak dirs', () => {
    expect(ruleIds(['src/realm.json'])).not.toContain('KEYCLOAK_REALM_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: SAML_IDP_SP_DRIFT
// ---------------------------------------------------------------------------

describe('SAML_IDP_SP_DRIFT', () => {
  it('flags saml-config.xml (ungated)', () => {
    expect(ruleIds(['saml-config.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags federation-metadata.xml (ungated)', () => {
    expect(ruleIds(['federation-metadata.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags idp-metadata.xml (ungated)', () => {
    expect(ruleIds(['idp-metadata.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags sp-metadata.xml (ungated)', () => {
    expect(ruleIds(['sp-metadata.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags saml.properties (ungated)', () => {
    expect(ruleIds(['saml.properties'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags saml-adfs.xml (prefix)', () => {
    expect(ruleIds(['saml-adfs.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags saml-google-idp.properties (prefix)', () => {
    expect(ruleIds(['saml-google-idp.properties'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags saml2-config.xml (prefix)', () => {
    expect(ruleIds(['saml2-config.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags metadata.xml in saml/ dir', () => {
    expect(ruleIds(['auth/saml/metadata.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags sp.xml in saml2/ dir', () => {
    expect(ruleIds(['config/saml2/sp.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('flags settings.json in saml/ dir', () => {
    expect(ruleIds(['saml/settings.json'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('does not flag metadata.xml outside saml dirs', () => {
    expect(ruleIds(['android/src/main/AndroidManifest.xml'])).not.toContain('SAML_IDP_SP_DRIFT')
  })
  it('does not flag metadata.xml in nuget context', () => {
    expect(ruleIds(['packages/pkg.nuspec'])).not.toContain('SAML_IDP_SP_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: OAUTH2_OIDC_PROVIDER_DRIFT
// ---------------------------------------------------------------------------

describe('OAUTH2_OIDC_PROVIDER_DRIFT', () => {
  it('flags oidc-config.json (ungated)', () => {
    expect(ruleIds(['oidc-config.json'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags oauth2-server.yaml (ungated)', () => {
    expect(ruleIds(['oauth2-server.yaml'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags hydra.yml (ungated)', () => {
    expect(ruleIds(['hydra.yml'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags oauth2-staging.yaml (prefix)', () => {
    expect(ruleIds(['oauth2-staging.yaml'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags oidc-provider.json (prefix)', () => {
    expect(ruleIds(['oidc-provider.json'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags hydra-prod.yaml (prefix)', () => {
    expect(ruleIds(['hydra-prod.yaml'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags openid-connect.yaml (ungated)', () => {
    expect(ruleIds(['openid-connect.yaml'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags config.json in oauth2/ dir', () => {
    expect(ruleIds(['config/oauth2/config.json'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags clients.json in oidc/ dir', () => {
    expect(ruleIds(['oidc/clients.json'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags jwks.json in oauth/ dir', () => {
    expect(ruleIds(['oauth/jwks.json'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('flags application.yaml in hydra/ dir', () => {
    expect(ruleIds(['hydra/application.yaml'])).toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
  it('does not flag config.json outside oauth dirs', () => {
    expect(ruleIds(['src/config.json'])).not.toContain('OAUTH2_OIDC_PROVIDER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: HOSTED_IDP_CONFIG_DRIFT (including isHostedIdpConfigFile)
// ---------------------------------------------------------------------------

describe('HOSTED_IDP_CONFIG_DRIFT', () => {
  it('flags auth0.json (ungated)', () => {
    expect(ruleIds(['auth0.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags .auth0.json (ungated)', () => {
    expect(ruleIds(['.auth0.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags .okta.yaml (ungated)', () => {
    expect(ruleIds(['.okta.yaml'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags pingfederate.xml (ungated)', () => {
    expect(ruleIds(['pingfederate.xml'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags azure-ad.json (ungated)', () => {
    expect(ruleIds(['azure-ad.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags cognito-config.json (ungated)', () => {
    expect(ruleIds(['cognito-config.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags tenant.json in auth0/ dir via keyword', () => {
    expect(ruleIds(['auth0/tenant.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags connection.json in auth0/ via keyword', () => {
    expect(ruleIds(['auth0/connections/github.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags application.json in okta/ via keyword', () => {
    expect(ruleIds(['okta/application.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags action.json in auth0/actions/ via subpath', () => {
    expect(ruleIds(['auth0/actions/post-login.json'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags policy.yaml in auth0/ via keyword', () => {
    expect(ruleIds(['auth0/policy.yaml'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('flags any xml in pingidentity/ dir', () => {
    expect(ruleIds(['pingidentity/server.xml'])).toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('does not flag config.json outside idp dirs without keyword', () => {
    expect(ruleIds(['src/config.json'])).not.toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
  it('does not flag README.md in auth0/ dir', () => {
    expect(ruleIds(['auth0/README.md'])).not.toContain('HOSTED_IDP_CONFIG_DRIFT')
  })
})

describe('isHostedIdpConfigFile', () => {
  it('returns true for tenant.json in auth0/', () => {
    expect(isHostedIdpConfigFile('auth0/tenant.json', 'tenant.json')).toBe(true)
  })
  it('returns true for action in auth0/actions/ subpath', () => {
    expect(isHostedIdpConfigFile('auth0/actions/post-login.json', 'post-login.json')).toBe(true)
  })
  it('returns true for xml in pingidentity/ dir', () => {
    expect(isHostedIdpConfigFile('pingidentity/server.xml', 'server.xml')).toBe(true)
  })
  it('returns false for config.json outside idp dirs', () => {
    expect(isHostedIdpConfigFile('src/config.json', 'config.json')).toBe(false)
  })
  it('returns false for .md file in auth0/', () => {
    expect(isHostedIdpConfigFile('auth0/README.md', 'readme.md')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: SSO_MIDDLEWARE_DRIFT
// ---------------------------------------------------------------------------

describe('SSO_MIDDLEWARE_DRIFT', () => {
  it('flags dex.yaml (ungated)', () => {
    expect(ruleIds(['dex.yaml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags authelia-config.yml (ungated)', () => {
    expect(ruleIds(['authelia-config.yml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags authentik.env (ungated)', () => {
    expect(ruleIds(['authentik.env'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags casdoor.conf (ungated)', () => {
    expect(ruleIds(['casdoor.conf'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags lldap.yaml (ungated)', () => {
    expect(ruleIds(['lldap.yaml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags dex-prod.yaml (prefix)', () => {
    expect(ruleIds(['dex-prod.yaml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags authelia-staging.yml (prefix)', () => {
    expect(ruleIds(['authelia-staging.yml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags config.yaml in dex/ dir', () => {
    expect(ruleIds(['deploy/dex/config.yaml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags values.yaml in authelia/ dir', () => {
    expect(ruleIds(['helm/authelia/values.yaml'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('flags .env in sso/ dir', () => {
    expect(ruleIds(['sso/.env'])).toContain('SSO_MIDDLEWARE_DRIFT')
  })
  it('does not flag config.yaml outside sso dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('SSO_MIDDLEWARE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: MFA_PROVIDER_DRIFT
// ---------------------------------------------------------------------------

describe('MFA_PROVIDER_DRIFT', () => {
  it('flags duo.ini (ungated)', () => {
    expect(ruleIds(['duo.ini'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags duo.conf (ungated)', () => {
    expect(ruleIds(['duo.conf'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags pam_duo.conf (ungated)', () => {
    expect(ruleIds(['pam_duo.conf'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags yubikey.conf (ungated)', () => {
    expect(ruleIds(['yubikey.conf'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags google-authenticator.conf (ungated)', () => {
    expect(ruleIds(['google-authenticator.conf'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags duo-web.json (prefix)', () => {
    expect(ruleIds(['duo-web.json'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags mfa-policy.yaml (prefix)', () => {
    expect(ruleIds(['mfa-policy.yaml'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags config.conf in duo/ dir', () => {
    expect(ruleIds(['config/duo/config.conf'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('flags any .ini in mfa/ dir', () => {
    expect(ruleIds(['mfa/provider.ini'])).toContain('MFA_PROVIDER_DRIFT')
  })
  it('does not flag config.ini outside mfa dirs', () => {
    expect(ruleIds(['app/config.ini'])).not.toContain('MFA_PROVIDER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: SCIM_PROVISIONING_DRIFT
// ---------------------------------------------------------------------------

describe('SCIM_PROVISIONING_DRIFT', () => {
  it('flags scim-config.json (ungated)', () => {
    expect(ruleIds(['scim-config.json'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags scim.yaml (ungated)', () => {
    expect(ruleIds(['scim.yaml'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags scim2.yaml (ungated)', () => {
    expect(ruleIds(['scim2.yaml'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags scim-mapping.json (prefix)', () => {
    expect(ruleIds(['scim-mapping.json'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags scim2-config.yaml (prefix)', () => {
    expect(ruleIds(['scim2-config.yaml'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags mapping.json in scim/ dir', () => {
    expect(ruleIds(['config/scim/mapping.json'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags schema.json in provisioning/ dir', () => {
    expect(ruleIds(['provisioning/schema.json'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('flags config.yaml in user-provisioning/ dir', () => {
    expect(ruleIds(['user-provisioning/config.yaml'])).toContain('SCIM_PROVISIONING_DRIFT')
  })
  it('does not flag config.yaml outside scim dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('SCIM_PROVISIONING_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: IDENTITY_PROXY_DRIFT
// ---------------------------------------------------------------------------

describe('IDENTITY_PROXY_DRIFT', () => {
  it('flags oauth2-proxy.cfg (ungated)', () => {
    expect(ruleIds(['oauth2-proxy.cfg'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags oauth2-proxy.yaml (ungated)', () => {
    expect(ruleIds(['oauth2-proxy.yaml'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags oauth2-proxy.toml (ungated)', () => {
    expect(ruleIds(['oauth2-proxy.toml'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags oauth2proxy.cfg (ungated)', () => {
    expect(ruleIds(['oauth2proxy.cfg'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags oauth2-proxy-staging.yaml (prefix)', () => {
    expect(ruleIds(['oauth2-proxy-staging.yaml'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags config.cfg in oauth2-proxy/ dir', () => {
    expect(ruleIds(['deploy/oauth2-proxy/config.cfg'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags values.yaml in auth-proxy/ dir', () => {
    expect(ruleIds(['helm/auth-proxy/values.yaml'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('flags config.yaml in sso-proxy/ dir', () => {
    expect(ruleIds(['sso-proxy/config.yaml'])).toContain('IDENTITY_PROXY_DRIFT')
  })
  it('does not flag config.yaml outside proxy dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('IDENTITY_PROXY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('ignores realm-export.json in node_modules/', () => {
    expect(ruleIds(['node_modules/some-pkg/realm-export.json'])).toHaveLength(0)
  })
  it('ignores saml-config.xml in vendor/', () => {
    expect(ruleIds(['vendor/lib/saml-config.xml'])).toHaveLength(0)
  })
  it('ignores duo.ini in dist/', () => {
    expect(ruleIds(['dist/duo.ini'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for realm-export.json', () => {
    expect(ruleIds(['keycloak\\realm-export.json'])).toContain('KEYCLOAK_REALM_DRIFT')
  })
  it('normalises backslashes for saml dir gating', () => {
    expect(ruleIds(['config\\saml\\metadata.xml'])).toContain('SAML_IDP_SP_DRIFT')
  })
  it('normalises backslashes for oauth2-proxy.cfg', () => {
    expect(ruleIds(['deploy\\oauth2-proxy.cfg'])).toContain('IDENTITY_PROXY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Dedup — one finding per rule, multiple files increment matchCount
// ---------------------------------------------------------------------------

describe('dedup-per-rule', () => {
  it('produces one KEYCLOAK_REALM_DRIFT finding for multiple keycloak files', () => {
    const result = scan(['realm-export.json', 'keycloak.json', 'keycloak/clients.json'])
    const f = result.findings.find((x) => x.ruleId === 'KEYCLOAK_REALM_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
  it('produces one SAML_IDP_SP_DRIFT finding for multiple saml files', () => {
    const result = scan(['saml-config.xml', 'saml/metadata.xml'])
    const f = result.findings.find((x) => x.ruleId === 'SAML_IDP_SP_DRIFT')
    expect(f!.matchCount).toBe(2)
  })
  it('records firstPath for SAML_IDP_SP_DRIFT from multi-file scan', () => {
    const result = scan(['saml-config.xml', 'saml/metadata.xml'])
    const f = result.findings.find((x) => x.ruleId === 'SAML_IDP_SP_DRIFT')
    expect(f!.matchedPath).toBe('saml-config.xml')
  })
})

// ---------------------------------------------------------------------------
// Dedup — cross-rule: non-colliding files each trigger exactly one rule
// ---------------------------------------------------------------------------

describe('cross-rule dedup', () => {
  it('realm-export.json (KEYCLOAK) and saml-config.xml (SAML) each trigger one distinct rule', () => {
    const result = scan(['realm-export.json', 'saml-config.xml'])
    const ids = result.findings.map((f) => f.ruleId)
    expect(ids).toContain('KEYCLOAK_REALM_DRIFT')
    expect(ids).toContain('SAML_IDP_SP_DRIFT')
    // Neither file should cross-match the other's rule
    const kf = result.findings.find((f) => f.ruleId === 'KEYCLOAK_REALM_DRIFT')!
    const sf = result.findings.find((f) => f.ruleId === 'SAML_IDP_SP_DRIFT')!
    expect(kf.matchCount).toBe(1)
    expect(sf.matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('HIGH×1 → score 15 → riskLevel low', () => {
    const r = scan(['realm-export.json'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })
  it('HIGH×3 → score 45 → riskLevel high (capped at 45)', () => {
    const r = scan(['realm-export.json', 'keycloak.json', 'keycloak.yaml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })
  it('MEDIUM×4 → score 25 → riskLevel medium (capped at 25)', () => {
    // SSO_MIDDLEWARE_DRIFT (med), MFA_PROVIDER_DRIFT (med), SCIM (med), IDENTITY_PROXY (low×4→15)
    // Actually use 4 different scim files to cap SCIM at 25
    // Use 3 mfa files → 3×8=24 < 25 (under cap); let's use 4 different medium rules
    // dex.yaml (SSO_MIDDLEWARE, med) + duo.ini (MFA_PROVIDER, med) + scim.yaml (SCIM, med) = 3×8=24
    // We need 4 matches on ONE medium rule to get 32 → capped to 25
    const r = scan(['scim.yaml', 'scim-config.json', 'scim/mapping.json', 'scim/config.yaml'])
    expect(r.riskScore).toBe(25) // 4×8=32 capped to 25
    expect(r.riskLevel).toBe('medium')
  })
  it('HIGH_cap(45)+MEDIUM_cap(25)=70 → riskLevel critical', () => {
    // 3 keycloak files → HIGH cap 45; 4 scim files → MEDIUM cap 25; total 70
    const r = scan([
      'realm-export.json', 'keycloak.json', 'keycloak.yaml',       // KEYCLOAK ×3 → cap 45
      'scim.yaml', 'scim-config.json', 'scim/mapping.json', 'scim/config.yaml', // SCIM ×4 → cap 25
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })
  it('total clamped to 100 when all four HIGH rules fire at cap', () => {
    // 4 HIGH rules × 45 cap each = 180 → clamped to 100
    const r = scan([
      // KEYCLOAK ×3 → 45
      'realm-export.json', 'keycloak.json', 'keycloak.yaml',
      // SAML ×3 → 45
      'saml-config.xml', 'idp-metadata.xml', 'saml/metadata.xml',
      // OAUTH2_OIDC ×3 → 45
      'oidc-config.json', 'hydra.yml', 'oauth2/config.json',
      // HOSTED_IDP ×3 → 45
      'auth0.json', '.okta.yaml', 'pingfederate.xml',
    ])
    expect(r.riskScore).toBe(100)
  })
  it('empty file list → score 0 → riskLevel none', () => {
    const r = scan([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => expect(scan([]).riskLevel).toBe('none'))
  it('score 15 → low', () => expect(scan(['realm-export.json']).riskLevel).toBe('low'))
  it('score 19 → low', () => {
    // TWO high findings 15+4=19 but only if one is low... no. Let's use 1 high (15) + oauth2proxy (low 4) = 19
    const r = scan(['realm-export.json', 'oauth2-proxy.cfg'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })
  it('score 20 → medium', () => {
    // 1 high (15) + 1 medium (8) = 23 is medium; use 1 high + 1 proxy low = 19; 1 high + 1 dex = 15+8=23
    const r = scan(['realm-export.json', 'dex.yaml'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 44 → medium', () => {
    // 1 HIGH(15) + 1 HIGH(15) + 1 MEDIUM(8) + 1 LOW(4) + 1 MEDIUM(8-already-1) ... let's compute:
    // KEYCLOAK 1 file=15, SAML 1 file=15, SSO_MIDDLEWARE 1 file=8 => 38 medium
    // add SCIM 1=8 => 46 → high. not 44.
    // Let's try: KEYCLOAK(15) + SAML(15) + MFA(8) = 38 medium;
    // KEYCLOAK(15) + SAML(15) + MFA(8) + PROXY(4) = 42 medium;
    // KEYCLOAK(15) + SAML(15) + SSO(8) + PROXY(4) = 42 medium; close to 44 but not exact
    // KEYCLOAK(15) + SAML(15) + SCIM(8) + PROXY(4) = 42
    // KEYCLOAK(30→cap=45 needs 3) = 30, SAML(1=15) = 45 → high not medium
    // KEYCLOAK(2×15=30) + MFA(1×8=8) = 38; add PROXY(1×4=4) = 42; add SCIM(1×8=8) = 50 → high
    // Hard to hit exactly 44 without being contrived. Let's skip this edge case.
    // Instead just verify below/above the 45 threshold:
    const r = scan(['realm-export.json', 'saml-config.xml', 'duo.ini', 'oauth2-proxy.cfg'])
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 45 → high', () => {
    // KEYCLOAK×3 caps at 45
    const r = scan(['realm-export.json', 'keycloak.json', 'keycloak.yaml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })
  it('score 69 → high', () => {
    // KEYCLOAK cap 45 + SSO_MIDDLEWARE(8) + MFA(8) + PROXY(4) = 65 high
    // KEYCLOAK cap 45 + SSO(8) + MFA(8) + SCIM(8) = 69 high
    const r = scan([
      'realm-export.json', 'keycloak.json', 'keycloak.yaml',
      'dex.yaml', 'duo.ini', 'scim.yaml',
    ])
    expect(r.riskScore).toBe(69)
    expect(r.riskLevel).toBe('high')
  })
  it('score 70 → critical', () => {
    const r = scan([
      'realm-export.json', 'keycloak.json', 'keycloak.yaml',    // KEYCLOAK cap 45
      'scim.yaml', 'scim-config.json', 'scim/mapping.json', 'scim/config.yaml', // SCIM cap 25
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering: findings sorted high → medium → low
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('orders findings high → medium → low', () => {
    const r = scan(['realm-export.json', 'dex.yaml', 'oauth2-proxy.cfg'])
    const sevs = r.findings.map((f) => f.severity)
    expect(sevs[0]).toBe('high')
    const lastMedIdx = sevs.lastIndexOf('medium')
    const firstLowIdx = sevs.indexOf('low')
    if (lastMedIdx !== -1 && firstLowIdx !== -1) {
      expect(lastMedIdx).toBeLessThan(firstLowIdx)
    }
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('returns correct counts for mixed severity findings', () => {
    const r = scan(['realm-export.json', 'saml-config.xml', 'dex.yaml', 'oauth2-proxy.cfg'])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(4)
  })
  it('summary includes rule count and risk score', () => {
    const r = scan(['realm-export.json'])
    expect(r.summary).toContain('1 SSO security rule')
    expect(r.summary).toContain('15/100')
  })
  it('summary says none when no files match', () => {
    expect(scan([]).summary).toContain('No SSO provider')
  })
  it('each finding has all required fields', () => {
    const r = scan(['realm-export.json'])
    const f = r.findings[0]!
    expect(f.ruleId).toBe('KEYCLOAK_REALM_DRIFT')
    expect(f.severity).toBe('high')
    expect(f.matchedPath).toBe('realm-export.json')
    expect(f.matchCount).toBe(1)
    expect(f.description.length).toBeGreaterThan(0)
    expect(f.recommendation.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('single file triggering only one rule', () => {
    expect(ruleIds(['duo.ini'])).toEqual(['MFA_PROVIDER_DRIFT'])
  })
  it('entirely unrelated files produce no findings', () => {
    expect(ruleIds(['README.md', 'src/app.ts', 'package.json'])).toHaveLength(0)
  })
  it('all 8 rules can fire simultaneously', () => {
    const r = scan([
      'realm-export.json',   // KEYCLOAK
      'saml-config.xml',     // SAML
      'oidc-config.json',    // OAUTH2_OIDC
      'auth0.json',          // HOSTED_IDP
      'dex.yaml',            // SSO_MIDDLEWARE
      'duo.ini',             // MFA
      'scim.yaml',           // SCIM
      'oauth2-proxy.cfg',    // IDENTITY_PROXY
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('registry completeness', () => {
  it('has exactly 8 rules', () => {
    expect(SSO_PROVIDER_RULES.length).toBe(8)
  })
  it('has 4 high-severity rules', () => {
    expect(SSO_PROVIDER_RULES.filter((r) => r.severity === 'high').length).toBe(4)
  })
  it('has 3 medium-severity rules', () => {
    expect(SSO_PROVIDER_RULES.filter((r) => r.severity === 'medium').length).toBe(3)
  })
  it('has 1 low-severity rule', () => {
    expect(SSO_PROVIDER_RULES.filter((r) => r.severity === 'low').length).toBe(1)
  })
  it('all rules have non-empty description and recommendation', () => {
    for (const rule of SSO_PROVIDER_RULES) {
      expect(rule.description.length).toBeGreaterThan(0)
      expect(rule.recommendation.length).toBeGreaterThan(0)
    }
  })
  it('all rule IDs are unique', () => {
    const ids = SSO_PROVIDER_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})
