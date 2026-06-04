// WS-79 — SSO Provider & Authentication Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to single-sign-on and authentication provider configuration files. This
// scanner focuses on the *identity layer* — configurations that govern how
// users authenticate, how identity providers are federated, and how OAuth2 /
// OIDC tokens are issued and validated.
//
// DISTINCT from:
//   WS-60  securityConfigDrift      — application-level JWT/CORS/session
//                                     configs inside backend service code
//   WS-62  cloudSecurityDrift       — cloud IAM resource policies; WS-79
//                                     covers the SSO product config files
//                                     that define authentication flows
//   WS-66  certPkiDrift             — certificate and PKI key material;
//                                     WS-79 covers SSO configuration
//                                     parameters, not the certs themselves
//   WS-70  identityAccessDrift      — general IAM/PAM, Vault policies, LDAP
//                                     server configs; WS-79 covers specific
//                                     SSO product configuration exports
//                                     (Keycloak realm exports, SAML metadata,
//                                     Auth0/Okta tenant configs, oauth2-proxy)
//
// Covered rule groups (8 rules):
//
//   KEYCLOAK_REALM_DRIFT             — Keycloak realm exports, client configs,
//                                      and authentication flow definitions
//   SAML_IDP_SP_DRIFT                — SAML IdP/SP metadata and assertion
//                                      signing configuration
//   OAUTH2_OIDC_PROVIDER_DRIFT       — OAuth2 authorisation server and OIDC
//                                      provider configuration (Ory Hydra,
//                                      Spring Authorization Server, etc.)
//   HOSTED_IDP_CONFIG_DRIFT          — Auth0, Okta, PingFederate, and hosted
//                                      identity provider tenant configurations
//   SSO_MIDDLEWARE_DRIFT             — Self-hosted SSO middleware (Dex,
//                                      Authelia, Authentik, Casdoor, lldap)
//   MFA_PROVIDER_DRIFT               — Multi-factor authentication provider
//                                      integration configs (Duo, YubiKey)
//   SCIM_PROVISIONING_DRIFT          — SCIM user provisioning endpoint and
//                                      attribute mapping configurations
//   IDENTITY_PROXY_DRIFT             — OAuth2-proxy and auth-proxy reverse
//                                      proxy authentication configs
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–78 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • realm-export.json / keycloak.json are globally unambiguous (tool-named).
//   • saml-config.xml / saml-*.xml prefix is self-unambiguous.
//   • metadata.xml is gated on SAML_DIRS (too generic to match ungated).
//   • auth0.json / okta.yaml are ungated; generic config files in IdP dirs
//     require isHostedIdpConfigFile (user contribution) for disambiguation.
//   • isHostedIdpConfigFile is the user contribution — see JSDoc below.
//
// Exports:
//   isHostedIdpConfigFile  — user contribution point (see JSDoc below)
//   SSO_PROVIDER_RULES     — readonly rule registry
//   scanSsoProviderDrift   — main scanner, returns SsoProviderDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SsoProviderRuleId =
  | 'KEYCLOAK_REALM_DRIFT'
  | 'SAML_IDP_SP_DRIFT'
  | 'OAUTH2_OIDC_PROVIDER_DRIFT'
  | 'HOSTED_IDP_CONFIG_DRIFT'
  | 'SSO_MIDDLEWARE_DRIFT'
  | 'MFA_PROVIDER_DRIFT'
  | 'SCIM_PROVISIONING_DRIFT'
  | 'IDENTITY_PROXY_DRIFT'

export type SsoProviderSeverity = 'high' | 'medium' | 'low'
export type SsoProviderRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type SsoProviderDriftFinding = {
  ruleId: SsoProviderRuleId
  severity: SsoProviderSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type SsoProviderDriftResult = {
  riskScore: number
  riskLevel: SsoProviderRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: SsoProviderDriftFinding[]
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

const KEYCLOAK_DIRS  = ['keycloak/', 'keycloak-config/', 'realm/', 'realms/', 'iam/keycloak/']
const SAML_DIRS      = ['saml/', 'saml2/', 'sso/saml/', 'auth/saml/', 'sp/', 'idp/']
const OAUTH_DIRS     = ['oauth/', 'oauth2/', 'oidc/', 'openid-connect/', 'hydra/', 'authorization-server/']
const HOSTED_IDP_DIRS = ['auth0/', 'okta/', 'azure-ad/', 'pingidentity/', 'pingfederate/', 'onelogin/', 'cognito/']
const SSO_DIRS       = ['dex/', 'authelia/', 'authentik/', 'casdoor/', 'sso/', 'lldap/', 'identity/']
const MFA_DIRS       = ['mfa/', 'duo/', 'totp/', '2fa/', 'otp/', 'yubikey/']
const SCIM_DIRS      = ['scim/', 'provisioning/', 'user-provisioning/', 'identity/scim/']
const PROXY_AUTH_DIRS = ['oauth2-proxy/', 'auth-proxy/', 'identity-proxy/', 'sso-proxy/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: KEYCLOAK_REALM_DRIFT (high)
// Keycloak realm exports, client registrations, and authentication flows
// ---------------------------------------------------------------------------

const KEYCLOAK_UNGATED = new Set([
  'realm-export.json',     // Standard Keycloak realm export format
  'keycloak-realm.json',   // Explicit realm export variant
  'keycloak.json',         // Client adapter config or realm config
  'keycloak.yml',          // YAML realm config
  'keycloak.yaml',         // YAML realm config
])

function isKeycloakRealmConfig(pathLower: string, base: string): boolean {
  if (KEYCLOAK_UNGATED.has(base)) return true

  // realm-*.json / realm-*.yaml / keycloak-*.json stage/env configs
  if (base.startsWith('realm-') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('keycloak-') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  if (!inAnyDir(pathLower, KEYCLOAK_DIRS)) return false

  // Canonical Keycloak admin resource filenames
  if (
    base === 'realm.json'        ||  // Realm descriptor
    base === 'client.json'       ||  // Client registration
    base === 'clients.json'      ||  // Client list export
    base === 'flows.json'        ||  // Authentication flow export
    base === 'groups.json'       ||  // Group hierarchy export
    base === 'roles.json'        ||  // Role definitions export
    base === 'users.json'        ||  // User export (carries credential hashes)
    base === 'realm-config.json' ||
    base === 'standalone.xml'    ||  // WildFly/EAP Keycloak subsystem config
    base === 'standalone-ha.xml'
  ) return true

  // Any JSON or YAML in keycloak dirs (realm operator CRDs, Helm values, etc.)
  if (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: SAML_IDP_SP_DRIFT (high)
// SAML identity provider and service provider configuration
// ---------------------------------------------------------------------------

const SAML_UNGATED = new Set([
  'saml-config.xml',        // Canonical SAML configuration — unambiguous
  'saml2-config.xml',       // SAML 2.0 configuration
  'federation-metadata.xml', // WS-Federation / SAML metadata — unambiguous
  'idp-metadata.xml',       // Identity provider metadata
  'sp-metadata.xml',        // Service provider metadata
  'saml.properties',        // Java SAML toolkit properties file
  'saml.conf',              // SAML configuration file
  'saml2.conf',             // SAML 2.0 configuration file
])

function isSamlIdpSpConfig(pathLower: string, base: string): boolean {
  if (SAML_UNGATED.has(base)) return true

  // saml-*.xml / saml-*.properties / saml2-*.xml prefix — file names its tool
  if (base.startsWith('saml-') && (base.endsWith('.xml') || base.endsWith('.properties') || base.endsWith('.conf'))) return true
  if (base.startsWith('saml2-') && base.endsWith('.xml')) return true

  if (!inAnyDir(pathLower, SAML_DIRS)) return false

  // Ambiguous filenames that are high-confidence inside a SAML directory
  if (
    base === 'metadata.xml'    ||  // SAML metadata (IdP or SP)
    base === 'config.xml'      ||  // SAML configuration
    base === 'sp.xml'          ||  // Service provider descriptor
    base === 'idp.xml'         ||  // Identity provider descriptor
    base === 'config.properties'||
    base === 'settings.json'   ||  // php-saml settings
    base === 'settings.yaml'   ||
    base === 'idp.json'        ||
    base === 'sp.json'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: OAUTH2_OIDC_PROVIDER_DRIFT (high)
// OAuth2 authorisation server and OpenID Connect provider configuration
// ---------------------------------------------------------------------------

const OAUTH_UNGATED = new Set([
  'oauth2-server.yaml',         // Generic OAuth2 server config
  'oauth2-server.yml',
  'oidc-config.json',           // OIDC provider configuration
  'oidc-config.yaml',
  'oauth2.json',                // OAuth2 configuration
  'openid-connect.yaml',        // OpenID Connect config
  'hydra.yml',                  // Ory Hydra OAuth2/OIDC server
  'hydra.yaml',
  '.hydra.yaml',
])

function isOAuth2OidcProviderConfig(pathLower: string, base: string): boolean {
  if (OAUTH_UNGATED.has(base)) return true

  // Tool-prefixed configs: oauth2-*.yaml, oidc-*.json, hydra-*.yaml, openid-*.json
  if (base.startsWith('oauth2-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.toml'))) return true
  if (base.startsWith('oidc-') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('hydra-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('openid-') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  if (!inAnyDir(pathLower, OAUTH_DIRS)) return false

  // Ambiguous config filenames inside oauth/oidc directories
  if (
    base === 'config.json'      ||
    base === 'config.yaml'      ||
    base === 'config.yml'       ||
    base === 'server.yaml'      ||
    base === 'server.json'      ||
    base === 'clients.json'     ||  // Registered OAuth clients
    base === 'scopes.json'      ||  // Defined OAuth scopes
    base === 'jwks.json'        ||  // JSON Web Key Set (public keys)
    base === 'application.yaml' ||  // Spring Authorization Server config
    base === 'application.yml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: HOSTED_IDP_CONFIG_DRIFT (high)
// Auth0, Okta, PingFederate, Azure AD, and hosted identity provider configs
// ---------------------------------------------------------------------------

const HOSTED_IDP_UNGATED = new Set([
  'auth0.json',           // Auth0 deploy CLI config or tenant export
  '.auth0.json',          // Hidden auth0 config
  'auth0.yaml',           // Auth0 YAML config
  '.okta.yaml',           // Okta CLI config
  'okta.yaml',            // Okta configuration
  'pingfederate.xml',     // PingFederate server configuration
  'ping-federate.xml',    // Alternate name
  'pingcentral.yaml',     // PingCentral configuration
  'azure-ad.json',        // Azure AD tenant configuration export
  'onelogin.yaml',        // OneLogin configuration
  'cognito-config.json',  // Amazon Cognito configuration
])

/**
 * WS-79 user contribution — determines whether a config file inside a hosted
 * identity provider directory is an actual IdP tenant/application config vs. a
 * generic tool config or test fixture that happens to live near auth code.
 *
 * The challenge: `config.json` in an `auth0/` directory could be the Auth0
 * Deploy CLI config, a Terraform provider config, a test fixture, or a real
 * Auth0 tenant export. Two independent signals raise confidence:
 *
 *   1. IdP-structural keywords in the basename — tenant, application,
 *      connection, rule, action, client, flow, policy, grant, provider — these
 *      only appear in genuine IdP configuration files.
 *   2. IdP-structural subdirectory path segments — connections/, rules/,
 *      actions/, applications/, clients/, grants/, flows/ — these subdirectory
 *      names come from how Auth0, Okta, and PingFederate organise their config
 *      export trees and are not found in general application config directories.
 *
 * Either signal is sufficient for a match. An `.xml` extension inside an
 * auth0/ directory is also high-confidence (Auth0 stores SAML connections as
 * XML, not JSON).
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isHostedIdpConfigFile(pathLower: string, base: string): boolean {
  // Must be inside a recognised hosted IdP or general auth directory
  const AUTH_DIRS = [...HOSTED_IDP_DIRS, 'auth/', 'identity/', 'iam/']
  if (!inAnyDir(pathLower, AUTH_DIRS)) return false

  // Must have a config-appropriate extension
  const CONFIG_EXTS = ['.json', '.yaml', '.yml', '.xml', '.toml', '.properties']
  if (!CONFIG_EXTS.some((ext) => base.endsWith(ext))) return false

  // Signal 1: IdP-structural keyword in the filename
  const IDP_KEYWORDS = [
    'tenant', 'application', 'connection', 'rule', 'action', 'client',
    'settings', 'grant', 'flow', 'policy', 'provider', 'idp', 'sso',
    'oauth', 'oidc', 'saml', 'hook', 'trigger', 'resource-server',
  ]
  if (IDP_KEYWORDS.some((kw) => base.includes(kw))) return true

  // Signal 2: IdP-structural subdirectory in the path
  const IDP_SUBPATHS = [
    'connections/', 'rules/', 'actions/', 'applications/', 'clients/',
    'grants/', 'flows/', 'policies/', 'providers/', 'resource-servers/',
    'hooks/', 'triggers/', 'pages/',
  ]
  if (IDP_SUBPATHS.some((sub) => pathLower.includes(sub))) return true

  // Signal 3: XML extension inside an IdP directory (SAML connections, metadata)
  if (inAnyDir(pathLower, HOSTED_IDP_DIRS) && base.endsWith('.xml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: SSO_MIDDLEWARE_DRIFT (medium)
// Self-hosted SSO middleware: Dex, Authelia, Authentik, Casdoor, lldap
// ---------------------------------------------------------------------------

const SSO_MIDDLEWARE_UNGATED = new Set([
  'dex.yaml',               // Dex OIDC provider — globally unambiguous
  'dex.yml',
  'authelia-config.yml',    // Authelia config — globally unambiguous
  'authelia-config.yaml',
  'authentik.env',          // Authentik environment config
  'casdoor.conf',           // Casdoor configuration
  'casdoor.yaml',
  'lldap.yml',              // lldap (Lightweight LDAP) config
  'lldap.yaml',
])

function isSsoMiddlewareConfig(pathLower: string, base: string): boolean {
  if (SSO_MIDDLEWARE_UNGATED.has(base)) return true

  // Tool-prefixed configs: dex-*.yaml, authelia-*.yml, authentik-*.yaml
  if (base.startsWith('dex-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('authelia-') && (base.endsWith('.yml') || base.endsWith('.yaml'))) return true
  if (base.startsWith('authentik-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.env'))) return true
  if (base.startsWith('casdoor-') && (base.endsWith('.yaml') || base.endsWith('.conf') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, SSO_DIRS)) return false

  // Ambiguous config filenames inside SSO-specific directories
  if (
    base === 'config.yaml' ||
    base === 'config.yml'  ||
    base === 'config.json' ||
    base === 'configuration.yaml' ||
    base === 'configuration.yml'  ||
    base === '.env'        ||       // SSO environment variables (inside sso/ dir)
    base === 'values.yaml' ||       // Helm values for SSO chart
    base === 'values.yml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: MFA_PROVIDER_DRIFT (medium)
// Multi-factor authentication provider integration configurations
// ---------------------------------------------------------------------------

const MFA_UNGATED = new Set([
  'duo.ini',                  // Duo Security integration config — unambiguous
  'duo.conf',
  'duosecurity.conf',         // Legacy Duo config name
  'pam_duo.conf',             // Duo PAM module configuration
  'yubikey.conf',             // YubiKey configuration file
  'yubico.conf',              // Yubico client configuration
  'google-authenticator.conf',// Google Authenticator PAM config
])

function isMfaProviderConfig(pathLower: string, base: string): boolean {
  if (MFA_UNGATED.has(base)) return true

  // Tool-prefixed configs: duo-*.ini, mfa-*.yaml, totp-*.yaml, yubikey-*.conf
  if (base.startsWith('duo-') && (base.endsWith('.ini') || base.endsWith('.conf') || base.endsWith('.json'))) return true
  if (base.startsWith('mfa-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('totp-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('yubikey-') && (base.endsWith('.conf') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, MFA_DIRS)) return false

  // Ambiguous config filenames inside MFA-specific directories
  if (
    base === 'config.ini'  ||
    base === 'config.conf' ||
    base === 'config.yaml' ||
    base === 'config.yml'  ||
    base === 'config.json'
  ) return true

  // Any .conf or .ini in MFA directories
  if (base.endsWith('.conf') || base.endsWith('.ini')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: SCIM_PROVISIONING_DRIFT (medium)
// SCIM user provisioning endpoint and attribute mapping configuration
// ---------------------------------------------------------------------------

const SCIM_UNGATED = new Set([
  'scim-config.json',    // SCIM configuration — globally unambiguous
  'scim-config.yaml',
  'scim-config.yml',
  'scim.json',           // SCIM configuration
  'scim.yaml',
  'scim2.yaml',          // SCIM 2.0 configuration
])

function isScimProvisioningConfig(pathLower: string, base: string): boolean {
  if (SCIM_UNGATED.has(base)) return true

  // Tool-prefixed configs: scim-*.json, scim-*.yaml, scim2-*.yaml
  if (base.startsWith('scim-') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.xml'))) return true
  if (base.startsWith('scim2-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, SCIM_DIRS)) return false

  // Ambiguous config filenames inside SCIM/provisioning directories
  if (
    base === 'config.json'   ||
    base === 'config.yaml'   ||
    base === 'config.yml'    ||
    base === 'mapping.json'  ||   // Attribute mapping configuration
    base === 'mapping.yaml'  ||
    base === 'schema.json'   ||   // SCIM schema definition
    base === 'schema.yaml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: IDENTITY_PROXY_DRIFT (low)
// OAuth2-proxy and auth-proxy reverse proxy authentication configs
// ---------------------------------------------------------------------------

const PROXY_UNGATED = new Set([
  'oauth2-proxy.cfg',     // oauth2-proxy configuration — globally unambiguous
  'oauth2-proxy.yaml',
  'oauth2-proxy.toml',
  'oauth2-proxy.ini',
  'oauth2proxy.cfg',      // Alternate naming convention
])

function isIdentityProxyConfig(pathLower: string, base: string): boolean {
  if (PROXY_UNGATED.has(base)) return true

  // Tool-prefixed configs: oauth2-proxy-*.yaml, oauth2proxy-*.cfg
  if (base.startsWith('oauth2-proxy-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.cfg') || base.endsWith('.toml'))) return true
  if (base.startsWith('oauth2proxy-') && (base.endsWith('.cfg') || base.endsWith('.yaml') || base.endsWith('.toml'))) return true

  if (!inAnyDir(pathLower, PROXY_AUTH_DIRS)) return false

  // Ambiguous filenames inside identity proxy directories
  if (
    base === 'config.cfg'   ||
    base === 'config.yaml'  ||
    base === 'config.yml'   ||
    base === 'config.toml'  ||
    base === 'config.ini'   ||
    base === 'values.yaml'     // Helm chart values for oauth2-proxy
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const SSO_PROVIDER_RULES: ReadonlyArray<{
  id: SsoProviderRuleId
  severity: SsoProviderSeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'KEYCLOAK_REALM_DRIFT',
    severity: 'high',
    description: 'Keycloak realm, client, or authentication flow configuration change detected.',
    recommendation:
      'Review realm security settings (token lifetimes, password policies), audit client credential and redirect URI changes, verify authentication flow steps have not been weakened, and confirm realm export does not expose production credential hashes.',
    match: isKeycloakRealmConfig,
  },
  {
    id: 'SAML_IDP_SP_DRIFT',
    severity: 'high',
    description: 'SAML identity provider or service provider configuration change detected.',
    recommendation:
      'Verify IdP metadata has not been replaced with an untrusted source, audit assertion signing and encryption certificate changes, review attribute mapping modifications, and confirm Single Logout configuration is intact.',
    match: isSamlIdpSpConfig,
  },
  {
    id: 'OAUTH2_OIDC_PROVIDER_DRIFT',
    severity: 'high',
    description: 'OAuth2 authorisation server or OIDC provider configuration change detected.',
    recommendation:
      'Audit allowed redirect URIs and client credential changes, verify token signing key configuration, review scope definitions and consent settings, and confirm PKCE enforcement is enabled for public clients.',
    match: isOAuth2OidcProviderConfig,
  },
  {
    id: 'HOSTED_IDP_CONFIG_DRIFT',
    severity: 'high',
    description: 'Hosted identity provider (Auth0, Okta, PingFederate) configuration change detected.',
    recommendation:
      'Review connection and application settings for credential or callback URI changes, audit authentication rule or action logic for injected code, verify MFA policy changes are intentional, and confirm tenant export does not contain plaintext secrets.',
    match: (p, b) => HOSTED_IDP_UNGATED.has(b) || isHostedIdpConfigFile(p, b),
  },
  {
    id: 'SSO_MIDDLEWARE_DRIFT',
    severity: 'medium',
    description: 'Self-hosted SSO middleware (Dex, Authelia, Authentik) configuration change detected.',
    recommendation:
      'Review connector and upstream IdP credential changes, audit session and cookie security settings, verify MFA bypass configuration has not been loosened, and confirm HTTPS redirect rules are in place.',
    match: isSsoMiddlewareConfig,
  },
  {
    id: 'MFA_PROVIDER_DRIFT',
    severity: 'medium',
    description: 'Multi-factor authentication provider integration configuration change detected.',
    recommendation:
      'Verify Duo integration keys and API hostnames have not been replaced, audit user group exemptions that bypass MFA, and confirm fail-open behaviour (allowing login when MFA is unavailable) has not been inadvertently introduced.',
    match: isMfaProviderConfig,
  },
  {
    id: 'SCIM_PROVISIONING_DRIFT',
    severity: 'medium',
    description: 'SCIM user provisioning endpoint or attribute mapping configuration change detected.',
    recommendation:
      'Review provisioning endpoint URL and bearer token changes, audit attribute mapping modifications that could grant unintended group memberships, and verify that deprovisioning (account suspension) is correctly configured.',
    match: isScimProvisioningConfig,
  },
  {
    id: 'IDENTITY_PROXY_DRIFT',
    severity: 'low',
    description: 'OAuth2-proxy or auth-proxy reverse proxy authentication configuration change detected.',
    recommendation:
      'Verify upstream provider client ID and secret configuration, review skip-auth-route or whitelist changes that may expose endpoints, audit cookie secret rotation, and confirm secure cookie flags are set.',
    match: isIdentityProxyConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<SsoProviderSeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: SsoProviderDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): SsoProviderRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanSsoProviderDrift(changedFiles: string[]): SsoProviderDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: SsoProviderDriftFinding[] = []

  for (const rule of SSO_PROVIDER_RULES) {
    let firstPath  = ''
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
  const ORDER: Record<SsoProviderSeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No SSO provider or authentication configuration changes detected.'
      : `${findings.length} SSO security rule${findings.length === 1 ? '' : 's'} triggered ` +
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
