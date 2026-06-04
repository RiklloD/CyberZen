/**
 * §6.26 SSO/SAML Configuration
 *
 * CRUD for SAML/OIDC identity provider configurations per tenant.
 * Schema already has `ssoConfigs` and `ssoTestLogins` tables.
 */
import { v } from 'convex/values'
import { mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

// ---------------------------------------------------------------------------
// SAML metadata validation helpers
// ---------------------------------------------------------------------------

function rejectXxe(xml: string): string | null {
  // Block DOCTYPE declarations entirely — these are the vector for XXE attacks
  if (/<!DOCTYPE/i.test(xml)) return 'SAML metadata must not contain a DOCTYPE declaration (XXE risk).'
  if (/<!ENTITY/i.test(xml)) return 'SAML metadata must not contain ENTITY declarations (XXE risk).'
  return null
}

function validateSamlFields(args: {
  protocol: string
  samlEntityId?: string
  samlSsoUrl?: string
  samlCertificate?: string
  samlMetadataXml?: string
}): string | null {
  if (args.protocol !== 'saml') return null

  // If no metadata XML is provided, require the key fields individually
  if (!args.samlMetadataXml) {
    if (!args.samlEntityId?.trim()) return 'SAML Entity ID is required.'
    if (!args.samlSsoUrl?.trim()) return 'SAML SSO URL is required.'
  }

  // SSO URL must be HTTPS when provided
  if (args.samlSsoUrl) {
    try {
      const u = new URL(args.samlSsoUrl)
      if (u.protocol !== 'https:') return 'SAML SSO URL must use HTTPS.'
    } catch {
      return 'SAML SSO URL is not a valid URL.'
    }
  }

  // Certificate format check (PEM)
  if (args.samlCertificate) {
    const cert = args.samlCertificate.trim()
    if (!cert.includes('BEGIN CERTIFICATE') && !cert.includes('BEGIN X509 CERTIFICATE')) {
      return 'Signing certificate must be in PEM format (-----BEGIN CERTIFICATE-----).'
    }
  }

  // Metadata XML validation
  if (args.samlMetadataXml) {
    const xxeError = rejectXxe(args.samlMetadataXml)
    if (xxeError) return xxeError
    if (!args.samlMetadataXml.includes('entityID')) {
      return 'SAML metadata XML must contain an entityID attribute.'
    }
    if (
      !args.samlMetadataXml.includes('SingleSignOnService') &&
      !args.samlMetadataXml.includes('IDPSSODescriptor')
    ) {
      return 'SAML metadata XML must contain SingleSignOnService or IDPSSODescriptor.'
    }
  }

  return null
}

// ---------------------------------------------------------------------------
// listSsoConfigs — query
// ---------------------------------------------------------------------------

export const listSsoConfigs = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q: any) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can manage SSO')
    }

    return ctx.db
      .query('ssoConfigs')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .collect()
  },
})

// ---------------------------------------------------------------------------
// createSsoConfig — mutation
// ---------------------------------------------------------------------------

export const createSsoConfig = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    protocol: v.union(v.literal('saml'), v.literal('oidc')),
    displayName: v.string(),
    enabled: v.boolean(),
    enforced: v.boolean(),
    defaultRole: v.union(v.literal('owner'), v.literal('admin'), v.literal('member')),
    // SAML fields
    samlEntityId: v.optional(v.string()),
    samlSsoUrl: v.optional(v.string()),
    samlSloUrl: v.optional(v.string()),
    samlCertificate: v.optional(v.string()),
    samlMetadataXml: v.optional(v.string()),
    samlNameIdFormat: v.optional(v.string()),
    samlSignatureAlgorithm: v.optional(v.string()),
    samlAttributeEmail: v.optional(v.string()),
    samlAttributeFirstName: v.optional(v.string()),
    samlAttributeLastName: v.optional(v.string()),
    // OIDC fields
    oidcIssuer: v.optional(v.string()),
    oidcClientId: v.optional(v.string()),
    oidcClientSecret: v.optional(v.string()),
    oidcAuthorizationEndpoint: v.optional(v.string()),
    oidcTokenEndpoint: v.optional(v.string()),
    oidcUserInfoEndpoint: v.optional(v.string()),
    oidcJwksUri: v.optional(v.string()),
    oidcScopes: v.optional(v.array(v.string())),
    // Domain restriction
    allowedEmailDomains: v.optional(v.array(v.string())),
  },
  handler: async (ctx, { authToken, tenantSlug, ...config }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q: any) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can manage SSO')
    }

    const validationError = validateSamlFields(config)
    if (validationError) throw new Error(validationError)

    const now = Date.now()
    const configId = await ctx.db.insert('ssoConfigs', {
      tenantId: tenant._id,
      ...config,
      createdByUserId: userId,
      createdAt: now,
      updatedAt: now,
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'sso.config_created',
      resourceType: 'ssoConfigs',
      resourceId: configId,
      payload: JSON.stringify({ protocol: config.protocol, displayName: config.displayName }),
      at: now,
    })

    return { configId }
  },
})

// ---------------------------------------------------------------------------
// updateSsoConfig — mutation
// ---------------------------------------------------------------------------

export const updateSsoConfig = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    configId: v.id('ssoConfigs'),
    displayName: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
    enforced: v.optional(v.boolean()),
    defaultRole: v.optional(v.union(v.literal('owner'), v.literal('admin'), v.literal('member'))),
    samlEntityId: v.optional(v.string()),
    samlSsoUrl: v.optional(v.string()),
    samlSloUrl: v.optional(v.string()),
    samlCertificate: v.optional(v.string()),
    samlMetadataXml: v.optional(v.string()),
    oidcIssuer: v.optional(v.string()),
    oidcClientId: v.optional(v.string()),
    oidcClientSecret: v.optional(v.string()),
    oidcAuthorizationEndpoint: v.optional(v.string()),
    oidcTokenEndpoint: v.optional(v.string()),
    oidcUserInfoEndpoint: v.optional(v.string()),
    oidcJwksUri: v.optional(v.string()),
    oidcScopes: v.optional(v.array(v.string())),
    allowedEmailDomains: v.optional(v.array(v.string())),
  },
  handler: async (ctx, { authToken, tenantSlug, configId, ...updates }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const config = await ctx.db.get(configId)
    if (!config || config.tenantId !== tenant._id) {
      throw new Error('SSO config not found')
    }

    // Validate any SAML fields being updated
    const mergedForValidation = {
      protocol: updates.samlEntityId !== undefined || updates.samlSsoUrl !== undefined || updates.samlCertificate !== undefined || updates.samlMetadataXml !== undefined
        ? 'saml'
        : (config as any).protocol ?? 'saml',
      samlEntityId: updates.samlEntityId ?? (config as any).samlEntityId,
      samlSsoUrl: updates.samlSsoUrl ?? (config as any).samlSsoUrl,
      samlCertificate: updates.samlCertificate ?? (config as any).samlCertificate,
      samlMetadataXml: updates.samlMetadataXml ?? (config as any).samlMetadataXml,
    }
    const updateValidationError = validateSamlFields(mergedForValidation)
    if (updateValidationError) throw new Error(updateValidationError)

    const now = Date.now()
    const patchData: any = { updatedAt: now }
    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) patchData[key] = value
    }

    await ctx.db.patch(configId, patchData)

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'sso.config_updated',
      resourceType: 'ssoConfigs',
      resourceId: configId,
      payload: JSON.stringify({ displayName: config.displayName }),
      at: now,
    })

    return { success: true }
  },
})

// ---------------------------------------------------------------------------
// deleteSsoConfig — mutation
// ---------------------------------------------------------------------------

export const deleteSsoConfig = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    configId: v.id('ssoConfigs'),
  },
  handler: async (ctx, { authToken, tenantSlug, configId }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const config = await ctx.db.get(configId)
    if (!config || config.tenantId !== tenant._id) {
      throw new Error('SSO config not found')
    }

    await ctx.db.delete(configId)

    const now = Date.now()
    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'sso.config_deleted',
      resourceType: 'ssoConfigs',
      resourceId: configId,
      payload: JSON.stringify({ displayName: config.displayName, protocol: config.protocol }),
      at: now,
    })

    return { success: true }
  },
})

// ---------------------------------------------------------------------------
// getAcsUrl — query (returns the ACS URL for this tenant)
// ---------------------------------------------------------------------------

export const getAcsUrl = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    // Return the ACS URL that the IdP should use for this tenant
    const convexUrl = process.env.CONVEX_URL ?? 'https://your-convex-instance.convex.cloud'
    return {
      acsUrl: `${convexUrl}/api/sso/acs/${tenant._id}`,
      entityId: `cyberzen:${tenant.slug}`,
      audience: `https://cyberzen.dev/sso/${tenant.slug}`,
    }
  },
})
