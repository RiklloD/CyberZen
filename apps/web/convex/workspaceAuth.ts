import type { Id } from './_generated/dataModel'
import { mutation, query, type MutationCtx, type QueryCtx } from './_generated/server'
import { v } from 'convex/values'
import { requireSessionAuth } from './lib/sessionAuth'

const workspaceRole = v.union(
  v.literal('owner'),
  v.literal('admin'),
  v.literal('member'),
)

const workspaceSummary = v.object({
  tenantId: v.id('tenants'),
  tenantSlug: v.string(),
  tenantName: v.string(),
  role: workspaceRole,
  selectedAt: v.number(),
})

const tenantSummary = v.object({
  _id: v.id('tenants'),
  slug: v.string(),
  name: v.string(),
  deploymentMode: v.string(),
  currentPhase: v.string(),
})

const currentWorkspaceResult = v.union(
  v.null(),
  v.object({
    user: v.object({
      id: v.id('users'),
      email: v.optional(v.string()),
      name: v.optional(v.string()),
    }),
    tenant: tenantSummary,
    workspaces: v.array(workspaceSummary),
  }),
)

const inviteResult = v.object({
  token: v.string(),
  inviteUrl: v.string(),
  tenantSlug: v.string(),
  tenantName: v.string(),
  email: v.string(),
  role: workspaceRole,
  expiresAt: v.optional(v.number()),
})

function normalizeEmail(email: string) {
  return email.trim().toLowerCase()
}

async function getCurrentUserId(ctx: QueryCtx | MutationCtx, authToken?: string) {
  const { userId } = await requireSessionAuth(ctx, authToken)
  return userId
}

async function loadUserEmail(
  ctx: QueryCtx | MutationCtx,
  userId: Id<'users'>,
) {
  const user = await ctx.db.get(userId)
  const email = user && typeof user === 'object' && 'email' in user ? (user as { email?: string }).email : undefined
  return email ? normalizeEmail(email) : null
}

async function loadWorkspaces(
  ctx: QueryCtx | MutationCtx,
  userId: Id<'users'>,
) {
  const memberships = await ctx.db
    .query('tenantMembers')
    .withIndex('by_user_and_selected_at', (q) => q.eq('userId', userId))
    .order('desc')
    .take(20)

  const workspaces = await Promise.all(
    memberships.map(async (membership) => {
      const tenant = await ctx.db.get(membership.tenantId)
      if (!tenant) {
        return null
      }

      return {
        tenantId: tenant._id,
        tenantSlug: tenant.slug,
        tenantName: tenant.name,
        role: membership.role,
        selectedAt: membership.selectedAt,
      }
    }),
  )

  return workspaces.filter((workspace): workspace is NonNullable<typeof workspace> => workspace !== null)
}

async function loadCurrentWorkspace(
  ctx: QueryCtx | MutationCtx,
  userId: Id<'users'>,
) {
  const workspaces = await loadWorkspaces(ctx, userId)
  if (workspaces.length === 0) {
    return null
  }

  const tenant = await ctx.db.get(workspaces[0].tenantId)
  if (!tenant) {
    return null
  }

  const user = await ctx.db.get(userId)

  return {
    user: {
      id: userId,
      email: user && typeof user === 'object' && 'email' in user ? (user as { email?: string }).email : undefined,
      name: user && typeof user === 'object' && 'name' in user ? (user as { name?: string }).name : undefined,
    },
    tenant: {
      _id: tenant._id,
      slug: tenant.slug,
      name: tenant.name,
      deploymentMode: tenant.deploymentMode,
      currentPhase: tenant.currentPhase,
    },
    workspaces,
  }
}

export const ensureUser = mutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error('Not signed in');

    const email = (identity as Record<string, unknown>).email as string | undefined;
    if (!email) throw new Error('Clerk session has no email');

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', normalizedEmail))
      .first();

    if (!existing) {
      const name =
        (identity as Record<string, unknown>).name as string | undefined ??
        (identity as Record<string, unknown>).givenName as string | undefined ??
        normalizedEmail.split('@')[0];
      await ctx.db.insert('users', { email: normalizedEmail, name });
    }

    return null;
  },
})

export const currentWorkspace = query({
  args: {
    authToken: v.optional(v.string()),
  },
  returns: currentWorkspaceResult,
  handler: async (ctx, { authToken }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    return await loadCurrentWorkspace(ctx, userId)
  },
})

export const listWorkspaces = query({
  args: {
    authToken: v.optional(v.string()),
  },
  returns: v.array(workspaceSummary),
  handler: async (ctx, { authToken }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    return await loadWorkspaces(ctx, userId)
  },
})

export const switchWorkspace = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  returns: currentWorkspaceResult,
  handler: async (ctx, { authToken, tenantSlug }) => {
    const userId = await getCurrentUserId(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) {
      throw new Error(`Tenant not found: ${tenantSlug}`)
    }

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership) {
      throw new Error('You do not have access to that workspace')
    }

    await ctx.db.patch(membership._id, {
      selectedAt: Date.now(),
    })

    return await loadCurrentWorkspace(ctx, userId)
  },
})

export const createWorkspaceInvite = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    email: v.string(),
    role: workspaceRole,
    /** §6.11 — Optional custom RBAC role to assign on acceptance. */
    assignedRoleId: v.optional(v.id('roles')),
  },
  returns: inviteResult,
  handler: async (ctx, { authToken, tenantSlug, email, role, assignedRoleId }) => {
    const userId = await getCurrentUserId(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) {
      throw new Error(`Tenant not found: ${tenantSlug}`)
    }

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can create invites')
    }

    // §6.11 — Validate assignedRoleId belongs to this tenant
    if (assignedRoleId) {
      const roleDoc = await ctx.db.get(assignedRoleId)
      if (!roleDoc || roleDoc.tenantId !== tenant._id) {
        throw new Error('Invalid role for this workspace')
      }
    }

    const token = crypto.randomUUID().replace(/-/g, '')
    const normalizedEmail = normalizeEmail(email)
    const now = Date.now()
    const expiresAt = now + 24 * 60 * 60 * 1000

    await ctx.db.insert('tenantInvites', {
      tenantId: tenant._id,
      email: normalizedEmail,
      token,
      role,
      status: 'pending',
      assignedRoleId,
      invitedByUserId: userId,
      createdAt: now,
      expiresAt,
    })

    return {
      token,
      inviteUrl: `/?invite=${token}`,
      tenantSlug: tenant.slug,
      tenantName: tenant.name,
      email: normalizedEmail,
      role,
      expiresAt,
    }
  },
})

// ─── §3.7 — Team Management queries & mutations ────────────────────────────

const memberSummary = v.object({
  _id: v.id('tenantMembers'),
  userId: v.id('users'),
  role: workspaceRole,
  email: v.optional(v.string()),
  name: v.optional(v.string()),
  joinedAt: v.optional(v.number()),
})

export const listMembers = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  returns: v.array(memberSummary),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const userId = await getCurrentUserId(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const callerMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!callerMembership) throw new Error('You do not have access to this workspace')

    const memberships = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const results = await Promise.all(
      memberships.map(async (m) => {
        const user = await ctx.db.get(m.userId)
        return {
          _id: m._id,
          userId: m.userId,
          role: m.role,
          email: user && typeof user === 'object' && 'email' in user ? (user as { email?: string }).email : undefined,
          name: user && typeof user === 'object' && 'name' in user ? (user as { name?: string }).name : undefined,
          joinedAt: 'joinedAt' in m ? (m as { joinedAt?: number }).joinedAt : undefined,
        }
      }),
    )

    return results
  },
})

export const inviteMember = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    email: v.string(),
    role: workspaceRole,
    /** §6.11 — Custom RBAC role to assign on invite acceptance. */
    assignedRoleId: v.optional(v.id('roles')),
  },
  returns: inviteResult,
  handler: async (ctx, { authToken, tenantSlug, email, role, assignedRoleId }) => {
    // Delegate to the existing createWorkspaceInvite implementation
    return await createWorkspaceInvite.handler(ctx, { authToken, tenantSlug, email, role, assignedRoleId })
  },
})

export const removeMember = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    memberUserId: v.id('users'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, memberUserId }) => {
    const userId = await getCurrentUserId(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const callerMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!callerMembership || (callerMembership.role !== 'owner' && callerMembership.role !== 'admin')) {
      throw new Error('Only owners and admins can remove members')
    }

    if (memberUserId === userId) {
      throw new Error('You cannot remove yourself')
    }

    const targetMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', memberUserId),
      )
      .unique()

    if (!targetMembership) throw new Error('Member not found in this workspace')

    if (targetMembership.role === 'owner') {
      throw new Error('Cannot remove the workspace owner')
    }

    await ctx.db.delete(targetMembership._id)
    return null
  },
})

export const changeRole = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    memberUserId: v.id('users'),
    newRole: workspaceRole,
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, memberUserId, newRole }) => {
    const userId = await getCurrentUserId(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const callerMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!callerMembership || callerMembership.role !== 'owner') {
      throw new Error('Only owners can change roles')
    }

    if (memberUserId === userId) {
      throw new Error('You cannot change your own role')
    }

    const targetMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', memberUserId),
      )
      .unique()

    if (!targetMembership) throw new Error('Member not found in this workspace')

    if (targetMembership.role === 'owner') {
      throw new Error('Cannot change the role of the workspace owner')
    }

    await ctx.db.patch(targetMembership._id, { role: newRole })
    return null
  },
})

export const acceptWorkspaceInvite = mutation({
  args: {
    authToken: v.optional(v.string()),
    token: v.string(),
  },
  returns: currentWorkspaceResult,
  handler: async (ctx, { authToken, token }) => {
    const userId = await getCurrentUserId(ctx, authToken)
    const userEmail = await loadUserEmail(ctx, userId)

    const invite = await ctx.db
      .query('tenantInvites')
      .withIndex('by_token', (q) => q.eq('token', token))
      .unique()

    if (!invite) {
      throw new Error('Invite not found')
    }

    if (invite.status === 'revoked') {
      throw new Error('Invite has been revoked')
    }

    if (invite.status === 'accepted') {
      throw new Error('This invite has already been used')
    }

    if (invite.expiresAt && invite.expiresAt < Date.now()) {
      throw new Error('Invite has expired')
    }

    if (!userEmail) {
      throw new Error('Your account has no email address. Please sign in with an account that has an email.')
    }

    if (normalizeEmail(userEmail) !== invite.email) {
      throw new Error(`This invite was sent to ${invite.email}. Please sign in with that account.`)
    }

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', invite.tenantId).eq('userId', userId),
      )
      .unique()

    if (!membership) {
      await ctx.db.insert('tenantMembers', {
        tenantId: invite.tenantId,
        userId,
        role: invite.role,
        selectedAt: Date.now(),
        invitedByUserId: invite.invitedByUserId,
        joinedAt: Date.now(),
      })
    } else {
      await ctx.db.patch(membership._id, {
        selectedAt: Date.now(),
      })
    }

    if (invite.status === 'pending') {
      await ctx.db.patch(invite._id, {
        status: 'accepted',
        acceptedByUserId: userId,
        acceptedAt: Date.now(),
      })
    }

    return await loadCurrentWorkspace(ctx, userId)
  },
})
