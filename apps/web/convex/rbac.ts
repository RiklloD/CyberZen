import type { Id } from './_generated/dataModel'
import { mutation, query } from './_generated/server'
import type { QueryCtx, MutationCtx } from './_generated/server'
import { v } from 'convex/values'
import { requireSessionAuth } from './lib/sessionAuth'

const permission = v.union(
  v.literal('read:findings'),
  v.literal('write:findings'),
  v.literal('read:repositories'),
  v.literal('write:repositories'),
  v.literal('admin:team'),
  v.literal('admin:roles'),
  v.literal('admin:api_keys'),
  v.literal('admin:settings'),
  v.literal('admin:integrations'),
  v.literal('read:audit_log'),
  v.literal('admin:compliance'),
  v.literal('admin:remediation'),
  v.literal('admin:gates'),
  v.literal('admin:scans'),
  v.string(),
)

const roleSummary = v.object({
  _id: v.id('roles'),
  name: v.string(),
  description: v.optional(v.string()),
  permissions: v.array(v.string()),
  isSystem: v.boolean(),
  userCount: v.number(),
  createdAt: v.number(),
  updatedAt: v.number(),
})

async function getTenantAndVerifyAdmin(
  ctx: Parameters<typeof mutation>[0] extends { handler: (ctx: infer C, ...args: any) => any } ? C : never,
  authToken: string,
  tenantSlug: string,
) {
  const { userId } = await requireSessionAuth(ctx, authToken)

  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
    .unique()

  if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) =>
      q.eq('tenantId', tenant._id).eq('userId', userId),
    )
    .unique()

  if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
    throw new Error('Only owners and admins can manage roles')
  }

  return { userId, tenant }
}

export const listRoles = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.array(roleSummary),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership) throw new Error('You do not have access to this workspace')

    const roles = await ctx.db
      .query('roles')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const results = await Promise.all(
      roles.map(async (role) => {
        const grants = await ctx.db
          .query('permissionGrants')
          .withIndex('by_role', (q) => q.eq('roleId', role._id))
          .collect()

        return {
          _id: role._id,
          name: role.name,
          description: role.description,
          permissions: role.permissions,
          isSystem: role.isSystem,
          userCount: grants.length,
          createdAt: role.createdAt,
          updatedAt: role.updatedAt,
        }
      }),
    )

    return results
  },
})

export const createRole = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    permissions: v.array(v.string()),
  },
  returns: v.id('roles'),
  handler: async (ctx, { authToken, tenantSlug, name, description, permissions }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const existing = await ctx.db
      .query('roles')
      .withIndex('by_tenant_and_name', (q) =>
        q.eq('tenantId', tenant._id).eq('name', name),
      )
      .unique()

    if (existing) throw new Error(`A role named "${name}" already exists`)

    const now = Date.now()
    const roleId = await ctx.db.insert('roles', {
      tenantId: tenant._id,
      name,
      description,
      permissions,
      isSystem: false,
      createdAt: now,
      updatedAt: now,
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'role.created',
      resourceType: 'roles',
      resourceId: roleId,
      payload: JSON.stringify({ name, permissions }),
      at: now,
    })

    return roleId
  },
})

export const updateRole = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    roleId: v.id('roles'),
    name: v.optional(v.string()),
    description: v.optional(v.string()),
    permissions: v.optional(v.array(v.string())),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, roleId, name, description, permissions }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const role = await ctx.db.get(roleId)
    if (!role || role.tenantId !== tenant._id) {
      throw new Error('Role not found')
    }

    if (role.isSystem) {
      throw new Error('System roles cannot be modified')
    }

    const updates: Record<string, any> = { updatedAt: Date.now() }
    if (name !== undefined) updates.name = name
    if (description !== undefined) updates.description = description
    if (permissions !== undefined) updates.permissions = permissions

    await ctx.db.patch(roleId, updates)

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'role.updated',
      resourceType: 'roles',
      resourceId: roleId,
      payload: JSON.stringify({ name, permissions }),
      at: Date.now(),
    })

    return null
  },
})

export const deleteRole = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    roleId: v.id('roles'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, roleId }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const role = await ctx.db.get(roleId)
    if (!role || role.tenantId !== tenant._id) {
      throw new Error('Role not found')
    }

    if (role.isSystem) {
      throw new Error('System roles cannot be deleted')
    }

    // Remove all permission grants for this role
    const grants = await ctx.db
      .query('permissionGrants')
      .withIndex('by_role', (q) => q.eq('roleId', roleId))
      .collect()

    await Promise.all(grants.map((g) => ctx.db.delete(g._id)))

    await ctx.db.delete(roleId)

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'role.deleted',
      resourceType: 'roles',
      resourceId: roleId,
      payload: JSON.stringify({ name: role.name }),
      at: Date.now(),
    })

    return null
  },
})

export const assignRoleToUser = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    targetUserId: v.id('users'),
    roleId: v.id('roles'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, targetUserId, roleId }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const role = await ctx.db.get(roleId)
    if (!role || role.tenantId !== tenant._id) {
      throw new Error('Role not found')
    }

    const targetMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', targetUserId),
      )
      .unique()

    if (!targetMembership) {
      throw new Error('User is not a member of this workspace')
    }

    const existing = await ctx.db
      .query('permissionGrants')
      .withIndex('by_user_and_role', (q) =>
        q.eq('userId', targetUserId).eq('roleId', roleId),
      )
      .unique()

    if (existing) return null // Already assigned

    const now = Date.now()
    await ctx.db.insert('permissionGrants', {
      tenantId: tenant._id,
      userId: targetUserId,
      roleId,
      grantedByUserId: userId,
      grantedAt: now,
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'role.assigned',
      resourceType: 'users',
      resourceId: targetUserId,
      payload: JSON.stringify({ roleId, roleName: role.name }),
      at: now,
    })

    return null
  },
})

export const removeRoleFromUser = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    targetUserId: v.id('users'),
    roleId: v.id('roles'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, targetUserId, roleId }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const existing = await ctx.db
      .query('permissionGrants')
      .withIndex('by_user_and_role', (q) =>
        q.eq('userId', targetUserId).eq('roleId', roleId),
      )
      .unique()

    if (!existing) return null

    await ctx.db.delete(existing._id)

    const role = await ctx.db.get(roleId)
    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'role.removed',
      resourceType: 'users',
      resourceId: targetUserId,
      payload: JSON.stringify({ roleId, roleName: role?.name }),
      at: Date.now(),
    })

    return null
  },
})

// ─── §C4 Delegated Administration ───────────────────────────────────────────

/** Permissions that delegated admins can never have — enforced server-side. */
const DELEGATED_ADMIN_BLOCKED = new Set([
  'admin:billing',
  'admin:sso',
  'admin:api_keys',
  'admin:roles',
  'admin:team',
  'workspace.delete',
  'workspace.transfer',
])

export const listMembersWithDelegations = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.array(
    v.object({
      memberId: v.id('tenantMembers'),
      userId: v.id('users'),
      role: v.union(v.literal('owner'), v.literal('admin'), v.literal('member')),
      email: v.optional(v.string()),
      name: v.optional(v.string()),
      delegatedPermissions: v.optional(v.array(v.string())),
    }),
  ),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can view delegated permissions')
    }

    const members = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(100)

    return await Promise.all(
      members.map(async (member) => {
        const user = await ctx.db.get(member.userId)
        return {
          memberId: member._id,
          userId: member.userId,
          role: member.role,
          email: (user as any)?.email as string | undefined,
          name: (user as any)?.name as string | undefined,
          delegatedPermissions: member.delegatedPermissions,
        }
      }),
    )
  },
})

export const setDelegatedPermissions = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    targetUserId: v.id('users'),
    permissions: v.array(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, targetUserId, permissions }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const targetMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', targetUserId),
      )
      .unique()

    if (!targetMembership) throw new Error('User is not a member of this workspace')
    if (targetMembership.role === 'owner') {
      throw new Error('Cannot set delegated permissions for the workspace owner')
    }

    // Strip any blocked permissions
    const safePermissions = permissions.filter((p) => !DELEGATED_ADMIN_BLOCKED.has(p))

    await ctx.db.patch(targetMembership._id, {
      delegatedPermissions: safePermissions.length > 0 ? safePermissions : undefined,
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'delegated_permissions.updated',
      resourceType: 'users',
      resourceId: targetUserId,
      payload: JSON.stringify({ permissions: safePermissions }),
      at: Date.now(),
    })

    return null
  },
})

/**
 * Returns true if the member identified by userId has the given delegated
 * permission either through their base role (owner/admin) or via the
 * delegatedPermissions array on their tenantMembers record.
 */
export async function hasDelegatedPermission(
  ctx: QueryCtx | MutationCtx,
  tenantId: Id<'tenants'>,
  userId: Id<'users'>,
  permission: string,
): Promise<boolean> {
  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) =>
      q.eq('tenantId', tenantId).eq('userId', userId),
    )
    .unique()

  if (!membership) return false
  if (membership.role === 'owner' || membership.role === 'admin') return true
  return membership.delegatedPermissions?.includes(permission) ?? false
}
