import type { Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

type AuthCtx = QueryCtx | MutationCtx;

/**
 * Resolve the authenticated user from Convex's built-in identity
 * (populated automatically by Clerk via ConvexProviderWithClerk).
 *
 * If no CyberZen user exists for the Clerk email, one is created automatically.
 */
export async function requireSessionAuth(
	ctx: AuthCtx,
	_authToken?: string | undefined,
): Promise<{ userId: Id<"users">; sessionId: null }> {
	const identity = await ctx.auth.getUserIdentity();
	if (!identity) {
		throw new Error("Not signed in");
	}

	// Clerk identity has `email` from the session.
	const email = (identity as Record<string, unknown>).email as string | undefined;
	if (!email) {
		throw new Error("Clerk session has no email — cannot resolve user");
	}

	const normalizedEmail = email.trim().toLowerCase();

	// Look up existing user by email
	const existingUser = await ctx.db
		.query("users")
		.withIndex("email", (q) => q.eq("email", normalizedEmail))
		.first();

	if (existingUser) {
		return {
			userId: existingUser._id,
			sessionId: null,
		};
	}

	// Auto-provision user on first sign-in (query context can't write, so we
	// only return the identity info — the mutation path below handles creation).
	// In query context, ctx.db.insert is not available, so we throw to signal
	// that a mutation needs to create the user first.
	// However, Convex queries CAN read but mutations CAN write.
	// For the auto-provision to work, we need to handle this in the caller.
	// The simplest approach: if this is a mutation context, create the user.
	// If it's a query context, throw a specific error the frontend can handle.

	// Check if we're in a mutation context (has db.insert capability)
	if ("insert" in ctx.db) {
		const name =
			(identity as Record<string, unknown>).name as string | undefined ??
			(identity as Record<string, unknown>).givenName as string | undefined ??
			normalizedEmail.split("@")[0];

		const userId = await (ctx.db as MutationCtx["db"]).insert("users", {
			email: normalizedEmail,
			name,
		});

		return {
			userId,
			sessionId: null,
		};
	}

	// Query context — user doesn't exist yet. The frontend should call
	// a mutation to create the user, then re-query.
	throw new Error(`No CyberZen user found for ${normalizedEmail}. Please sign in again to create your account.`);
}

/**
 * Resolve the authenticated user AND the tenant from a slug, with membership
 * verification. Returns the tenant doc, userId, and membership doc.
 *
 * Use this in queries/mutations that need both auth and tenant scoping:
 *   const { tenant } = await requireTenantAccess(ctx, args.authToken, args.tenantSlug)
 */
export async function requireTenantAccess(
	ctx: AuthCtx,
	_authToken?: string | undefined,
	tenantSlug?: string | undefined,
): Promise<{
	tenant: NonNullable<Awaited<ReturnType<AuthCtx["db"]["query"]>["first"]>>;
	userId: Id<"users">;
	membership: NonNullable<Awaited<ReturnType<AuthCtx["db"]["query"]>["first"]>>;
}> {
	const { userId } = await requireSessionAuth(ctx, _authToken);

	if (!tenantSlug) {
		throw new Error("Tenant slug is required");
	}

	const tenant = await ctx.db
		.query("tenants")
		.withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
		.first();
	if (!tenant) {
		throw new Error(`Tenant "${tenantSlug}" not found`);
	}

	const membership = await ctx.db
		.query("tenantMembers")
		.withIndex("by_tenant_and_user", (q) =>
			q.eq("tenantId", tenant._id).eq("userId", userId),
		)
		.unique();
	if (!membership) {
		throw new Error("Not authorized for this tenant");
	}

	return { tenant, userId, membership };
}
