import type { Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

type AuthCtx = QueryCtx | MutationCtx;

/**
 * Resolve the authenticated user from Convex's built-in identity
 * (populated automatically by Clerk via ConvexProviderWithClerk).
 */
export async function requireSessionAuth(
	ctx: AuthCtx,
	_authToken?: string | undefined,
): Promise<{ userId: Id<"users">; sessionId: null }> {
	const identity = await ctx.auth.getUserIdentity();
	if (!identity) {
		throw new Error("Not signed in");
	}

	// Clerk identity has `subject` = the Clerk user ID (e.g. "user_2abc...")
	// and `email` from the Clerk session. Resolve the CyberZen user by email.
	const email = (identity as Record<string, unknown>).email as string | undefined;
	if (!email) {
		throw new Error("Clerk session has no email — cannot resolve user");
	}

	const user = await ctx.db
		.query("users")
		.withIndex("email", (q) => q.eq("email", email))
		.first();

	if (!user) {
		throw new Error(`No CyberZen user found for ${email}`);
	}

	return {
		userId: user._id,
		sessionId: null,
	};
}
