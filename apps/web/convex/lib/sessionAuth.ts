import { createLocalJWKSet, jwtVerify } from "jose";
import type { Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

const issuer = process.env.CONVEX_SITE_URL;
const jwksJson = process.env.JWKS;

if (!issuer) {
	throw new Error("CONVEX_SITE_URL is not set");
}

const jwks = jwksJson ? createLocalJWKSet(JSON.parse(jwksJson)) : null;

type AuthCtx = QueryCtx | MutationCtx;

export async function requireSessionAuth(
	ctx: AuthCtx,
	authToken: string,
): Promise<{ userId: Id<"users">; sessionId: Id<"authSessions"> }> {
	if (!authToken) {
		throw new Error("Not signed in");
	}

	if (!jwks) {
		throw new Error("JWKS is not configured — set the JWKS env variable");
	}

	const { payload } = await jwtVerify(authToken, jwks, {
		issuer,
		audience: "convex",
	});

	if (typeof payload.sub !== "string") {
		throw new Error("Not signed in");
	}

	const [userIdRaw, sessionIdRaw] = payload.sub.split("|");
	if (!userIdRaw || !sessionIdRaw) {
		throw new Error("Not signed in");
	}

	const sessionId = sessionIdRaw as Id<"authSessions">;
	const session = await ctx.db.get(sessionId);
	if (
		!session ||
		session.userId !== (userIdRaw as Id<"users">) ||
		session.expirationTime <= Date.now()
	) {
		throw new Error("Not signed in");
	}

	return {
		userId: userIdRaw as Id<"users">,
		sessionId,
	};
}
