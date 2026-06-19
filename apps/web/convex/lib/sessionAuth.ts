import { createLocalJWKSet, jwtVerify } from "jose";
import type { Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

const jwksJson = process.env.JWKS;
const jwks = jwksJson ? createLocalJWKSet(JSON.parse(jwksJson)) : null;

type AuthCtx = QueryCtx | MutationCtx;

export async function requireSessionAuth(
	ctx: AuthCtx,
	authToken: string,
): Promise<{ userId: Id<"users">; sessionId: Id<"authSessions"> }> {
	if (!authToken) {
		throw new Error("Not signed in");
	}

	// A21 — deferred (lazy) issuer check: only throw when actually needed,
	// not at module-load time (which would take down the entire backend)
	const issuer = process.env.CONVEX_SITE_URL;
	if (!issuer) {
		throw new Error("CONVEX_SITE_URL is not set");
	}

	if (!jwks) {
		throw new Error("JWKS is not configured — set the JWKS env variable");
	}

	const { payload } = await jwtVerify(authToken, jwks, {
		issuer,
		audience: "convex",
		clockTolerance: "30s", // A22 — tolerate minor clock skew between issuer and verifier
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
