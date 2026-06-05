// ── §5.4 — Application-managed GitHub OAuth for API access ────────────
//
// `@convex-dev/auth` does not store OAuth access tokens on the
// `authAccounts.secret` column (only hashed credential passwords go
// there). To call the GitHub API on behalf of a signed-in user — for
// example to list their repos during onboarding — we run a separate,
// application-managed GitHub OAuth flow with the right scopes
// (`read:user user:email public_repo`) and persist the resulting
// access token in the `userGithubTokens` table.
//
// Flow:
//   1. `startGithubConnect` (action) generates a CSRF nonce, stores
//      it in `githubOAuthStates` with a 10-minute TTL, and returns the
//      GitHub authorize URL for the user to visit.
//   2. The user authorizes CyberZen on github.com.
//   3. GitHub redirects back to the HTTP action
//      `/api/github/oauth/callback` (mounted in `http.ts`) with
//      `?code=...&state=...`.
//   4. The callback validates `state`, exchanges `code` for a token,
//      fetches the user's GitHub login, and stores the row via the
//      internal mutation `storeGithubToken`.
//   5. The callback then 302s the browser back to the SPA — typically
//      `/onboarding?github=connected` — so the React app re-queries
//      and the repo dropdown populates.
//
import { v } from "convex/values";
import { action, internalMutation, mutation, query } from "./_generated/server";
import { internal } from "./_generated/api";
import type { Doc, Id } from "./_generated/dataModel";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API = "https://api.github.com";

/** Scopes the connection grants. `public_repo` is what unlocks
 *  `GET /user/repos`. `repo` is requested too so private repos show
 *  up for users on a Pro/Team plan. */
const GITHUB_SCOPES = ["read:user", "user:email", "public_repo", "repo"];

const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// ── User resolution helper ──────────────────────────────────────────────

/**
 * Extract the `users` table document ID from `identity.subject`.
 * `@convex-dev/auth` encodes the subject as `"<userId>|<sessionId>"`.
 */
function userIdFromSubject(subject: string): Id<"users"> {
    return subject.split("|")[0] as Id<"users">;
}

/**
 * Look up the `users` row for the currently authenticated identity.
 * Tries email first (fast index), then falls back to extracting the
 * userId from `identity.subject` when the email claim is absent.
 */
async function resolveCurrentUser(ctx: any) {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated");
    
    // Path 1: resolve by email (fast)
    if (identity.email) {
        const user = await ctx.db
            .query("users")
            .withIndex("email", (q: any) => q.eq("email", identity.email))
            .first();
        if (user) return { user, identity };
    }

    // Path 2: resolve by subject ("userId|sessionId")
    const userId = userIdFromSubject(identity.subject);
    const user = await ctx.db.get(userId);
    if (!user) throw new Error("No user found for identity");
    return { user, identity };
}

/** Internal query so the action can resolve the user.
 *
 *  Tries two resolution paths:
 *    1. If `identity.email` is present, look up by email index (fast).
 *    2. If `identity.email` is absent (e.g. GitHub user with private
 *       email), extract the userId from `identity.subject` — Convex Auth
 *       encodes it as `"<userId>|<sessionId>"` — and fetch the user
 *       document directly.
 */
export const _resolveUser = query({
    args: {},
    returns: v.union(
        v.null(),
        v.object({ userId: v.id("users"), email: v.string() }),
    ),
    handler: async (ctx) => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) return null;

        // Path 1: email present in JWT claims
        if (identity.email) {
            const user = await ctx.db
                .query("users")
                .withIndex("email", (q) => q.eq("email", identity.email!))
                .first();
            if (user) return { userId: user._id, email: identity.email! };
        }

        // Path 2: extract userId from subject ("userId|sessionId")
        const userIdRaw = identity.subject.split("|")[0];
        if (userIdRaw) {
            const user = await ctx.db.get(userIdRaw as Id<"users">);
            if (user && user.email) {
                return { userId: user._id, email: user.email };
            }
        }

        return null;
    },
});

// ── State table helpers ────────────────────────────────────────────────

/** Internal mutation: persist a `state → userId` mapping for CSRF
 *  validation when the GitHub OAuth callback comes back. Called from
 *  the `startGithubConnect` action. */
export const createOAuthState = internalMutation({
    args: {
        state: v.string(),
        email: v.string(),
        tenantSlug: v.string(),
        returnTo: v.string(),
    },
    returns: v.object({ state: v.string(), expiresAt: v.number() }),
    handler: async (ctx, args) => {
        // Resolve the real user ID from email — identity.subject from
        // @convex-dev/auth is a composite string, NOT a v.id("users").
        const user = await ctx.db
            .query("users")
            .withIndex("email", (q) => q.eq("email", args.email))
            .first();
        if (!user) {
            throw new Error(`No user found for email ${args.email}`);
        }

        const now = Date.now();
        const expiresAt = now + STATE_TTL_MS;
        await ctx.db.insert("githubOAuthStates", {
            state: args.state,
            userId: user._id,
            tenantSlug: args.tenantSlug,
            returnTo: args.returnTo,
            createdAt: now,
            expiresAt,
        });
        return { state: args.state, expiresAt };
    },
});

/** Internal mutation: consume a `state` row and return its user/tenant
 *  context. Used by the HTTP callback to validate the request and
 *  delete the state row so it can't be replayed. */
export const consumeOAuthState = internalMutation({
    args: { state: v.string() },
    returns: v.union(
        v.object({
            userId: v.id("users"),
            tenantSlug: v.string(),
            returnTo: v.string(),
        }),
        v.null(),
    ),
    handler: async (ctx, args) => {
        const row = await ctx.db
            .query("githubOAuthStates")
            .withIndex("by_state", (q) => q.eq("state", args.state))
            .first();
        if (!row) return null;
        if (row.expiresAt < Date.now()) {
            await ctx.db.delete(row._id);
            return null;
        }
        await ctx.db.delete(row._id);
        return {
            userId: row.userId,
            tenantSlug: row.tenantSlug,
            returnTo: row.returnTo,
        };
    },
});

/** Internal mutation: persist the GitHub access token returned by the
 *  OAuth callback. Idempotent — re-linking overwrites the previous
 *  row for the same `userId`. */
export const storeGithubToken = internalMutation({
    args: {
        userId: v.id("users"),
        login: v.string(),
        accessToken: v.string(),
        scopes: v.array(v.string()),
        expiresAt: v.optional(v.number()),
    },
    returns: v.object({ tokenId: v.id("userGithubTokens") }),
    handler: async (ctx, args) => {
        const now = Date.now();
        const existing = await ctx.db
            .query("userGithubTokens")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .first();
        if (existing) {
            await ctx.db.patch(existing._id, {
                login: args.login,
                accessToken: args.accessToken,
                scopes: args.scopes,
                expiresAt: args.expiresAt,
                updatedAt: now,
            });
            return { tokenId: existing._id };
        }
        const id = await ctx.db.insert("userGithubTokens", {
            userId: args.userId,
            login: args.login,
            accessToken: args.accessToken,
            scopes: args.scopes,
            expiresAt: args.expiresAt,
            linkedAt: now,
            updatedAt: now,
        });
        return { tokenId: id };
    },
});

// ── Public-facing functions ────────────────────────────────────────────

/** Return the current user's GitHub connection status, for the UI. */
export const getGithubConnectionStatus = query({
    args: {},
    returns: v.union(
        v.object({
            connected: v.literal(true),
            login: v.string(),
            scopes: v.array(v.string()),
            linkedAt: v.number(),
            updatedAt: v.number(),
        }),
        v.object({ connected: v.literal(false) }),
    ),
    handler: async (ctx) => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) return { connected: false as const };

        // Resolve user — try email first, then subject fallback
        let userId: Id<"users"> | null = null;
        if (identity.email) {
            const user = await ctx.db
                .query("users")
                .withIndex("email", (q) => q.eq("email", identity.email!))
                .first();
            if (user) userId = user._id;
        }
        if (!userId) {
            userId = userIdFromSubject(identity.subject);
            // Verify the user actually exists
            const user = await ctx.db.get(userId);
            if (!user) return { connected: false as const };
        }

        const row = (await ctx.db
            .query("userGithubTokens")
            .withIndex("by_user", (q) =>
                q.eq("userId", userId!),
            )
            .first()) as Doc<"userGithubTokens"> | null;
        if (!row) return { connected: false as const };

        return {
            connected: true as const,
            login: row.login,
            scopes: row.scopes,
            linkedAt: row.linkedAt,
            updatedAt: row.updatedAt,
        };
    },
});

/** Disconnect GitHub for the current user. Removes the stored token. */
export const disconnectGithub = mutation({
    args: {},
    returns: v.object({ removed: v.boolean() }),
    handler: async (ctx) => {
        const { user } = await resolveCurrentUser(ctx);
        const row = await ctx.db
            .query("userGithubTokens")
            .withIndex("by_user", (q) =>
                q.eq("userId", user._id),
            )
            .first();
        if (!row) return { removed: false };
        await ctx.db.delete(row._id);
        return { removed: true };
    },
});

/** Begin a GitHub OAuth flow. Returns the GitHub authorize URL the
 *  browser should navigate to. */
export const startGithubConnect = action({
    args: {
        tenantSlug: v.string(),
        returnTo: v.optional(v.string()),
    },
    returns: v.object({
        authorizeUrl: v.string(),
        state: v.string(),
        expiresAt: v.number(),
    }),
    handler: async (
        ctx,
        args,
    ): Promise<{
        authorizeUrl: string;
        state: string;
        expiresAt: number;
    }> => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) {
            throw new Error("Not authenticated");
        }

        // Resolve user — works even when identity.email is missing
        // (e.g. GitHub users with private emails) by falling back to
        // the userId embedded in identity.subject.
        const resolved = await ctx.runQuery(
            internal.githubOAuth._resolveUser,
            {},
        );
        if (!resolved) {
            throw new Error(
                "Could not resolve current user. Please sign in again.",
            );
        }

        const clientId = process.env["AUTH_GITHUB_API_ID"];
        const siteUrl = process.env["CONVEX_SITE_URL"];
        if (!clientId) {
            throw new Error(
                "AUTH_GITHUB_API_ID is not set. Configure it in the Convex dashboard env vars.",
            );
        }
        if (!siteUrl) {
            throw new Error(
                "CONVEX_SITE_URL is not set. Configure it in the Convex dashboard env vars.",
            );
        }

        // Cryptographically-strong nonce. `crypto.randomUUID` is
        // available on the Convex runtime.
        const state = crypto.randomUUID();
        const returnTo = args.returnTo ?? `/onboarding?github=connected`;

        const persisted = await ctx.runMutation(
            internal.githubOAuth.createOAuthState,
            {
                state,
                email: resolved.email,
                tenantSlug: args.tenantSlug,
                returnTo,
            },
        );

        const callbackUrl = `${siteUrl}/api/github/oauth/callback`;
        const authorizeUrl =
            `${GITHUB_AUTHORIZE_URL}?client_id=${encodeURIComponent(clientId)}` +
            `&redirect_uri=${encodeURIComponent(callbackUrl)}` +
            `&scope=${encodeURIComponent(GITHUB_SCOPES.join(" "))}` +
            `&state=${encodeURIComponent(state)}` +
            `&allow_signup=false`;

        return {
            authorizeUrl,
            state: persisted.state,
            expiresAt: persisted.expiresAt,
        };
    },
});

/** Internal: exchange a GitHub OAuth `code` for an access token. */
export const exchangeCodeForToken = action({
    args: { code: v.string() },
    returns: v.object({
        accessToken: v.string(),
        scopes: v.array(v.string()),
        expiresAt: v.optional(v.number()),
    }),
    handler: async (
        _ctx,
        args,
    ): Promise<{
        accessToken: string;
        scopes: string[];
        expiresAt?: number;
    }> => {
        const clientId = process.env["AUTH_GITHUB_API_ID"];
        const clientSecret = process.env["AUTH_GITHUB_API_SECRET"];
        if (!clientId || !clientSecret) {
            throw new Error(
                "AUTH_GITHUB_API_ID and AUTH_GITHUB_API_SECRET must be set in the Convex dashboard env vars.",
            );
        }

        const response = await fetch(GITHUB_TOKEN_URL, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                code: args.code,
            }),
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(
                `GitHub token exchange failed (${response.status}): ${text.slice(0, 200)}`,
            );
        }

        const payload = (await response.json()) as {
            access_token?: string;
            scope?: string;
            expires_in?: number;
            token_type?: string;
            error?: string;
            error_description?: string;
        };

        if (payload.error || !payload.access_token) {
            throw new Error(
                `GitHub token exchange error: ${payload.error ?? "no_access_token"} ${payload.error_description ?? ""}`,
            );
        }

        const scopes = (payload.scope ?? "")
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
        const expiresAt =
            typeof payload.expires_in === "number"
                ? Date.now() + payload.expires_in * 1000
                : undefined;

        return {
            accessToken: payload.access_token,
            scopes,
            expiresAt,
        };
    },
});

/** Internal: fetch the GitHub login of the user the access token
 *  belongs to, so we can show "connected as <login>" in the UI. */
export const fetchGithubLogin = action({
    args: { accessToken: v.string() },
    returns: v.object({ login: v.string() }),
    handler: async (
        _ctx,
        args,
    ): Promise<{ login: string }> => {
        const response = await fetch(`${GITHUB_API}/user`, {
            headers: {
                Accept: "application/vnd.github+json",
                Authorization: `Bearer ${args.accessToken}`,
                "User-Agent": "CyberZen-Sentinel",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        });
        if (!response.ok) {
            const body = await response.text();
            throw new Error(
                `GitHub /user failed (${response.status}): ${body.slice(0, 200)}`,
            );
        }
        const payload = (await response.json()) as { login?: string };
        if (!payload.login) {
            throw new Error("GitHub /user response missing login");
        }
        return { login: payload.login };
    },
});
