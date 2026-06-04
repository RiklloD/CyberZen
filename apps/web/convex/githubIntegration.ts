import { v } from "convex/values";
import { action, internalQuery, query } from "./_generated/server";
import { internal } from "./_generated/api";
import type { Doc, Id } from "./_generated/dataModel";

// ── §5.4 — GitHub integration: list the signed-in user's repos ─────────
//
// Reads the OAuth access token stored on the user's `authAccounts` row
// (created when they signed in with the GitHub provider) and uses it to
// call the GitHub `/user/repos` endpoint. The result is shaped into the
// same `RepoDraft` fields used by the onboarding form so the UI can bind
// directly to it.

const GITHUB_API = "https://api.github.com";

type GithubRepo = {
	id: number;
	full_name: string;
	name: string;
	private: boolean;
	default_branch: string;
	language: string | null;
	description: string | null;
	html_url: string;
	updated_at: string | null;
	archived: boolean;
	fork: boolean;
};

/**
 * Internal helper: pull the access token off the current user's
 * GitHub `authAccounts` row. Convex actions can't read the database
 * directly, so the action calls this via `ctx.runQuery`.
 */
export const getGithubAccessToken = internalQuery({
	args: {},
	returns: v.union(v.string(), v.null()),
	handler: async (ctx) => {
		const identity = await ctx.auth.getUserIdentity();
		if (!identity) return null;

		const account = (await ctx.db
			.query("authAccounts")
			.withIndex("userIdAndProvider", (q) =>
				q
					.eq("userId", identity.subject as Id<"users">)
					.eq("provider", "github"),
			)
			.unique()) as Doc<"authAccounts"> | null;

		if (!account?.secret) return null;
		return account.secret;
	},
});

/**
 * Return the GitHub repos the currently signed-in user can see.
 *
 * The `provider` value used by `@auth/core/providers/github` is the
 * string `"github"`, which is what we match against on the authAccounts
 * table. The access token is stored in the `secret` field of the row.
 */
export const listGithubRepos = action({
	args: {
		tenantSlug: v.string(),
		perPage: v.optional(v.number()),
	},
	returns: v.object({
		login: v.string(),
		repos: v.array(
			v.object({
				id: v.number(),
				fullName: v.string(),
				name: v.string(),
				defaultBranch: v.string(),
				primaryLanguage: v.string(),
				visibility: v.union(v.literal("private"), v.literal("public")),
				description: v.optional(v.string()),
				htmlUrl: v.string(),
				archived: v.boolean(),
				fork: v.boolean(),
				updatedAt: v.optional(v.string()),
			}),
		),
	}),
	handler: async (
		ctx,
		args,
	): Promise<{
		login: string;
		repos: Array<{
			id: number;
			fullName: string;
			name: string;
			defaultBranch: string;
			primaryLanguage: string;
			visibility: "private" | "public";
			description?: string;
			htmlUrl: string;
			archived: boolean;
			fork: boolean;
			updatedAt?: string;
		}>;
	}> => {
		const accessToken = await ctx.runQuery(
			internal.githubIntegration.getGithubAccessToken,
			{},
		);
		if (!accessToken) {
			throw new Error(
				"No GitHub account is linked. Sign in with GitHub to fetch your repos.",
			);
		}

		const perPage = Math.min(Math.max(args.perPage ?? 100, 1), 100);
		const url = `${GITHUB_API}/user/repos?per_page=${perPage}&sort=updated&affiliation=owner,collaborator,organization_member&visibility=all`;

		const response = await fetch(url, {
			headers: {
				Accept: "application/vnd.github+json",
				Authorization: `Bearer ${accessToken}`,
				"User-Agent": "CyberZen-Sentinel",
				"X-GitHub-Api-Version": "2022-11-28",
			},
		});

		if (!response.ok) {
			const body = await response.text();
			throw new Error(
				`GitHub list repos failed (${response.status}): ${body.slice(0, 200)}`,
			);
		}

		const rawRepos = (await response.json()) as GithubRepo[];

		// Fetch the linked GitHub login so the UI can show "from <login>".
		const meResponse = await fetch(`${GITHUB_API}/user`, {
			headers: {
				Accept: "application/vnd.github+json",
				Authorization: `Bearer ${accessToken}`,
				"User-Agent": "CyberZen-Sentinel",
				"X-GitHub-Api-Version": "2022-11-28",
			},
		});
		const me = meResponse.ok
			? ((await meResponse.json()) as { login: string })
			: { login: "" };

		return {
			login: me.login,
			repos: rawRepos.map((repo) => ({
				id: repo.id,
				fullName: repo.full_name,
				name: repo.name,
				defaultBranch: repo.default_branch || "main",
				primaryLanguage: repo.language || "Unknown",
				visibility: repo.private ? ("private" as const) : ("public" as const),
				description: repo.description ?? undefined,
				htmlUrl: repo.html_url,
				archived: repo.archived,
				fork: repo.fork,
				updatedAt: repo.updated_at ?? undefined,
			})),
		};
	},
});

/**
 * Public-facing view: which VCS providers the current user has linked via
 * authAccounts (e.g. "github", "gitlab"). Pure query, no HTTP.
 *
 * Use `listIntegrationStatusForTenant` alongside this to know whether the
 * tenant has also configured the corresponding integration.
 */
export const listLinkedProviders = query({
	args: { tenantSlug: v.string() },
	returns: v.array(
		v.object({
			provider: v.string(),
			providerAccountId: v.string(),
			linkedAt: v.number(),
		}),
	),
	handler: async (ctx, args) => {
		const identity = await ctx.auth.getUserIdentity();
		if (!identity) {
			return [];
		}

		// We don't filter by tenant at this level: an OAuth link is a
		// property of the user, not the tenant. The tenant filter happens
		// on the consumer side via the integrationStatus join.
		void args.tenantSlug;

		const accounts = (await ctx.db
			.query("authAccounts")
			.withIndex("userIdAndProvider", (q) =>
				q.eq("userId", identity.subject as Id<"users">),
			)
			.collect()) as Doc<"authAccounts">[];

		// Drop the password provider from the "VCS" list — it isn't a VCS.
		return accounts
			.filter(
				(account) => account.provider !== "password" && account.secret,
			)
			.map((account) => ({
				provider: account.provider,
				providerAccountId: account.providerAccountId,
				linkedAt: account._creationTime,
			}));
	},
});
