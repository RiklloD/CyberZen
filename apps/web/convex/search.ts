import { query } from "./_generated/server";
import { v } from "convex/values";

/**
 * §6.15 — Universal search query.
 *
 * Searches across findings, repositories, and advisory sync runs by
 * text matching. Returns results grouped by category.
 *
 * Note: Convex full-text search requires a searchIndex in the schema.
 * Since no search indexes are currently defined, this uses a lightweight
 * prefix-scan approach via index + client-side filtering. For production
 * at scale, add searchIndex definitions to the relevant tables.
 */

export const universalSearch = query({
	args: {
		tenantId: v.id("tenants"),
		query: v.string(),
		limit: v.optional(v.number()),
	},
	handler: async (ctx, args) => {
		const limit = Math.min(args.limit ?? 20, 50);
		const q = args.query.trim().toLowerCase();

		if (q.length < 2) {
			return { findings: [], repositories: [], advisories: [] };
		}

		// --- Repositories: scan by tenant, filter by name/fullName ---
		const repos = await ctx.db
			.query("repositories")
			.withIndex("by_tenant", (q) => q.eq("tenantId", args.tenantId))
			.collect();

		const matchingRepos = repos
			.filter(
				(r) =>
					r.name.toLowerCase().includes(q) ||
					r.fullName.toLowerCase().includes(q) ||
					r.primaryLanguage.toLowerCase().includes(q),
			)
			.slice(0, limit)
			.map((r) => ({
				_id: r._id,
				type: "repository" as const,
				label: r.fullName,
				sublabel: r.primaryLanguage,
				route: `/repositories?repo=${r._id}`,
			}));

		// --- Findings: scan by tenant, filter by title/vulnClass ---
		const findings = await ctx.db
			.query("findings")
			.withIndex("by_tenant_and_created_at", (q) =>
				q.eq("tenantId", args.tenantId),
			)
			.order("desc")
			.collect();

		const matchingFindings = findings
			.filter(
				(f) =>
					f.title.toLowerCase().includes(q) ||
					f.vulnClass.toLowerCase().includes(q) ||
					f.summary.toLowerCase().includes(q),
			)
			.slice(0, limit)
			.map((f) => ({
				_id: f._id,
				type: "finding" as const,
				label: f.title,
				sublabel: `${f.severity} · ${f.vulnClass}`,
				route: `/findings?finding=${f._id}`,
			}));

		// --- Advisory sync runs: scan by tenant ---
		const advisoryRuns = await ctx.db
			.query("advisorySyncRuns")
			.withIndex("by_tenant_and_started_at", (q) =>
				q.eq("tenantId", args.tenantId),
			)
			.order("desc")
			.collect();

		const matchingAdvisories = advisoryRuns
			.filter(
				(a) =>
					(a.reason ?? "").toLowerCase().includes(q) ||
					a.triggerType.toLowerCase().includes(q),
			)
			.slice(0, limit)
			.map((a) => ({
				_id: a._id,
				type: "advisory" as const,
				label: `Advisory sync — ${a.triggerType}`,
				sublabel: `${a.packageCount} packages · ${a.status}`,
				route: `/breach-intel`,
			}));

		return {
			repositories: matchingRepos,
			findings: matchingFindings,
			advisories: matchingAdvisories,
		};
	},
});
