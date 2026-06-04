import { query } from "./_generated/server";
import { v } from "convex/values";

/**
 * §1.8 LLM Certification — Intel queries
 *
 * Certification status per LLM-using code path in a repository.
 * Status can be: "certified" | "uncertified" | "pending".
 */

// ---------------------------------------------------------------------------
// Types (shared return shapes)
// ---------------------------------------------------------------------------

export interface CertPath {
	pathId: string;
	label: string;
	status: "certified" | "uncertified" | "pending";
	lastCertifiedAt: number | null;
	failureReasons: string[];
	modelVersion: string;
	confidence: number;
}

export interface CertReport {
	_id: string;
	_creationTime: number;
	repositoryId: string;
	overallStatus: "certified" | "uncertified" | "mixed";
	paths: CertPath[];
	summary: string;
	certifiedAt: number | null;
	totalPaths: number;
	certifiedPaths: number;
	uncertifiedPaths: number;
	pendingPaths: number;
}

// ---------------------------------------------------------------------------
// getLatestCertificationReport
// ---------------------------------------------------------------------------

export const getLatestCertificationReport = query({
	args: {
		repositoryId: v.id("repositories"),
	},
	handler: async (_ctx, _args): Promise<CertReport | null> => {
		// Stub — will be backed by real data pipeline.
		// Returns the latest LLM certification report for the given repository.
		return null;
	},
});

// ---------------------------------------------------------------------------
// getCertificationHistory
// ---------------------------------------------------------------------------

export const getCertificationHistory = query({
	args: {
		repositoryId: v.id("repositories"),
		limit: v.optional(v.number()),
	},
	handler: async (_ctx, _args): Promise<CertReport[]> => {
		// Stub — will be backed by real data pipeline.
		return [];
	},
});

// ---------------------------------------------------------------------------
// getTenantCertificationSummary
// ---------------------------------------------------------------------------

export const getTenantCertificationSummary = query({
	args: {
		tenantSlug: v.string(),
	},
	handler: async (_ctx, _args): Promise<{
		totalRepos: number;
		certifiedRepos: number;
		uncertifiedRepos: number;
		pendingRepos: number;
		repos: {
			repositoryId: string;
			repositoryFullName: string;
			overallStatus: "certified" | "uncertified" | "mixed";
			certifiedPaths: number;
			totalPaths: number;
			lastCertifiedAt: number | null;
		}[];
	} | null> => {
		// Stub — will be backed by real data pipeline.
		return null;
	},
});
