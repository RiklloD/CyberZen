import type { Id } from "./convex";
import { severityRank } from "./format";

/**
 * Row shape returned by `api.findings.list` (mirrors `findingListRow` in
 * convex/findings.ts). Declared explicitly because the generated API types
 * resolve to `any` for this module.
 */
export interface FindingRow {
	_id: Id<"findings">;
	title: string;
	summary: string;
	severity: "critical" | "high" | "medium" | "low" | "informational";
	validationStatus: string;
	status: string;
	confidence: number;
	source: string;
	vulnClass: string;
	affectedPackages: string[];
	createdAt: number;
	resolvedAt?: number;
	prUrl?: string;
	repositoryId: Id<"repositories">;
	repositoryName: string;
	repositoryFullName: string;
	disclosureRef?: string;
	fixVersion?: string;
}

export const OPEN_STATUSES = new Set(["open", "pr_opened"]);

export function isOpen(f: Pick<FindingRow, "status">) {
	return OPEN_STATUSES.has(f.status);
}

export function isExploitable(f: Pick<FindingRow, "validationStatus">) {
	return f.validationStatus === "validated" || f.validationStatus === "likely_exploitable";
}

/**
 * Order findings by what to fix first: severity, then proven exploitability,
 * then whether a fix version is known, then age (oldest first — closest to SLA).
 */
export function compareByPriority(a: FindingRow, b: FindingRow) {
	return (
		severityRank(a.severity) - severityRank(b.severity) ||
		Number(isExploitable(b)) - Number(isExploitable(a)) ||
		Number(!!b.fixVersion) - Number(!!a.fixVersion) ||
		a.createdAt - b.createdAt
	);
}

export type FindingGroup = {
	key: string;
	/** Highest-priority finding in the group; used for display. */
	lead: FindingRow;
	items: FindingRow[];
};

/**
 * Collapse findings with the same title in the same repository (e.g. 13×
 * "High-entropy string literal") into one row with a count.
 */
export function groupFindings(findings: FindingRow[]): FindingGroup[] {
	const map = new Map<string, FindingGroup>();
	for (const f of findings) {
		const key = `${f.repositoryId}::${f.title}`;
		const group = map.get(key);
		if (group) {
			group.items.push(f);
			if (compareByPriority(f, group.lead) < 0) group.lead = f;
		} else {
			map.set(key, { key, lead: f, items: [f] });
		}
	}
	return [...map.values()].sort((a, b) => compareByPriority(a.lead, b.lead));
}

export function countBySeverity(findings: Pick<FindingRow, "severity">[]) {
	const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
	for (const f of findings) {
		if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
	}
	return counts;
}
