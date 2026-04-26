export function formatTimestamp(timestamp?: number) {
	if (!timestamp) return "Not yet";
	return new Intl.DateTimeFormat("en-CH", {
		month: "short",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
	}).format(timestamp);
}

export function formatDate(timestamp?: number) {
	if (!timestamp) return "—";
	return new Intl.DateTimeFormat("en-CH", {
		year: "numeric",
		month: "short",
		day: "2-digit",
	}).format(timestamp);
}

export type Tone = "neutral" | "success" | "warning" | "danger" | "info";

export function severityTone(severity: string): Tone {
	if (severity === "critical" || severity === "high") return "danger";
	if (severity === "medium") return "warning";
	return "info";
}

export function workflowTone(status: string): Tone {
	if (status === "completed") return "success";
	if (status === "failed") return "danger";
	if (status === "running") return "info";
	return "warning";
}

export function disclosureTone(status: string): Tone {
	if (status === "matched") return "danger";
	if (status === "version_unknown" || status === "no_snapshot") return "warning";
	if (status === "version_unaffected") return "success";
	return "info";
}

export function syncTone(status: string): Tone {
	if (status === "failed") return "danger";
	if (status === "skipped") return "warning";
	return "success";
}

export function validationTone(status?: string): Tone {
	if (status === "validated") return "success";
	if (status === "likely_exploitable") return "warning";
	if (status === "unexploitable") return "info";
	return workflowTone(status ?? "queued");
}

export function blastTierTone(riskTier: string): Tone {
	if (riskTier === "critical") return "danger";
	if (riskTier === "high") return "warning";
	if (riskTier === "medium") return "neutral";
	return "success";
}

export function attackSurfaceTone(score: number): Tone {
	if (score >= 70) return "success";
	if (score >= 40) return "warning";
	if (score > 0) return "danger";
	return "neutral";
}

export function driftLevelTone(level: string): Tone {
	if (level === "non_compliant") return "danger";
	if (level === "at_risk" || level === "drifting") return "warning";
	return "success";
}

export function frameworkScoreTone(score: number): Tone {
	if (score >= 80) return "success";
	if (score >= 60) return "warning";
	return "danger";
}

export function slaComplianceTone(rate: number): Tone {
	if (rate >= 0.9) return "success";
	if (rate >= 0.7) return "warning";
	return "danger";
}

export function priorityTierTone(tier: string): Tone {
	if (tier === "p0") return "danger";
	if (tier === "p1") return "warning";
	if (tier === "p2") return "info";
	return "neutral";
}

export function trendTone(trend: string): Tone {
	if (trend === "improving") return "success";
	if (trend === "degrading") return "warning";
	return "neutral";
}

export function supplyChainRiskTone(riskLevel: string): Tone {
	if (riskLevel === "critical" || riskLevel === "high") return "danger";
	if (riskLevel === "medium") return "warning";
	return "success";
}

export function injectionRiskTone(riskLevel: string): Tone {
	if (
		riskLevel === "confirmed_injection" ||
		riskLevel === "likely_injection"
	)
		return "danger";
	if (riskLevel === "suspicious") return "warning";
	return "success";
}

export function honeypotScoreTone(score: number): Tone {
	if (score >= 85) return "danger";
	if (score >= 70) return "warning";
	return "neutral";
}

export function learningTrendTone(trend: string): Tone {
	if (trend === "improving") return "success";
	if (trend === "degrading") return "danger";
	return "neutral";
}

export function maturityTone(score: number): Tone {
	if (score >= 70) return "success";
	if (score >= 35) return "warning";
	return "neutral";
}

export function multiplierTone(m: number): Tone {
	if (m >= 1.5) return "danger";
	return "neutral";
}

export function repositoryHealthTone(score: number): Tone {
	if (score >= 80) return "success";
	if (score >= 60) return "warning";
	return "danger";
}

export function formatLayerLabel(layer: string) {
	if (layer === "ai_model") return "AI model";
	return layer.replace("_", " ");
}
