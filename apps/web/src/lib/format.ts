/**
 * Display helpers shared by the redesigned surfaces.
 */

const ACRONYMS = new Set([
	"ci", "cd", "cicd", "iac", "sbom", "sla", "pr", "prs", "llm", "api", "cve",
	"osv", "ghsa", "kev", "cisa", "otx", "tls", "sso", "saml", "dns", "vpn",
	"k8s", "siem", "eol", "epss", "poc", "ai", "ml", "id",
]);

const OVERRIDES: Record<string, string> = {
	cicd: "CI/CD",
	cicd_scan: "CI/CD scan",
	iac_scan: "IaC scan",
	secret_scan: "Secret scan",
	crypto_weakness_scan: "Crypto weakness",
	sensitive_file_scan: "Sensitive files",
	semantic_fingerprint: "Semantic fingerprint",
	breach_intel: "Breach intel",
	red_agent: "Red agent",
	blue_agent: "Blue agent",
	traffic_monitor: "Traffic monitor",
	cisa_kev: "CISA KEV",
	pr_opened: "PR opened",
	accepted_risk: "Risk accepted",
	false_positive: "False positive",
	likely_exploitable: "Likely exploitable",
	version_unaffected: "Not affected",
	version_unknown: "Version unknown",
	no_snapshot: "No SBOM",
	npm: "npm",
	pypi: "PyPI",
	github: "GitHub",
	gitlab: "GitLab",
	bitbucket: "Bitbucket",
	nuget: "NuGet",
	crates: "crates.io",
	golang: "Go",
	go: "Go",
};

/** `crypto_weakness_scan` → "Crypto weakness", `pr_opened` → "PR opened". */
export function humanize(value: string): string {
	if (!value) return value;
	const key = value.toLowerCase();
	if (OVERRIDES[key]) return OVERRIDES[key];
	// Leave already-formatted strings (spaces + capitals, emoji, digits-first) alone.
	if (!/[_-]/.test(value) && value !== value.toLowerCase()) return value;
	const words = value.replace(/[_-]+/g, " ").trim().split(/\s+/);
	return words
		.map((w, i) => {
			const lw = w.toLowerCase();
			if (ACRONYMS.has(lw)) return lw.toUpperCase();
			return i === 0 ? lw.charAt(0).toUpperCase() + lw.slice(1) : lw;
		})
		.join(" ");
}

const RTF = new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "short" });

/** "3m ago", "yesterday", "2 wk. ago". Falls back to "—" for missing values. */
export function relativeTime(timestamp?: number, now: number = Date.now()): string {
	if (!timestamp) return "—";
	const diff = timestamp - now;
	const abs = Math.abs(diff);
	const min = 60_000;
	const hour = 60 * min;
	const day = 24 * hour;
	if (abs < min) return "just now";
	if (abs < hour) return RTF.format(Math.round(diff / min), "minute");
	if (abs < day) return RTF.format(Math.round(diff / hour), "hour");
	if (abs < 7 * day) return RTF.format(Math.round(diff / day), "day");
	if (abs < 30 * day) return RTF.format(Math.round(diff / (7 * day)), "week");
	if (abs < 365 * day) return RTF.format(Math.round(diff / (30 * day)), "month");
	return RTF.format(Math.round(diff / (365 * day)), "year");
}

/** Full timestamp for tooltips. */
export function absoluteTime(timestamp?: number): string {
	if (!timestamp) return "";
	return new Intl.DateTimeFormat(undefined, {
		dateStyle: "medium",
		timeStyle: "short",
	}).format(timestamp);
}

export const SEVERITY_ORDER = [
	"critical",
	"high",
	"medium",
	"low",
	"informational",
] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export function severityRank(severity: string): number {
	const idx = SEVERITY_ORDER.indexOf(severity as Severity);
	return idx === -1 ? SEVERITY_ORDER.length : idx;
}

export function plural(count: number, one: string, many = `${one}s`): string {
	return `${count} ${count === 1 ? one : many}`;
}

/** `RiklloD/CyberZen` → `CyberZen`. */
export function repoShortName(fullName: string): string {
	const idx = fullName.lastIndexOf("/");
	return idx === -1 ? fullName : fullName.slice(idx + 1);
}
