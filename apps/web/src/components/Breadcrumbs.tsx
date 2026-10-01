import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import { humanize } from "../lib/format";

/**
 * Breadcrumb navigation — shows the user where they are in the IA hierarchy.
 *
 * Uses a label map to resolve route paths to human-readable names.
 * Rendered inside the sticky top bar.
 */

const LABEL_MAP: Record<string, string> = {
	"/": "Overview",
	"/findings": "Findings",
	"/repositories": "Repositories",
	"/breach-intel": "Breach intel",
	"/attack-paths": "Attack paths",
	"/supply-chain": "Supply chain",
	"/sbom": "SBOM",
	"/cross-repo": "Cross-Repo",
	"/zero-day": "Zero-day",
	"/exploit-validation": "Exploit validation",
	"/ci-cd": "CI/CD gates",
	"/remediation": "Remediation",
	"/agent-activity": "Agents",
	"/settings/llm-providers": "LLM providers",
	"/neural-memory": "Neural memory",
	"/agents": "Agents & learning",
	"/reports": "Reports",
	"/posture": "Security posture",
	"/executive-report": "Executive report",
	"/maturity": "Maturity assessment",
	"/business-impact": "Business impact",
	"/compliance": "Compliance",
	"/settings": "Settings",
	"/settings/general": "General",
	"/settings/team": "Team",
	"/settings/roles": "Roles & permissions",
	"/settings/billing": "Billing",
	"/settings/api-keys": "API keys",
	"/settings/webhooks": "Webhooks",
	"/settings/scans": "Scan schedules",
	"/settings/policies": "Policy builder",
	"/settings/suppression": "Suppression rules",
	"/settings/notifications": "Notifications",
	"/settings/on-call": "On-Call",
	"/settings/two-factor": "Two-factor auth",
	"/settings/sso": "SSO / SAML",
	"/settings/sessions": "Sessions",
	"/settings/ip-allowlist": "IP allowlist",
	"/settings/access-review": "Access review",
	"/settings/mssp-keys": "MSSP keys",
	"/settings/retention": "Data retention",
	"/settings/data-privacy": "Data privacy",
	"/settings/jobs": "Background jobs",
	"/settings/sla": "SLA policies",
	"/settings/deployment": "Deployment mode",
	"/audit-log": "Audit log",
	"/timeline": "Timeline",
	"/integrations": "Integrations",
	"/marketplace": "Marketplace",
	"/onboarding": "Onboarding",
	"/connect/github": "Connect GitHub",
	"/dashboards": "Dashboard builder",
	"/docs/api": "API docs",
	"/docs/github-integration": "GitHub Action",
	"/mssp": "MSSP portal",
	"/status": "Status",
	"/pricing": "Pricing",
};

/**
 * Build breadcrumb segments from the current path.
 * Settings and docs pages get their section as a parent.
 */
function getBreadcrumbs(pathname: string): { label: string; to: string }[] {
	const path = pathname.length > 1 ? pathname.replace(/\/$/, "") : pathname;
	if (path === "/") return [{ label: "Overview", to: "/" }];

	const fallback = humanize(path.split("/").filter(Boolean).at(-1) ?? "");

	if (path.startsWith("/settings/")) {
		return [
			{ label: "Settings", to: "/settings" },
			{ label: LABEL_MAP[path] ?? fallback, to: path },
		];
	}
	if (path.startsWith("/docs/")) {
		return [
			{ label: "Docs", to: "/docs/api" },
			{ label: LABEL_MAP[path] ?? fallback, to: path },
		];
	}
	if (path.startsWith("/dashboards/")) {
		return [
			{ label: "Dashboards", to: "/dashboards" },
			{ label: "Dashboard", to: path },
		];
	}
	return [{ label: LABEL_MAP[path] ?? fallback, to: path }];
}

export default function Breadcrumbs() {
	const pathname = useRouterState({ select: (s) => s.location.pathname });
	const crumbs = getBreadcrumbs(pathname);

	return (
		<nav className="breadcrumbs" aria-label="Breadcrumb">
			{crumbs.map((crumb, i) => {
				const isLast = i === crumbs.length - 1;
				return (
					<span key={crumb.to} className="inline-flex min-w-0 items-center gap-1.5">
						{isLast ? (
							<span className="breadcrumb-current" aria-current="page">
								{crumb.label}
							</span>
						) : (
							<>
								<Link to={crumb.to as "/"} className="breadcrumb-link">
									{crumb.label}
								</Link>
								<ChevronRight size={13} className="breadcrumb-separator" />
							</>
						)}
					</span>
				);
			})}
		</nav>
	);
}
