import { Link } from "@tanstack/react-router";
import { ChevronRight, Home } from "lucide-react";
import { useRouterState } from "@tanstack/react-router";

/**
 * Breadcrumb navigation — shows the user where they are in the IA hierarchy.
 *
 * Uses a label map to resolve route paths to human-readable names.
 * Rendered at the top of each page above the page-header.
 */

const LABEL_MAP: Record<string, string> = {
	"/": "Dashboard",
	"/findings": "Findings",
	"/repositories": "Repositories",
	"/breach-intel": "Breach Intel",
	"/attack-paths": "Attack Paths",
	"/supply-chain": "Supply Chain",
	"/sbom": "SBOM",
	"/cross-repo": "Cross-Repo",
	"/zero-day": "Zero-Day",
	"/exploit-validation": "Exploit Validation",
	"/ci-cd": "CI/CD Gates",
	"/remediation": "Remediation",
	"/agent-activity": "Agents",
	"/neural-memory": "Neural Memory",
	"/agents": "Agents & Learning",
	"/reports": "Reports",
	"/posture": "Security Posture",
	"/executive-report": "Executive Report",
	"/maturity": "Maturity Assessment",
	"/business-impact": "Business Impact",
	"/compliance": "Compliance",
	"/settings": "Settings",
	"/settings/general": "General",
	"/settings/team": "Team",
	"/settings/roles": "Roles & Permissions",
	"/settings/billing": "Billing",
	"/settings/api-keys": "API Keys",
	"/settings/webhooks": "Webhooks",
	"/settings/scans": "Scan Schedules",
	"/settings/policies": "Policy Builder",
	"/settings/suppression": "Suppression Rules",
	"/settings/notifications": "Notifications",
	"/settings/on-call": "On-Call",
	"/settings/two-factor": "Two-Factor Auth",
	"/settings/sso": "SSO / SAML",
	"/settings/sessions": "Sessions",
	"/settings/ip-allowlist": "IP Allowlist",
	"/settings/access-review": "Access Review",
	"/settings/mssp-keys": "MSSP Keys",
	"/settings/retention": "Data Retention",
	"/settings/data-privacy": "Data Privacy",
	"/settings/jobs": "Background Jobs",
	"/settings/sla": "SLA Policies",
	"/settings/deployment": "Deployment Mode",
	"/audit-log": "Audit Log",
	"/timeline": "Timeline",
	"/integrations": "Integrations",
	"/marketplace": "Marketplace",
	"/onboarding": "Onboarding",
	"/connect/github": "Connect GitHub",
	"/dashboards": "Dashboard Builder",
	"/docs/api": "API Docs",
	"/docs/github-integration": "GitHub Action",
	"/mssp": "MSSP Portal",
	"/status": "Status",
	"/pricing": "Pricing",
};

/**
 * Build breadcrumb segments from the current path.
 * Settings pages get a "Settings" parent.
 */
function getBreadcrumbs(pathname: string): { label: string; to: string }[] {
	const segments: { label: string; to: string }[] = [
		{ label: "Home", to: "/" },
	];

	// Handle settings sub-pages
	if (pathname.startsWith("/settings/") && pathname !== "/settings") {
		segments.push({ label: "Settings", to: "/settings" });
		const label = LABEL_MAP[pathname];
		if (label) segments.push({ label, to: pathname });
		return segments;
	}

	// Handle docs
	if (pathname.startsWith("/docs/")) {
		segments.push({ label: LABEL_MAP[pathname] ?? "Docs", to: pathname });
		return segments;
	}

	const label = LABEL_MAP[pathname];
	if (label && pathname !== "/") {
		segments.push({ label, to: pathname });
	}

	return segments;
}

export default function Breadcrumbs() {
	const routerState = useRouterState();
	const crumbs = getBreadcrumbs(routerState.location.pathname);

	if (crumbs.length <= 1) return null;

	return (
		<nav className="breadcrumbs" aria-label="Breadcrumb">
			{crumbs.map((crumb, i) => {
				const isLast = i === crumbs.length - 1;
				return (
					<span key={crumb.to} className="breadcrumb-item-wrapper">
						{i === 0 && <Home size={12} className="breadcrumb-home-icon" />}
						{isLast ? (
							<span className="breadcrumb-current">{crumb.label}</span>
						) : (
							<Link
								to={crumb.to as "/"}
								className="breadcrumb-link"
							>
								{crumb.label}
							</Link>
						)}
						{!isLast && (
							<ChevronRight size={12} className="breadcrumb-separator" />
						)}
					</span>
				);
			})}
		</nav>
	);
}
