import { createFileRoute, redirect } from "@tanstack/react-router";
import { BarChart3, Briefcase, ClipboardCheck, ShieldCheck, Trophy } from "lucide-react";
import HubTabs from "../components/HubTabs";

/**
 * Reports hub — landing page with tabs linking to all report types.
 * Redirects to the default tab (Security Posture) on visit.
 */
export const Route = createFileRoute("/reports")({
	beforeLoad: () => {
		throw redirect({ to: "/posture" });
	},
});

// Exported for reuse by sub-pages
export const REPORTS_TABS = [
	{ key: "posture", label: "Security Posture", icon: ShieldCheck, to: "/posture" },
	{ key: "executive", label: "Executive Report", icon: BarChart3, to: "/executive-report" },
	{ key: "maturity", label: "Maturity Assessment", icon: Trophy, to: "/maturity" },
	{ key: "business-impact", label: "Business Impact", icon: Briefcase, to: "/business-impact" },
	{ key: "compliance", label: "Compliance", icon: ClipboardCheck, to: "/compliance" },
];
