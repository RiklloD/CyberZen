import { createFileRoute } from "@tanstack/react-router";
import { Clock } from "lucide-react";
import SlaPolicyForm from "../../components/settings/SlaPolicyForm";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/sla")({
	errorComponent: RouteErrorBoundary,
	component: SlaSettingsPage });

function SlaSettingsPage() {
	const TENANT = useTenantSlug();

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Clock size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">SLA Policy</h1>
						<p className="page-subtitle">
							Configure per-severity response deadlines
						</p>
					</div>
				</div>
			</div>
			<div className="page-body">
				<SlaPolicyForm tenantSlug={TENANT} />
			</div>
		</main>
	);
}
