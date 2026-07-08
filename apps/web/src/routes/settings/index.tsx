import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/settings/")({
	component: SettingsHubPage,
});

function SettingsHubPage() {
	return (
		<main>
			<div className="page-header">
				<h1 className="page-title">Settings</h1>
				<p className="page-subtitle">
					Workspace configuration, team, integrations, and policies
				</p>
			</div>
			<div className="page-body">
				<div className="panel rounded-2xl p-6">
					<p className="text-sm text-[var(--sea-ink-soft)]">
						Use the navigation on the left to configure your workspace.
						Start with <strong>General</strong> to set your workspace name,
						then connect repositories and set up scan schedules.
					</p>
				</div>
			</div>
		</main>
	);
}
