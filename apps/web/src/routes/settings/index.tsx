import { createFileRoute, Link } from "@tanstack/react-router";
import { Search } from "lucide-react";
import { useState } from "react";
import { SETTINGS_GROUPS } from "../../components/SettingsLayout";
import EmptyState from "../../components/ui/EmptyState";
import PageHeader from "../../components/ui/PageHeader";

export const Route = createFileRoute("/settings/")({
	component: SettingsHubPage,
});

/** Settings landing: every settings area at a glance, filterable. */
function SettingsHubPage() {
	const [query, setQuery] = useState("");
	const q = query.trim().toLowerCase();
	const groups = SETTINGS_GROUPS.map((g) => ({
		...g,
		links: g.links.filter(
			(l) =>
				!q || l.label.toLowerCase().includes(q) || (l.description ?? "").toLowerCase().includes(q),
		),
	})).filter((g) => g.links.length > 0);

	return (
		<main>
			<PageHeader
				title="Settings"
				description="Workspace, integrations, security policy and access"
				actions={
					<label className="search-input w-64">
						<Search size={14} />
						<input
							type="search"
							placeholder="Find a setting…"
							value={query}
							onChange={(e) => setQuery(e.target.value)}
							autoFocus
						/>
					</label>
				}
			/>
			<div className="page-body space-y-7">
				{groups.length === 0 && (
					<div className="list">
						<EmptyState title={`No settings match “${query}”`} />
					</div>
				)}
				{groups.map((group) => (
					<section key={group.label}>
						<h2 className="section-title mb-3">{group.label}</h2>
						<div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
							{group.links.map((link) => (
								<Link
									key={link.to}
									to={link.to as "/"}
									className="card card-sm flex items-start gap-3 !text-[var(--text)] hover:border-[var(--line-strong)] hover:bg-[var(--surface-2)]"
								>
									<span className="metric-icon shrink-0">
										<link.icon size={14} />
									</span>
									<span className="min-w-0">
										<span className="block text-[0.85rem] font-medium">{link.label}</span>
										{link.description && (
											<span className="block text-xs text-[var(--text-3)]">{link.description}</span>
										)}
									</span>
								</Link>
							))}
						</div>
					</section>
				))}
			</div>
		</main>
	);
}
