import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Loader2, Save, Settings } from "lucide-react";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/general")({
	errorComponent: QueryErrorFallback,
	component: GeneralSettingsPage,
});

/**
 * §3.13 — Workspace General Settings.
 *
 * Uses:
 *   useQuery(api.workspaceAuth.getWorkspaceSettings)
 *   useMutation(api.workspaceAuth.updateWorkspaceSettings)
 *
 * Provides editable fields for:
 *   • Workspace name
 *   • Default policy (dropdown)
 *   • Deployment mode (dropdown)
 */

type PolicyOption = "standard" | "strict" | "permissive" | "custom";
type DeploymentMode = "production" | "staging" | "development" | "evaluation";

const POLICY_OPTIONS: { value: PolicyOption; label: string }[] = [
	{ value: "standard", label: "Standard" },
	{ value: "strict", label: "Strict" },
	{ value: "permissive", label: "Permissive" },
	{ value: "custom", label: "Custom" },
];

const DEPLOYMENT_MODE_OPTIONS: { value: DeploymentMode; label: string }[] = [
	{ value: "production", label: "Production" },
	{ value: "staging", label: "Staging" },
	{ value: "development", label: "Development" },
	{ value: "evaluation", label: "Evaluation" },
];

interface WorkspaceSettings {
	name: string;
	defaultPolicy: PolicyOption;
	deploymentMode: DeploymentMode;
}

function GeneralSettingsPage() {
	const TENANT = useTenantSlug();
	const settings = useQuery(api.workspaceAuth.getWorkspaceSettings, {
		tenantSlug: TENANT,
	});
	const updateSettings = useMutation(
		api.workspaceAuth.updateWorkspaceSettings,
	);

	const [form, setForm] = useState<WorkspaceSettings | null>(null);
	const [saving, setSaving] = useState(false);
	const [saveMsg, setSaveMsg] = useState<string | null>(null);

	// Sync query data into local form once loaded
	const currentForm: WorkspaceSettings = form ?? {
		name: settings?.name ?? "",
		defaultPolicy: (settings?.defaultPolicy as PolicyOption) ?? "standard",
		deploymentMode:
			(settings?.deploymentMode as DeploymentMode) ?? "production",
	};

	const handleSave = async () => {
		setSaving(true);
		setSaveMsg(null);
		try {
			await updateSettings({
				tenantSlug: TENANT,
				name: currentForm.name,
				defaultPolicy: currentForm.defaultPolicy,
				deploymentMode: currentForm.deploymentMode,
			});
			setSaveMsg("Settings saved successfully.");
		} catch (err) {
			setSaveMsg(
				err instanceof Error ? err.message : "Failed to save settings.",
			);
		} finally {
			setSaving(false);
			setTimeout(() => setSaveMsg(null), 4000);
		}
	};

	if (!settings) {
		return (
			<main className="page-body-padded">
				<div className="space-y-4">
					{["a", "b", "c"].map((k) => (
						<div key={k} className="loading-panel h-16 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Settings size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">General Settings</h1>
						<p className="page-subtitle">
							Configure workspace name, policies, and deployment mode
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="card card-sm space-y-5 max-w-2xl">
					{/* Workspace Name */}
					<div>
						<label
							htmlFor="workspace-name"
							className="block text-sm font-medium text-[var(--sea-ink)] mb-1"
						>
							Workspace Name
						</label>
						<input
							id="workspace-name"
							type="text"
							value={currentForm.name}
							onChange={(e) =>
								setForm({ ...currentForm, name: e.target.value })
							}
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] outline-none focus:border-[var(--signal)] transition-colors"
							placeholder="My Workspace"
						/>
					</div>

					{/* Default Policy */}
					<div>
						<label
							htmlFor="default-policy"
							className="block text-sm font-medium text-[var(--sea-ink)] mb-1"
						>
							Default Policy
						</label>
						<select
							id="default-policy"
							value={currentForm.defaultPolicy}
							onChange={(e) =>
								setForm({
									...currentForm,
									defaultPolicy: e.target.value as PolicyOption,
								})
							}
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] outline-none focus:border-[var(--signal)] transition-colors"
						>
							{POLICY_OPTIONS.map((opt) => (
								<option key={opt.value} value={opt.value}>
									{opt.label}
								</option>
							))}
						</select>
						<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
							Sets the default security policy applied to newly connected
							repositories.
						</p>
					</div>

					{/* Deployment Mode */}
					<div>
						<label
							htmlFor="deployment-mode"
							className="block text-sm font-medium text-[var(--sea-ink)] mb-1"
						>
							Deployment Mode
						</label>
						<select
							id="deployment-mode"
							value={currentForm.deploymentMode}
							onChange={(e) =>
								setForm({
									...currentForm,
									deploymentMode: e.target.value as DeploymentMode,
								})
							}
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] outline-none focus:border-[var(--signal)] transition-colors"
						>
							{DEPLOYMENT_MODE_OPTIONS.map((opt) => (
								<option key={opt.value} value={opt.value}>
									{opt.label}
								</option>
							))}
						</select>
						<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
							Controls how aggressively scanners and enforcement agents run
							across your workspace.
						</p>
					</div>

					{/* Save */}
					<div className="flex items-center gap-3 pt-2">
						<button
							type="button"
							className="signal-button inline-flex items-center gap-1.5 text-xs"
							onClick={handleSave}
							disabled={saving}
						>
							{saving ? (
								<Loader2 size={14} className="animate-spin" />
							) : (
								<Save size={14} />
							)}
							{saving ? "Saving…" : "Save Changes"}
						</button>

						{saveMsg && (
							<span
								className={`text-xs ${saveMsg.includes("success") || saveMsg.includes("saved") ? "text-[var(--success)]" : "text-[var(--danger)]"}`}
							>
								{saveMsg}
							</span>
						)}
					</div>
				</div>
			</div>
		</main>
	);
}
