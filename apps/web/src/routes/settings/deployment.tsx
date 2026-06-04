import { useAuthToken } from "@convex-dev/auth/react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { AlertTriangle, Cloud, Lock, Server, Shuffle } from "lucide-react";
import { useState } from "react";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";
import StatusPill from "../../components/StatusPill";
import { useFeatureFlag } from "../../lib/featureFlags";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";

export const Route = createFileRoute("/settings/deployment")({
	errorComponent: RouteErrorBoundary,
	component: DeploymentSettingsPage,
});

type CanonicalMode = "cloud_saas" | "vpc_injection" | "on_prem";

const MODE_OPTIONS: Array<{
	value: CanonicalMode;
	label: string;
	description: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
}> = [
	{
		value: "cloud_saas",
		label: "Cloud SaaS",
		description: "Hosted by Sentinel. Lowest operational burden.",
		icon: Cloud,
	},
	{
		value: "vpc_injection",
		label: "Hybrid (VPC Injection)",
		description:
			"Workers run in your VPC, control plane stays managed by Sentinel.",
		icon: Shuffle,
	},
	{
		value: "on_prem",
		label: "On-Prem",
		description:
			"Fully self-hosted. No egress, no managed updates. Customer-owned data.",
		icon: Server,
	},
];

function DeploymentSettingsPage() {
	const enabled = useFeatureFlag("deployment_toggle");

	if (enabled === undefined) {
		return <div className="page-body-padded loading-panel h-48 rounded-2xl" />;
	}

	if (!enabled) {
		return (
			<main>
				<div className="page-header">
					<div className="flex items-center gap-3">
						<Server size={20} className="text-[var(--signal)]" />
						<div>
							<h1 className="page-title">Deployment Mode</h1>
							<p className="page-subtitle">
								Switch between Cloud SaaS, Hybrid, and On-Prem
							</p>
						</div>
					</div>
				</div>
				<div className="page-body">
					<div className="card">
						<div className="flex items-start gap-3">
							<Lock size={18} className="text-[var(--signal)] mt-0.5" />
							<div>
								<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
									Deployment Mode Toggle requires Enterprise
								</h3>
								<p className="text-xs text-[var(--sea-ink-soft)] mt-1">
									Hybrid and On-Prem deployment modes are part of the Enterprise
									plan.
								</p>
								<Link
									to="/pricing"
									className="signal-button inline-flex items-center gap-1 mt-3"
									style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
								>
									See Enterprise plans
								</Link>
							</div>
						</div>
					</div>
				</div>
			</main>
		);
	}

	return <DeploymentModePanel />;
}

function DeploymentModePanel() {
	const tenantSlug = useTenantSlug();
	const authToken = useAuthToken();
	const current = useQuery(api.deploymentMode.getDeploymentModeForSlug, {
		tenantSlug,
	});
	const switchMode = useMutation(api.deploymentMode.switchDeploymentMode);
	const [pendingTarget, setPendingTarget] = useState<CanonicalMode | null>(
		null,
	);
	const [confirmTarget, setConfirmTarget] = useState<CanonicalMode | null>(
		null,
	);
	const [error, setError] = useState<string | null>(null);

	if (!current || !authToken) {
		return <div className="page-body-padded loading-panel h-48 rounded-2xl" />;
	}

	async function applySwitch() {
		if (!confirmTarget || !authToken || !current) return;
		setPendingTarget(confirmTarget);
		setError(null);
		try {
			await switchMode({
				authToken,
				tenantId: current.tenantId,
				mode: confirmTarget,
			});
			setConfirmTarget(null);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Switch failed");
		} finally {
			setPendingTarget(null);
		}
	}

	const env = current.environment;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Server size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Deployment Mode</h1>
						<p className="page-subtitle">
							Switch between Cloud SaaS, Hybrid, and On-Prem
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-4">
				<div className="card">
					<div className="flex items-center justify-between">
						<div>
							<p className="text-[10px] uppercase tracking-wide text-[var(--sea-ink-soft)]">
								Current deployment mode
							</p>
							<div className="flex items-center gap-2 mt-1">
								<h3 className="text-lg font-bold text-[var(--sea-ink)]">
									{current.label}
								</h3>
								<StatusPill label={current.mode} tone="neutral" />
							</div>
						</div>
					</div>
					<div className="grid gap-2 sm:grid-cols-2 mt-4 text-xs">
						<EnvRow label="Hosting Region" value={env.hostingRegion} />
						<EnvRow
							label="Egress Enabled"
							value={env.egressEnabled ? "yes" : "no"}
						/>
						<EnvRow
							label="Managed Updates"
							value={env.managedUpdates ? "yes" : "no"}
						/>
						<EnvRow label="Data Residency" value={env.dataResidency} />
					</div>
				</div>

				<div className="card">
					<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-3">
						Switch deployment mode
					</h3>
					<div className="grid gap-3 sm:grid-cols-3">
						{MODE_OPTIONS.map((opt) => {
							const isCurrent = opt.value === current.mode;
							const Icon = opt.icon;
							return (
								<button
									type="button"
									key={opt.value}
									disabled={isCurrent || pendingTarget !== null}
									onClick={() => setConfirmTarget(opt.value)}
									className={`text-left rounded-xl border p-3 transition-colors ${
										isCurrent
											? "border-[var(--signal)] bg-[var(--signal-soft)]"
											: "border-[var(--line)] hover:border-[var(--signal)]"
									} disabled:opacity-60 disabled:cursor-not-allowed`}
								>
									<div className="flex items-center gap-2 mb-1">
										<Icon size={14} className="text-[var(--signal)]" />
										<span className="text-sm font-semibold text-[var(--sea-ink)]">
											{opt.label}
										</span>
										{isCurrent && (
											<StatusPill label="Current" tone="success" />
										)}
									</div>
									<p className="text-xs text-[var(--sea-ink-soft)]">
										{opt.description}
									</p>
								</button>
							);
						})}
					</div>
					{error && (
						<p className="mt-3 text-xs text-[var(--danger)]">{error}</p>
					)}
				</div>
			</div>

			{confirmTarget && (
				<ConfirmModal
					target={confirmTarget}
					currentLabel={current.label}
					onCancel={() => setConfirmTarget(null)}
					onConfirm={applySwitch}
					pending={pendingTarget !== null}
				/>
			)}
		</main>
	);
}

function EnvRow({ label, value }: { label: string; value: string }) {
	return (
		<div className="flex items-center justify-between rounded-lg bg-[var(--surface-soft)] px-3 py-2">
			<span className="text-[10px] uppercase tracking-wide text-[var(--sea-ink-soft)]">
				{label}
			</span>
			<span className="text-xs font-semibold text-[var(--sea-ink)]">
				{value}
			</span>
		</div>
	);
}

function ConfirmModal({
	target,
	currentLabel,
	onCancel,
	onConfirm,
	pending,
}: {
	target: CanonicalMode;
	currentLabel: string;
	onCancel: () => void;
	onConfirm: () => void;
	pending: boolean;
}) {
	const targetMeta = MODE_OPTIONS.find((o) => o.value === target);

	return (
		<div
			className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
			role="dialog"
			aria-modal="true"
		>
			<div className="card max-w-md w-full m-4">
				<div className="flex items-start gap-3 mb-3">
					<AlertTriangle
						size={18}
						className="text-[var(--warning)] flex-shrink-0 mt-0.5"
					/>
					<div>
						<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
							Switch to {targetMeta?.label}?
						</h3>
						<p className="text-xs text-[var(--sea-ink-soft)] mt-1">
							You are about to move this workspace from <strong>{currentLabel}</strong> to{" "}
							<strong>{targetMeta?.label}</strong>. Some integrations may be
							disabled and infrastructure defaults will change.
						</p>
					</div>
				</div>

				<div className="flex items-center justify-end gap-2">
					<button
						type="button"
						className="signal-button secondary-button"
						style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
						onClick={onCancel}
						disabled={pending}
					>
						Cancel
					</button>
					<button
						type="button"
						className="signal-button"
						style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
						onClick={onConfirm}
						disabled={pending}
					>
						{pending ? "Switching…" : "Confirm switch"}
					</button>
				</div>
			</div>
		</div>
	);
}
