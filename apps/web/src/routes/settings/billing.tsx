import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useAction } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	CreditCard,
	Check,
	ArrowUpRight,
	Download,
	Sparkles } from "lucide-react";
import { useState } from "react";
import StatusPill from "../../components/StatusPill";
import UpgradeButton from "../../components/UpgradeButton";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/billing")({
	errorComponent: RouteErrorBoundary,
	component: BillingPage });

function BillingPage() {
	const TENANT = useTenantSlug();
	const plans = useQuery(api.billing.listPlans);
	const current = useQuery(api.billing.currentPlanForTenant, {
		tenantSlug: TENANT });
	const invoices = useQuery(api.billing.listInvoicesForTenant, {
		tenantSlug: TENANT });
	const usage = useQuery(api.billing.currentUsageForTenant, {
		tenantSlug: TENANT });
	const tieredPlan = useQuery(api.plans.currentPlanForTenant, {
		tenantSlug: TENANT });
	const tieredPlans = useQuery(api.plans.listPlans);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<CreditCard size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Billing & Subscription</h1>
						<p className="page-subtitle">
							Plan details, usage metrics, and invoices
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{/* §8.1 — Tiered Plan Display */}
				{tieredPlan && (
					<CurrentTierCard
						plan={tieredPlan}
						allTieredPlans={tieredPlans ?? null}
					/>
				)}

				{/* Current Plan Summary */}
				<BillingSummaryCard
					current={current}
					usage={usage}
					plans={plans}
				/>

				{/* Plan Comparison */}
				{plans && plans.length > 0 && (
					<PlanComparisonTable plans={plans} currentPlanSlug={current?.plan?.slug ?? null} />
				)}

				{/* Invoices */}
				<InvoiceList invoices={invoices} />
			</div>
		</main>
	);
}

function CurrentTierCard({
	plan,
	allTieredPlans }: {
	plan: {
		_id: string;
		slug: string;
		name: string;
		monthlyPrice: number;
		repoLimit: number;
		seatLimit: number;
		featureFlags: string[];
	};
	allTieredPlans:
		| Array<{
				_id: string;
				slug: string;
				name: string;
				monthlyPrice: number;
		  }>
		| null;
}) {
	const repoLabel =
		plan.repoLimit < 0 ? "Unlimited" : `${plan.repoLimit} repos`;
	const seatLabel =
		plan.seatLimit < 0 ? "Unlimited seats" : `${plan.seatLimit} seats`;

	const upgradeTarget = allTieredPlans
		? [...allTieredPlans]
				.sort((a, b) => a.monthlyPrice - b.monthlyPrice)
				.find((p) => p.monthlyPrice > plan.monthlyPrice)
		: undefined;

	return (
		<div className="card">
			<div className="flex items-start justify-between gap-3">
				<div>
					<div className="flex items-center gap-2 mb-1">
						<Sparkles size={14} className="text-[var(--signal)]" />
						<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
							Current Tier — {plan.name}
						</h3>
						<StatusPill label={plan.slug} tone="neutral" />
					</div>
					<p className="text-2xl font-bold text-[var(--sea-ink)]">
						${plan.monthlyPrice}
						<span className="text-xs font-normal text-[var(--sea-ink-soft)]">
							/mo
						</span>
					</p>
					<p className="text-xs text-[var(--sea-ink-soft)] mt-1">
						{repoLabel} · {seatLabel} · {plan.featureFlags.length} features
					</p>
				</div>
				<div className="flex flex-col items-end gap-2">
					<Link
						to="/pricing"
						className="text-xs text-[var(--signal)] underline"
					>
						See all plans
					</Link>
					{upgradeTarget && (
						<UpgradeButton
							targetPlanSlug={upgradeTarget.slug}
							label={`Upgrade to ${upgradeTarget.name}`}
						/>
					)}
				</div>
			</div>
		</div>
	);
}

// ─── Sub-components ──────────────────────────────────────────────────────────

type BillingCurrent = NonNullable<FunctionReturnType<typeof api.billing.currentPlanForTenant>>;
type BillingUsage = NonNullable<FunctionReturnType<typeof api.billing.currentUsageForTenant>>;
type BillingPlans = NonNullable<FunctionReturnType<typeof api.billing.listPlans>>;
type BillingInvoices = FunctionReturnType<typeof api.billing.listInvoicesForTenant>;

function BillingSummaryCard({
	current,
	usage,
	plans }: {
	current: BillingCurrent | null | undefined;
	usage: BillingUsage | null | undefined;
	plans: BillingPlans | null | undefined;
}) {
	const TENANT = useTenantSlug();
	const createPortalSession = useAction(api.billingPortal.createPortalSession);
	const [portalLoading, setPortalLoading] = useState(false);

	async function handleManage() {
		setPortalLoading(true);
		try {
			const result = await createPortalSession({ tenantSlug: TENANT });
			if (result?.url) {
				window.location.href = result.url;
			}
		} catch {
			setPortalLoading(false);
		}
	}
	if (!current) {
		return (
			<div className="card">
				<div className="flex items-center gap-3 mb-3">
					<div className="w-10 h-10 rounded-xl bg-[var(--signal-soft)] flex items-center justify-center text-[var(--signal)]">
						<CreditCard size={18} />
					</div>
					<div>
						<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
							No Active Subscription
						</h3>
						<p className="text-xs text-[var(--sea-ink-soft)]">
							Your workspace is on the free tier. Upgrade to unlock more
							features.
						</p>
					</div>
				</div>
				{plans && plans.length > 0 && (
					<p className="text-xs text-[var(--sea-ink-soft)]">
						See the plans below to choose the right one for your team.
					</p>
				)}
			</div>
		);
	}

	const statusTone: Record<string, "success" | "warning" | "danger" | "neutral"> = {
		active: "success",
		trialing: "neutral",
		past_due: "danger",
		canceled: "warning" };

	const planName = current.plan?.name ?? current.subscription.planSlug;
	const priceFmt = current.plan
		? `$${(current.plan.priceCents / 100).toFixed(2)}/${current.plan.interval === "month" ? "mo" : "yr"}`
		: "—";

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-4">
				<div className="flex items-center gap-3">
					<div className="w-10 h-10 rounded-xl bg-[var(--signal-soft)] flex items-center justify-center text-[var(--signal)]">
						<CreditCard size={18} />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
								{planName}
							</h3>
							<StatusPill
								label={current.subscription.status}
								tone={statusTone[current.subscription.status] ?? "neutral"}
							/>
						</div>
						<p className="text-xs text-[var(--sea-ink-soft)]">
							{priceFmt} · Renews{" "}
							{formatTimestamp(current.subscription.currentPeriodEnd)}
						</p>
					</div>
				</div>
				{current.subscription.status === "active" && !current.subscription.cancelAtPeriodEnd && (
					<button
						type="button"
						className="signal-button secondary-button"
						style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
						onClick={handleManage}
						disabled={portalLoading}
					>
						<ArrowUpRight size={12} className="mr-1" />
						{portalLoading ? "Loading..." : "Manage"}
					</button>
				)}
			</div>

			{/* Usage meters */}
			{usage && usage.length > 0 && (
				<div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-3">
					{usage.map((u: BillingUsage[number]) => {
						const plan = current.plan;
						let max: number | undefined;
						if (plan && u.metric === "repositories") max = plan.maxRepositories;
						if (plan && u.metric === "members") max = plan.maxMembers;
						const pct = max ? Math.min((u.value / max) * 100, 100) : undefined;

						return (
							<div
								key={u.metric}
								className="rounded-lg bg-[var(--surface-soft)] p-3"
							>
								<p className="text-[10px] font-medium text-[var(--sea-ink-soft)] uppercase tracking-wide mb-1">
									{u.metric}
								</p>
								<p className="text-sm font-semibold text-[var(--sea-ink)]">
									{u.value}
									{max ? ` / ${max}` : ""}
								</p>
								{pct !== undefined && (
									<div className="mt-1.5 h-1.5 rounded-full bg-[var(--line)] overflow-hidden">
										<div
											className="h-full rounded-full bg-[var(--signal)]"
											style={{ width: `${pct}%` }}
										/>
									</div>
								)}
							</div>
						);
					})}
				</div>
			)}
		</div>
	);
}

function PlanComparisonTable({
	plans,
	currentPlanSlug }: {
	plans: BillingPlans;
	currentPlanSlug: string | null;
}) {
	return (
		<div className="card">
			<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-4">
				Available Plans
			</h3>
			<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
				{plans.map((plan: BillingPlans[number]) => {
					const isCurrent = plan.slug === currentPlanSlug;
					return (
						<div
							key={plan._id}
							className={`rounded-xl border p-4 transition-colors ${
								isCurrent
									? "border-[var(--signal)] bg-[var(--signal-soft)]"
									: plan.highlighted
										? "border-[var(--signal)]"
										: "border-[var(--line)]"
							}`}
						>
							<div className="flex items-center justify-between mb-2">
								<h4 className="text-sm font-semibold text-[var(--sea-ink)]">
									{plan.name}
								</h4>
								{isCurrent && (
									<StatusPill label="Current" tone="success" />
								)}
								{plan.highlighted && !isCurrent && (
									<StatusPill label="Popular" tone="neutral" />
								)}
							</div>
							<p className="text-lg font-bold text-[var(--sea-ink)]">
								${(plan.priceCents / 100).toFixed(0)}
								<span className="text-xs font-normal text-[var(--sea-ink-soft)]">
									/{plan.interval === "month" ? "mo" : "yr"}
								</span>
							</p>
							<p className="text-xs text-[var(--sea-ink-soft)] mt-1 mb-3">
								{plan.description}
							</p>
							<ul className="space-y-1.5">
								{plan.features.map((f: string) => (
									<li
										key={f}
										className="flex items-center gap-1.5 text-xs text-[var(--sea-ink)]"
									>
										<Check size={12} className="text-[var(--success)] flex-shrink-0" />
										{f}
									</li>
								))}
							</ul>
							<p className="text-[10px] text-[var(--sea-ink-soft)] mt-3">
								Up to {plan.maxRepositories} repos · {plan.maxMembers} members
							</p>
							{!isCurrent && (
								<UpgradeButton
									targetPlanSlug={plan.slug}
									label="Upgrade"
								/>
							)}
						</div>
					);
				})}
			</div>
		</div>
	);
}

function InvoiceList({
	invoices }: {
	invoices: BillingInvoices | undefined;
}) {
	return (
		<div className="card">
			<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-3">
				Invoices
			</h3>
			{!invoices ? (
				<div className="space-y-2">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-10 rounded-lg" />
					))}
				</div>
			) : invoices.length === 0 ? (
				<p className="text-xs text-[var(--sea-ink-soft)]">
					No invoices yet. They will appear here once your first billing
					period completes.
				</p>
			) : (
				<div className="space-y-2">
					{invoices.map((inv: NonNullable<BillingInvoices>[number]) => {
						const tone =
							inv.status === "paid"
								? "success"
								: inv.status === "void"
									? "neutral"
									: "warning";
						return (
							<div
								key={inv._id}
								className="flex items-center justify-between rounded-lg bg-[var(--surface-soft)] px-3 py-2"
							>
								<div className="flex items-center gap-3">
									<div>
										<p className="text-xs font-medium text-[var(--sea-ink)]">
											{formatTimestamp(inv.periodStart)} –{" "}
											{formatTimestamp(inv.periodEnd)}
										</p>
										<p className="text-[10px] text-[var(--sea-ink-soft)]">
											Due {formatTimestamp(inv.dueDate)}
										</p>
									</div>
								</div>
								<div className="flex items-center gap-3">
									<span className="text-xs font-semibold text-[var(--sea-ink)]">
										${(inv.amountCents / 100).toFixed(2)} {inv.currency.toUpperCase()}
									</span>
									<StatusPill label={inv.status} tone={tone} />
									{inv.pdfUrl && (
										<a
											href={inv.pdfUrl}
											target="_blank"
											rel="noopener noreferrer"
											className="text-[var(--signal)] hover:opacity-80"
										>
											<Download size={14} />
										</a>
									)}
								</div>
							</div>
						);
					})}
				</div>
			)}
		</div>
	);
}
