import { useTransition } from "react";
import { useMutation, useQuery } from "convex/react";
import { ShieldOff } from "lucide-react";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import StatusPill from "../StatusPill";
import type { FunctionReturnType } from "convex/server";

type RiskAcceptanceSummary = NonNullable<
	FunctionReturnType<
		typeof api.riskAcceptanceIntel.getAcceptanceSummaryForRepository
	>
>;

export default function RepositoryRiskAcceptancePanel({
	riskAcceptance,
	repositoryId,
}: {
	riskAcceptance: RiskAcceptanceSummary;
	repositoryId?: Id<"repositories">;
}) {
	const [isPending, startTransition] = useTransition();
	const revokeMutation = useMutation(
		api.riskAcceptanceIntel.revokeRiskAcceptance,
	);

	// Fetch individual records so we can show revoke buttons
	const records = useQuery(
		api.riskAcceptanceIntel.getRiskAcceptancesForRepository,
		repositoryId ? { repositoryId } : "skip",
	);

	const activeRecords = records?.filter((r: NonNullable<typeof records>[number]) => r.status === "active") ?? [];

	function handleRevoke(findingId: Id<"findings">) {
		startTransition(async () => {
			await revokeMutation({
				findingId,
				revokedBy: "operator",
			});
		});
	}

	return (
		<div className="card card-sm">
			<p className="panel-label">Risk Acceptances</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`${riskAcceptance.totalActive} active`}
					tone="neutral"
				/>
				{riskAcceptance.expiringSoon > 0 && (
					<StatusPill
						label={`${riskAcceptance.expiringSoon} expiring soon`}
						tone="warning"
					/>
				)}
				{riskAcceptance.permanent > 0 && (
					<StatusPill
						label={`${riskAcceptance.permanent} permanent`}
						tone="neutral"
					/>
				)}
			</div>

			{/* Individual acceptances with revoke */}
			{activeRecords.length > 0 && (
				<div className="mt-3 space-y-2">
					{activeRecords.slice(0, 10).map((record: NonNullable<typeof records>[number]) => (
						<div
							key={record._id}
							className="flex items-center justify-between gap-2 rounded-lg border border-[var(--line)] px-3 py-2"
						>
							<div className="min-w-0 flex-1">
								<div className="text-xs font-semibold text-[var(--sea-ink)] truncate">
									{record.justification}
								</div>
								<div className="flex flex-wrap gap-1.5 mt-1">
									<StatusPill
										label={record.level}
										tone="neutral"
									/>
									<span className="text-[10px] text-[var(--sea-ink-soft)]">
										by {record.approver}
									</span>
									{record.expiresAt && (
										<span className="text-[10px] text-[var(--sea-ink-soft)]">
											expires{" "}
											{new Date(
												record.expiresAt,
											).toLocaleDateString()}
										</span>
									)}
								</div>
							</div>
							<button
								type="button"
								onClick={() =>
									handleRevoke(
										record.findingId as Id<"findings">,
									)
								}
								disabled={isPending}
								title="Revoke acceptance"
								className="signal-button secondary-button shrink-0"
								style={{
									padding: "0.35rem 0.65rem",
									fontSize: "0.7rem",
								}}
							>
								<ShieldOff size={12} />
								Revoke
							</button>
						</div>
					))}
				</div>
			)}
		</div>
	);
}
