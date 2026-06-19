import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type SecurityDebt = NonNullable<
	FunctionReturnType<typeof api.securityDebtIntel.getLatestSecurityDebtBySlug>
>;

export default function SecurityDebtPanel({
	data }: {
	data: SecurityDebt;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Security Debt</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`score ${data.debtScore}`}
					tone={
						data.debtScore > 70
							? "danger"
							: data.debtScore > 40
								? "warning"
								: "success"
					}
				/>
				<StatusPill label={data.trend} tone="neutral" />
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
