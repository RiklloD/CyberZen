import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { attackSurfaceTone, trendTone } from "../../lib/utils";

type AttackSurface = NonNullable<
	FunctionReturnType<
		typeof api.attackSurfaceIntel.getAttackSurfaceDashboard
	>
>;

export default function RepositoryAttackSurfacePanel({
	attackSurface,
}: {
	attackSurface: AttackSurface;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label">Attack Surface</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`score ${attackSurface.snapshot.score}`}
					tone={attackSurfaceTone(attackSurface.snapshot.score)}
				/>
				<StatusPill
					label={attackSurface.snapshot.trend}
					tone={trendTone(attackSurface.snapshot.trend)}
				/>
				{attackSurface.snapshot.openCriticalCount > 0 && (
					<StatusPill
						label={`${attackSurface.snapshot.openCriticalCount} critical`}
						tone="danger"
					/>
				)}
			</div>
			{attackSurface.history.length > 1 && (
				<div className="mt-2 flex h-6 items-end gap-[2px]">
					{attackSurface.history.slice(-12).map((p: AttackSurface["history"][number], i: number) => (
						<div
							// biome-ignore lint/suspicious/noArrayIndexKey: history points have no stable id
							key={i}
							className="flex-1 rounded-sm bg-[var(--sea-ink-soft)]/25"
							style={{ height: `${Math.max(8, p.score)}%` }}
							title={`Score ${p.score}`}
						/>
					))}
				</div>
			)}
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{attackSurface.snapshot.summary}
			</p>
		</div>
	);
}
