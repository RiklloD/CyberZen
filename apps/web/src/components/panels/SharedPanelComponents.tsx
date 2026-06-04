import type { ReactNode } from "react";

/**
 * PanelSkeleton — shared loading placeholder.
 * Renders animated `loading-panel` blocks matching the common panel pattern.
 *
 * Usage:
 *   <PanelSkeleton />               → single block
 *   <PanelSkeleton count={3} />     → three blocks in a grid
 *   <PanelSkeleton rows={5} />      → single block with inner row shimmer lines
 */
export function PanelSkeleton({
	count = 1,
	rows,
	className = "",
}: {
	count?: number;
	rows?: number;
	className?: string;
}) {
	return (
		<div className={`grid gap-3 sm:grid-cols-2 ${className}`}>
			{Array.from({ length: count }).map((_, i) => (
				<div key={i} className="loading-panel h-32 rounded-2xl">
					{rows && (
						<div className="p-4 space-y-2">
							{Array.from({ length: rows }).map((_, j) => (
								<div
									// biome-ignore lint/suspicious/noArrayIndexKey: skeleton rows have no identity
									key={j}
									className="h-3 rounded bg-[rgba(130,122,110,0.10)]"
									style={{ width: `${60 + Math.random() * 30}%` }}
								/>
							))}
						</div>
					)}
				</div>
			))}
		</div>
	);
}

/**
 * EmptyState — "no data yet" placeholder used across panels.
 *
 * Usage:
 *   <EmptyState icon={<Shield size={24} />} message="No disclosures found." />
 */
export function EmptyState({
	icon,
	message,
}: {
	icon?: ReactNode;
	message: string;
}) {
	return (
		<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl text-center py-8 px-4">
			{icon && <div className="mb-2 flex justify-center opacity-40">{icon}</div>}
			<p className="text-sm text-[var(--sea-ink-soft)]">{message}</p>
		</div>
	);
}

/**
 * PanelContainer — shared frame wrapper providing title, subtitle, and optional action slot.
 *
 * Usage:
 *   <PanelContainer title="EPSS Threat Intel" subtitle="Latest snapshot">
 *     {children}
 *   </PanelContainer>
 */
export function PanelContainer({
	title,
	subtitle,
	actions,
	children,
	className = "",
}: {
	title: string;
	subtitle?: string;
	actions?: ReactNode;
	children: ReactNode;
	className?: string;
}) {
	return (
		<div className={className}>
			<div className="section-header mb-3">
				<div>
					<h2 className="section-title">{title}</h2>
					{subtitle && (
						<p className="text-xs text-[var(--sea-ink-soft)]">{subtitle}</p>
					)}
				</div>
				{actions && <div className="flex gap-2">{actions}</div>}
			</div>
			{children}
		</div>
	);
}
