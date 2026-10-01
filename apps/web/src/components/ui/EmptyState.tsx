import type { ComponentType, ReactNode } from "react";

export default function EmptyState({
	icon: Icon,
	title,
	description,
	actions,
	bordered = false,
}: {
	icon?: ComponentType<{ size?: number }>;
	title: ReactNode;
	description?: ReactNode;
	actions?: ReactNode;
	bordered?: boolean;
}) {
	return (
		<div
			className={`empty-state ${bordered ? "rounded-xl border border-dashed border-[var(--line-strong)]" : ""}`}
		>
			{Icon && (
				<span className="empty-state-icon">
					<Icon size={16} />
				</span>
			)}
			<p className="empty-state-title">{title}</p>
			{description && <p className="max-w-md">{description}</p>}
			{actions && <div className="empty-state-actions">{actions}</div>}
		</div>
	);
}
