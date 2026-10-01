import type { ReactNode } from "react";

export default function Section({
	title,
	description,
	actions,
	children,
	className = "",
}: {
	title: ReactNode;
	description?: ReactNode;
	actions?: ReactNode;
	children: ReactNode;
	className?: string;
}) {
	return (
		<section className={`section ${className}`}>
			<div className="section-header">
				<div className="min-w-0">
					<h2 className="section-title">{title}</h2>
					{description && <p className="section-description">{description}</p>}
				</div>
				{actions && <div className="flex items-center gap-3">{actions}</div>}
			</div>
			{children}
		</section>
	);
}
