import type { ReactNode } from "react";

/**
 * Standard page header: title, one-line description, right-aligned actions,
 * and an optional slot below (tabs, filters) that spans the full width.
 */
export default function PageHeader({
	title,
	description,
	actions,
	children,
}: {
	title: ReactNode;
	description?: ReactNode;
	actions?: ReactNode;
	children?: ReactNode;
}) {
	return (
		<header className="page-header">
			<div className="page-header-row">
				<div className="min-w-0">
					<h1 className="page-title">{title}</h1>
					{description && <p className="page-subtitle">{description}</p>}
				</div>
				{actions && <div className="page-actions">{actions}</div>}
			</div>
			{children && <div className="mt-4">{children}</div>}
		</header>
	);
}
