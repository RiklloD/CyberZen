import { humanize } from "../../lib/format";

const LEVEL: Record<string, number> = {
	critical: 3,
	high: 3,
	medium: 2,
	low: 1,
	informational: 0,
};

/** Severity with a signal-strength glyph so it reads without colour too. */
export default function SeverityBadge({
	severity,
	compact = false,
}: {
	severity: string;
	compact?: boolean;
}) {
	const level = LEVEL[severity] ?? 0;
	const label = severity === "informational" ? "Info" : humanize(severity);
	return (
		<span className="sev" data-sev={severity} title={humanize(severity)}>
			<span className="sev-bars" aria-hidden="true">
				<i className={level >= 1 ? "on" : ""} />
				<i className={level >= 2 ? "on" : ""} />
				<i className={level >= 3 ? "on" : ""} />
			</span>
			{!compact && label}
		</span>
	);
}

export function SeverityDot({ severity }: { severity: string }) {
	return (
		<span
			data-sev={severity}
			className="inline-block h-2 w-2 shrink-0 rounded-full"
			style={{ background: "var(--sev)" }}
			aria-hidden="true"
		/>
	);
}
