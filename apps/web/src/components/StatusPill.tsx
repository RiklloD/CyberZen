import type { ReactNode } from "react";
import { humanize } from "../lib/format";

type Tone = "neutral" | "success" | "warning" | "danger" | "info";

/**
 * Small tinted badge. Labels are humanized (`version_unaffected` →
 * "Version unaffected") so call sites can pass raw enum values.
 */
export default function StatusPill({
	label,
	tone = "neutral",
	dot = false,
	children,
}: {
	label?: string;
	tone?: Tone;
	dot?: boolean;
	children?: ReactNode;
}) {
	const content =
		label !== undefined ? humanize(label) : typeof children === "string" ? humanize(children) : children;
	return (
		<span className="badge" data-tone={tone}>
			{dot && <span className="badge-dot" />}
			{content}
		</span>
	);
}
