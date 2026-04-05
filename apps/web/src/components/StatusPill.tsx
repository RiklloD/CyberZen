type Tone = "neutral" | "success" | "warning" | "danger" | "info";

const toneClassNames: Record<Tone, string> = {
	neutral:
		"border-[rgba(94,113,119,0.2)] bg-[rgba(94,113,119,0.08)] text-[var(--sea-ink-soft)]",
	success:
		"border-[rgba(91,212,158,0.24)] bg-[rgba(91,212,158,0.1)] text-[var(--success)]",
	warning:
		"border-[rgba(242,165,59,0.26)] bg-[rgba(242,165,59,0.12)] text-[var(--warning)]",
	danger:
		"border-[rgba(255,107,107,0.24)] bg-[rgba(255,107,107,0.11)] text-[var(--danger)]",
	info: "border-[rgba(101,214,210,0.24)] bg-[rgba(101,214,210,0.1)] text-[var(--teal)]",
};

export default function StatusPill({
	label,
	tone = "neutral",
}: {
	label: string;
	tone?: Tone;
}) {
	return (
		<span
			className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[0.68rem] font-semibold tracking-[0.14em] uppercase ${toneClassNames[tone]}`}
		>
			{label}
		</span>
	);
}
