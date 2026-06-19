import { useMutation, useQuery } from "convex/react";
import { Save } from "lucide-react";
import { useState } from "react";
import { api } from "../../lib/convex";

type SeverityKey = "critical" | "high" | "medium" | "low";

const SEVERITIES: SeverityKey[] = ["critical", "high", "medium", "low"];

const DEFAULT_HOURS: Record<SeverityKey, number> = {
	critical: 24,
	high: 72,
	medium: 168,
	low: 720 };

interface SlaPolicyFormProps {
	tenantSlug: string;
}

export default function SlaPolicyForm({ tenantSlug }: SlaPolicyFormProps) {
	const policy = useQuery(api.slaIntel.getCurrentPolicy, { tenantSlug });
	const upsert = useMutation(api.slaIntel.upsertSlaPolicy);

	const [hours, setHours] = useState<Record<SeverityKey, number>>(
		() => ({ ...DEFAULT_HOURS }),
	);
	const [approachingThreshold, setApproachingThreshold] = useState(0.75);
	const [saving, setSaving] = useState(false);
	const [lastResult, setLastResult] = useState<"success" | "error" | null>(
		null,
	);

	// Sync server state into local form when policy loads
	if (policy && !saving && lastResult === null) {
		const serverHours = policy.thresholdHours;
		const serverApproaching = policy.approachingThreshold;
		const needsSync =
			serverHours.critical !== hours.critical ||
			serverHours.high !== hours.high ||
			serverHours.medium !== hours.medium ||
			serverHours.low !== hours.low ||
			serverApproaching !== approachingThreshold;
		if (needsSync) {
			setHours({
				critical: serverHours.critical,
				high: serverHours.high,
				medium: serverHours.medium,
				low: serverHours.low });
			setApproachingThreshold(serverApproaching);
		}
	}

	const handleSave = async () => {
		setSaving(true);
		setLastResult(null);
		try {
			await upsert({
				tenantSlug,
				thresholdHours: hours,
				approachingThreshold });
			setLastResult("success");
		} catch {
			setLastResult("error");
		} finally {
			setSaving(false);
			setTimeout(() => setLastResult(null), 3000);
		}
	};

	const toneClass =
		lastResult === "success"
			? "text-[var(--success)]"
			: lastResult === "error"
				? "text-[var(--danger)]"
				: "";

	return (
		<div className="card">
			<p className="panel-label mb-3">
				SLA Policy — hours to resolve per severity
			</p>

			{!policy && (
				<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
					No custom policy set — using platform defaults.
				</p>
			)}

			<div className="grid gap-3 sm:grid-cols-2">
				{SEVERITIES.map((sev) => (
					<div key={sev} className="card card-sm">
						<label
							htmlFor={`sla-${sev}`}
							className="text-sm font-semibold text-[var(--sea-ink)] capitalize"
						>
							{sev}
						</label>
						<div className="flex items-center gap-2 mt-1">
							<input
								id={`sla-${sev}`}
								type="number"
								min={1}
								max={8760}
								value={hours[sev]}
								onChange={(e) =>
									setHours((prev) => ({
										...prev,
										[sev]: Math.max(1, Number(e.target.value) || 1) }))
								}
								className="w-24 rounded-md border border-[var(--line)] bg-transparent px-2 py-1 text-sm font-mono text-[var(--sea-ink)] focus:outline-none focus:ring-1 focus:ring-[var(--signal)]"
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								hours
							</span>
						</div>
					</div>
				))}
			</div>

			<div className="card card-sm mt-3">
				<label
					htmlFor="sla-approaching"
					className="text-sm font-semibold text-[var(--sea-ink)]"
				>
					Approaching threshold
				</label>
				<div className="flex items-center gap-2 mt-1">
					<input
						id="sla-approaching"
						type="number"
						min={0}
						max={1}
						step={0.05}
						value={approachingThreshold}
						onChange={(e) =>
							setApproachingThreshold(
								Math.min(1, Math.max(0, Number(e.target.value) || 0)),
							)
						}
						className="w-24 rounded-md border border-[var(--line)] bg-transparent px-2 py-1 text-sm font-mono text-[var(--sea-ink)] focus:outline-none focus:ring-1 focus:ring-[var(--signal)]"
					/>
					<span className="text-xs text-[var(--sea-ink-soft)]">
						fraction (0–1) of SLA window before "approaching" status
					</span>
				</div>
			</div>

			<div className="flex items-center gap-3 mt-4">
				<button
					type="button"
					onClick={handleSave}
					disabled={saving}
					className="btn signal-button inline-flex items-center gap-1.5 disabled:opacity-50"
				>
					<Save size={14} />
					<span>{saving ? "Saving…" : "Save Policy"}</span>
				</button>
				{lastResult && (
					<span className={`text-xs font-medium ${toneClass}`}>
						{lastResult === "success"
							? "Policy saved"
							: "Save failed"}
					</span>
				)}
			</div>
		</div>
	);
}
