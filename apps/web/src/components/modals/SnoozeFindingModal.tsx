import { useState, useTransition } from "react";
import { useMutation } from "convex/react";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";

type SnoozeDuration = 1 | 7 | 30;

const DURATION_OPTIONS: { value: SnoozeDuration; label: string }[] = [
	{ value: 1, label: "1 day" },
	{ value: 7, label: "7 days" },
	{ value: 30, label: "30 days" },
];

interface SnoozeFindingModalProps {
	findingId: Id<"findings">;
	onClose: () => void;
}

export default function SnoozeFindingModal({
	findingId,
	onClose }: SnoozeFindingModalProps) {
	const snoozeMutation = useMutation(api.findingTriage.snoozeFinding);
	const [isPending, startTransition] = useTransition();

	const [duration, setDuration] = useState<SnoozeDuration>(7);
	const [reason, setReason] = useState("");

	function handleSubmit() {
		startTransition(() => {
			void snoozeMutation({
				findingId, // FIX: C1 — pass auth token
				durationDays: duration,
				reason: reason.trim() || undefined }).then(() => {
				onClose();
			});
		});
	}

	return (
		<div
			style={{
				position: "fixed",
				inset: 0,
				zIndex: 50,
				display: "flex",
				alignItems: "center",
				justifyContent: "center" }}
		>
			{/* Dark overlay */}
			<div
				onClick={onClose}
				style={{
					position: "fixed",
					inset: 0,
					background: "rgba(0, 0, 0, 0.44)",
					backdropFilter: "blur(2px)" }}
			/>

			{/* Modal card */}
			<div className="card" style={{ padding: "1.5rem", maxWidth: "420px", width: "100%", zIndex: 51, position: "relative" }}>
				<h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>
					Snooze Finding
				</h3>

				<div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
					{/* Duration picker */}
					<div>
						<label
							htmlFor="snooze-duration"
							className="panel-label"
							style={{ display: "block", marginBottom: "0.375rem" }}
						>
							Duration
						</label>
						<select
							id="snooze-duration"
							value={duration}
							onChange={(e) => setDuration(Number(e.target.value) as SnoozeDuration)}
							style={{
								width: "100%",
								padding: "0.5rem 0.75rem",
								borderRadius: "0.5rem",
								border: "1px solid var(--line)",
								background: "var(--chip-bg)",
								color: "var(--sea-ink)",
								fontSize: "0.85rem" }}
						>
							{DURATION_OPTIONS.map((opt) => (
								<option key={opt.value} value={opt.value}>
									{opt.label}
								</option>
							))}
						</select>
					</div>

					{/* Reason textarea */}
					<div>
						<label
							htmlFor="snooze-reason"
							className="panel-label"
							style={{ display: "block", marginBottom: "0.375rem" }}
						>
							Reason (optional)
						</label>
						<textarea
							id="snooze-reason"
							value={reason}
							onChange={(e) => setReason(e.target.value)}
							placeholder="Why are you snoozing this finding?"
							rows={3}
							style={{
								width: "100%",
								padding: "0.5rem 0.75rem",
								borderRadius: "0.5rem",
								border: "1px solid var(--line)",
								background: "var(--chip-bg)",
								color: "var(--sea-ink)",
								fontSize: "0.85rem",
								resize: "vertical",
								fontFamily: "inherit" }}
						/>
					</div>

					{/* Actions */}
					<div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end" }}>
						<button
							type="button"
							onClick={onClose}
							disabled={isPending}
							className="signal-button secondary-button"
							style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
						>
							Cancel
						</button>
						<button
							type="button"
							onClick={handleSubmit}
							disabled={isPending}
							className="signal-button"
							style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
						>
							{isPending ? "Snoozing…" : "Snooze"}
						</button>
					</div>
				</div>
			</div>
		</div>
	);
}
