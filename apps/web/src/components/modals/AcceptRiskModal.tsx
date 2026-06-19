import { useState, useTransition } from "react";
import { useMutation } from "convex/react";
import { ShieldCheck } from "lucide-react";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import { track } from "../../lib/analytics";

interface AcceptRiskModalProps {
	findingId: Id<"findings">;
	open: boolean;
	onClose: () => void;
}

export default function AcceptRiskModal({
	findingId,
	open,
	onClose }: AcceptRiskModalProps) {
	const [justification, setJustification] = useState("");
	const [approver, setApprover] = useState("");
	const [durationDays, setDurationDays] = useState("");
	const [isPending, startTransition] = useTransition();

	const createAcceptance = useMutation(
		api.riskAcceptanceIntel.createRiskAcceptance,
	);

	if (!open) return null;

	function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!justification.trim() || !approver.trim()) return;

		startTransition(async () => {
			await createAcceptance({
				findingId,
				justification: justification.trim(),
				approver: approver.trim(),
				durationDays: durationDays ? Number(durationDays) : undefined });
			track("finding.accepted_risk", {
				findingId,
				justification: justification.trim(),
				expiryDays: durationDays ? Number(durationDays) : undefined });
			setJustification("");
			setApprover("");
			setDurationDays("");
			onClose();
		});
	}

	function handleBackdropClick(e: React.MouseEvent) {
		if (e.target === e.currentTarget) onClose();
	}

	return (
		<div
			onClick={handleBackdropClick}
			style={{
				position: "fixed",
				inset: 0,
				zIndex: 50,
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				background: "rgba(0, 0, 0, 0.44)",
				backdropFilter: "blur(2px)" }}
		>
			<div
				className="card"
				style={{
					width: "min(480px, 92vw)",
					maxHeight: "90vh",
					overflowY: "auto" }}
			>
				<div className="flex items-center gap-2 mb-4">
					<ShieldCheck
						size={18}
						className="text-[var(--signal)]"
					/>
					<h2 className="text-sm font-bold text-[var(--sea-ink)]">
						Accept Risk
					</h2>
				</div>

				<form onSubmit={handleSubmit} className="space-y-4">
					{/* Justification */}
					<div>
						<label
							htmlFor="ra-justification"
							className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
						>
							Justification *
						</label>
						<textarea
							id="ra-justification"
							value={justification}
							onChange={(e) => setJustification(e.target.value)}
							rows={3}
							required
							placeholder="Why is this risk acceptable?"
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] resize-none"
						/>
					</div>

					{/* Approver */}
					<div>
						<label
							htmlFor="ra-approver"
							className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
						>
							Approver *
						</label>
						<input
							id="ra-approver"
							type="text"
							value={approver}
							onChange={(e) => setApprover(e.target.value)}
							required
							placeholder="e.g. security-team@example.com"
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						/>
					</div>

					{/* Duration */}
					<div>
						<label
							htmlFor="ra-duration"
							className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
						>
							Duration (days)
						</label>
						<input
							id="ra-duration"
							type="number"
							min={1}
							value={durationDays}
							onChange={(e) => setDurationDays(e.target.value)}
							placeholder="Leave empty for permanent"
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						/>
						<p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
							Omit for a permanent acceptance, or enter a number
							of days for a temporary one.
						</p>
					</div>

					{/* Actions */}
					<div className="flex justify-end gap-2 pt-2">
						<button
							type="button"
							onClick={onClose}
							disabled={isPending}
							className="signal-button secondary-button"
							style={{
								padding: "0.5rem 0.9rem",
								fontSize: "0.78rem" }}
						>
							Cancel
						</button>
						<button
							type="submit"
							disabled={isPending}
							className="signal-button"
							style={{
								padding: "0.5rem 0.9rem",
								fontSize: "0.78rem" }}
						>
							{isPending ? "Accepting…" : "Accept Risk"}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}
