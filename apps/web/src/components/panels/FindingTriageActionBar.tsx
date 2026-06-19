import { useState, useTransition } from "react";
import { useAuthToken } from "../../lib/clerk-compat";
import { useMutation } from "convex/react";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import { track } from "../../lib/analytics";
import SnoozeFindingModal from "../modals/SnoozeFindingModal";

export default function FindingTriageActionBar({
	findingId,
}: {
	findingId: Id<"findings">;
}) {
	const triageMutation = useMutation(api.findingTriage.markFalsePositive);
	const [isPending, startTransition] = useTransition();
	const [showSnoozeModal, setShowSnoozeModal] = useState(false);
	const authToken = useAuthToken() ?? ""; // FIX: C1 — auth token for tenant verification

	function handleFalsePositive() {
		startTransition(() => {
			void triageMutation({
				findingId,
				authToken, // FIX: C1 — pass auth token
				note: "Marked false positive via operator dashboard",
			}).then(() => {
				track("finding.triaged", {
					severity: "unknown",
					action: "false_positive",
					findingId,
				});
			});
		});
	}

	return (
		<div>
			<p className="panel-label mb-2">Triage</p>
			<div className="space-y-2">
				<div className="mt-3 flex flex-wrap gap-2">
					<button
						type="button"
						onClick={handleFalsePositive}
						disabled={isPending}
						className="signal-button secondary-button"
						style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
					>
						Mark false positive
					</button>
					<button
						type="button"
						onClick={() => setShowSnoozeModal(true)}
						disabled={isPending}
						className="signal-button secondary-button"
						style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
					>
						Snooze
					</button>
				</div>
			</div>

			{showSnoozeModal && (
				<SnoozeFindingModal
					findingId={findingId}
					onClose={() => setShowSnoozeModal(false)}
				/>
			)}
		</div>
	);
}
