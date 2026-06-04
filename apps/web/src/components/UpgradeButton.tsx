import { useAction } from "convex/react";
import { ArrowUpRight } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

interface UpgradeButtonProps {
	targetPlanSlug: string;
	label?: string;
	className?: string;
}

export default function UpgradeButton({
	targetPlanSlug,
	label,
	className,
}: UpgradeButtonProps) {
	const TENANT = useTenantSlug();
	const createCheckoutSession = useAction(api.checkout.createCheckoutSession);
	const [pending, setPending] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function handleClick() {
		setPending(true);
		setError(null);
		try {
			const result = await createCheckoutSession({
				tenantSlug: TENANT,
				planSlug: targetPlanSlug,
			});
			if (result.url) {
				window.location.href = result.url;
				return;
			}
			setError("No checkout URL returned");
		} catch (err) {
			setError(err instanceof Error ? err.message : "Checkout failed");
		} finally {
			setPending(false);
		}
	}

	return (
		<div className="inline-flex flex-col items-end gap-1">
			<button
				type="button"
				onClick={handleClick}
				disabled={pending}
				className={
					className ??
					"signal-button inline-flex items-center gap-1"
				}
				style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
			>
				<ArrowUpRight size={12} />
				{pending ? "Redirecting…" : (label ?? "Upgrade")}
			</button>
			{error && (
				<p className="text-[10px] text-[var(--danger)]">{error}</p>
			)}
		</div>
	);
}
