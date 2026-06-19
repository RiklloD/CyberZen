import { useMutation, useQuery } from "convex/react";
import { BarChart2, X } from "lucide-react";
import { api } from "../lib/convex";

export default function AnalyticsConsentBanner() {
	const consentRecord = useQuery(
		api.analyticsConsent.getMyConsent,
	);
	const updateConsent = useMutation(api.analyticsConsent.updateMyConsent);

	// Only show when consent has not been set (null = never asked)
	if (consentRecord === undefined || consentRecord !== null) return null;

	async function accept() {
		await updateConsent({ consent: true });
	}

	async function decline() {
		await updateConsent({ consent: false });
	}

	return (
		<div
			role="dialog"
			aria-label="Analytics consent"
			className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 w-full max-w-lg mx-auto px-4"
		>
			<div className="card flex items-start gap-3 shadow-lg border border-[var(--line)]">
				<div className="flex-shrink-0 mt-0.5 text-[var(--signal)]">
					<BarChart2 size={16} />
				</div>
				<div className="flex-1 min-w-0">
					<p className="text-xs font-semibold text-[var(--sea-ink)] mb-0.5">
						Help us improve CyberZen
					</p>
					<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed">
						We use analytics to understand feature usage and improve the product.
						No personal data is sold. You can change this at any time in{" "}
						<a
							href="/settings/data-privacy"
							className="underline text-[var(--signal)]"
						>
							Privacy Settings
						</a>
						.
					</p>
				</div>
				<div className="flex items-center gap-2 shrink-0 mt-0.5">
					<button
						type="button"
						className="signal-button text-xs py-1 px-3"
						onClick={accept}
					>
						Accept
					</button>
					<button
						type="button"
						className="text-xs px-3 py-1 rounded-lg border border-[var(--line)] text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)] transition-colors"
						onClick={decline}
					>
						Decline
					</button>
					<button
						type="button"
						className="text-[var(--sea-ink-dim)] hover:text-[var(--sea-ink)] transition-colors"
						onClick={decline}
						aria-label="Dismiss"
					>
						<X size={14} />
					</button>
				</div>
			</div>
		</div>
	);
}
