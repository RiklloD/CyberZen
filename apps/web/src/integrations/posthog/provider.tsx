import { PostHogProvider as BasePostHogProvider } from "@posthog/react";
import posthog from "posthog-js";
import type { ReactNode } from "react";
import { useEffect } from "react";
import { useQuery } from "convex/react";
import { useAuthToken } from "@convex-dev/auth/react";
import { env } from "#/env";
import { api } from "#/lib/convex";

interface PostHogProviderProps {
	children: ReactNode;
}

function PostHogInitializer() {
	const authToken = useAuthToken() ?? "";
	const consentRecord = useQuery(
		api.analyticsConsent.getMyConsent,
		authToken ? { authToken } : "skip",
	);

	useEffect(() => {
		if (!env.VITE_POSTHOG_KEY) return;
		if (consentRecord === undefined) return; // loading

		if (consentRecord?.consent === true) {
			if (!posthog.__loaded) {
				posthog.init(env.VITE_POSTHOG_KEY, {
					api_host: env.VITE_POSTHOG_HOST,
					person_profiles: "identified_only",
					capture_pageview: false,
					defaults: "2025-11-30",
				});
			}
		} else {
			// Opt out without unloading — prevents tracking when consent is withdrawn
			if (posthog.__loaded) {
				posthog.opt_out_capturing();
			}
		}
	}, [consentRecord]);

	return null;
}

export default function PostHogProvider({ children }: PostHogProviderProps) {
	if (!env.VITE_POSTHOG_KEY) {
		return <>{children}</>;
	}

	return (
		<BasePostHogProvider client={posthog}>
			<PostHogInitializer />
			{children}
		</BasePostHogProvider>
	);
}
