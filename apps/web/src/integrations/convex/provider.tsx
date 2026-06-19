import { useAuth } from "@clerk/tanstack-react-start";
import { ConvexProviderWithClerk } from "convex/react-clerk";
import { ConvexReactClient } from "convex/react";
import { type ReactNode, useEffect } from "react";
import { env } from "#/env";

const convexClient = env.VITE_CONVEX_URL
	? new ConvexReactClient(env.VITE_CONVEX_URL)
	: null;

function ConvexMissingPage() {
	return (
		<div
			style={{
				display: "flex",
				minHeight: "100vh",
				alignItems: "center",
				justifyContent: "center",
				background: "var(--page-bg, #0d1117)",
				padding: "2rem",
			}}
		>
			<div
				style={{
					maxWidth: "480px",
					width: "100%",
					background: "var(--panel-bg, #161b22)",
					border: "1px solid var(--border, #30363d)",
					borderRadius: "1rem",
					padding: "2.5rem",
					textAlign: "center",
				}}
			>
				<div
					style={{
						display: "inline-flex",
						alignItems: "center",
						justifyContent: "center",
						width: "3rem",
						height: "3rem",
						borderRadius: "50%",
						background: "rgba(239,68,68,0.15)",
						marginBottom: "1.25rem",
					}}
				>
					<svg
						width="22"
						height="22"
						viewBox="0 0 24 24"
						fill="none"
						stroke="#ef4444"
						strokeWidth="2"
						strokeLinecap="round"
						strokeLinejoin="round"
					>
						<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
						<line x1="12" y1="9" x2="12" y2="13" />
						<line x1="12" y1="17" x2="12.01" y2="17" />
					</svg>
				</div>
				<h1
					style={{
						fontSize: "1.125rem",
						fontWeight: 600,
						color: "var(--sea-ink, #e6edf3)",
						margin: "0 0 0.5rem",
					}}
				>
					CyberZen is not configured
				</h1>
				<p
					style={{
						fontSize: "0.875rem",
						color: "var(--sea-ink-soft, #8b949e)",
						margin: "0 0 1.25rem",
						lineHeight: 1.6,
					}}
				>
					<code
						style={{
							background: "rgba(239,68,68,0.12)",
							color: "#ef4444",
							borderRadius: "0.25rem",
							padding: "0.125rem 0.375rem",
							fontSize: "0.8rem",
						}}
					>
						VITE_CONVEX_URL
					</code>{" "}
					is missing. Contact your administrator to set this environment variable.
				</p>
				<p
					style={{
						fontSize: "0.75rem",
						color: "var(--sea-ink-soft, #8b949e)",
						margin: 0,
						opacity: 0.6,
					}}
				>
					This value is required to connect to the CyberZen backend.
				</p>
			</div>
		</div>
	);
}

export default function AppConvexProvider({
	children,
}: {
	children: ReactNode;
}) {
	useEffect(() => {
		if (import.meta.env.DEV) {
			(window as Window & { __convexClient?: ConvexReactClient }).__convexClient =
				convexClient ?? undefined;
		}
	}, []);

	if (!convexClient) {
		return <ConvexMissingPage />;
	}

	return (
		<ConvexProviderWithClerk client={convexClient} useAuth={useAuth}>
			{children}
		</ConvexProviderWithClerk>
	);
}
