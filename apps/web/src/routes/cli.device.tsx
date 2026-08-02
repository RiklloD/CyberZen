import { useAuth, SignInButton } from "@clerk/react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { useMemo, useState } from "react";
import { api } from "../lib/convex";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/cli/device")({
	errorComponent: RouteErrorBoundary,
	component: CliDeviceAuthorizationPage,
});

function CliDeviceAuthorizationPage() {
	const { isLoaded, isSignedIn } = useAuth();
	const authorizeDevice = useMutation(api.cliDeviceAuth.authorizeDevice);
	const workspaces = useQuery(
		api.workspaceAuth.listWorkspaces,
		isSignedIn ? {} : "skip",
	);
	const code = useMemo(
		() => new URLSearchParams(window.location.search).get("code") ?? "",
		[],
	);
	const [tenantSlug, setTenantSlug] = useState("");
	const [message, setMessage] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);

	if (!isLoaded) return <DeviceShell><p>Loading authorization…</p></DeviceShell>;
	if (!isSignedIn) {
		return (
			<DeviceShell>
				<h1>Authorize CyberZen CLI</h1>
				<p>Sign in to authorize this CLI session.</p>
				<SignInButton mode="modal">
					<button type="button" className="auth-submit">Sign in</button>
				</SignInButton>
			</DeviceShell>
		);
	}

	const choices = (workspaces ?? []) as Array<{ slug: string; name: string }>;
	const authorize = async () => {
		if (!code || !tenantSlug) {
			setMessage("Choose a workspace before authorizing.");
			return;
		}
		setSubmitting(true);
		setMessage(null);
		try {
			await authorizeDevice({ userCode: code, tenantSlug });
			setMessage("CLI authorized. You can return to your terminal.");
		} catch (error) {
			setMessage(error instanceof Error ? error.message : "Authorization failed.");
		} finally {
			setSubmitting(false);
		}
	};

	return (
		<DeviceShell>
			<h1>Authorize CyberZen CLI</h1>
			<p>Choose the workspace this terminal may access.</p>
			<div style={{ display: "grid", gap: "0.75rem", margin: "1.5rem 0" }}>
				<label htmlFor="workspace">Workspace</label>
				<select
					id="workspace"
					value={tenantSlug}
					onChange={(event) => setTenantSlug(event.target.value)}
				>
					<option value="">Select a workspace</option>
					{choices.map((workspace) => (
						<option key={workspace.slug} value={workspace.slug}>
							{workspace.name} ({workspace.slug})
						</option>
					))}
				</select>
			</div>
			<button type="button" className="auth-submit" disabled={submitting || !code} onClick={authorize}>
				{submitting ? "Authorizing…" : "Authorize CLI"}
			</button>
			{message && <p role="status" style={{ marginTop: "1rem" }}>{message}</p>}
			{!code && <p role="alert">This authorization link is missing its device code.</p>}
		</DeviceShell>
	);
}

function DeviceShell({ children }: { children: React.ReactNode }) {
	return (
		<div className="auth-screen">
			<div className="auth-card">{children}</div>
		</div>
	);
}
