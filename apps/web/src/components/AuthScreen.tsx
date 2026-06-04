import { useAuthActions } from "@convex-dev/auth/react";
import { useRouterState } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Shield, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/convex";

type AuthMode = "signIn" | "signUp";

function getInviteToken(search: string) {
	const params = new URLSearchParams(search);
	return params.get("invite");
}

export default function AuthScreen() {
	const { signIn } = useAuthActions();
	const routerState = useRouterState();
	const inviteToken = useMemo(
		() => getInviteToken(routerState.location.searchStr),
		[routerState.location.searchStr],
	);
	const [mode, setMode] = useState<AuthMode>("signIn");
	const [error, setError] = useState<string | null>(null);
	const [email, setEmail] = useState("");
	const recordAuthFailure = useMutation(api.authLockout.recordAuthFailure);
	const lockoutStatus = useQuery(
		api.authLockout.checkAuthLockout,
		email ? { email } : "skip",
	);

	// Strip invite token from URL immediately so it doesn't persist in browser history
	useEffect(() => {
		if (inviteToken) {
			const url = new URL(window.location.href);
			url.searchParams.delete("invite");
			window.history.replaceState(null, "", url.pathname + (url.search || ""));
		}
	}, []); // eslint-disable-line react-hooks/exhaustive-deps

	return (
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-card-header">
					<div className="auth-card-badge">
						<Shield size={18} />
					</div>
					<div>
						<p className="auth-card-eyebrow">CyberZen</p>
						<h1 className="auth-card-title">Sign in to your workspace</h1>
					</div>
				</div>

				<p className="auth-card-copy">
					Create or join a company workspace, invite teammates, and manage
					red-team automation from one place.
				</p>

			{inviteToken && (
					<div className="auth-invite-banner">
						<Sparkles size={16} />
						<span>
							Invite detected. After sign-in, you'll be added to the workspace
							automatically.
						</span>
					</div>
				)}

				<button
					type="button"
					className="auth-oauth-btn"
					onClick={() => void signIn("github")}
				>
					<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
						<path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
					</svg>
					Continue with GitHub
				</button>

				<div className="auth-divider">
					<span>or continue with email</span>
				</div>

				{lockoutStatus?.locked && lockoutStatus.lockedUntil && (
					<div className="auth-error">
						Too many failed attempts. Try again in{" "}
						{Math.ceil((lockoutStatus.lockedUntil - Date.now()) / 60_000)} minute
						{Math.ceil((lockoutStatus.lockedUntil - Date.now()) / 60_000) !== 1
							? "s"
							: ""}
						.
					</div>
				)}

				<form
					className="auth-form"
					onSubmit={async (event) => {
						event.preventDefault();
						setError(null);

						if (lockoutStatus?.locked) {
							setError("Too many failed attempts. Please wait before trying again.");
							return;
						}

						const formData = new FormData(event.currentTarget);
						const submittedEmail = (formData.get("email") as string) ?? "";
						try {
							await signIn("password", formData);
						} catch (thrown) {
							// Record failure for lockout tracking (best-effort)
							void recordAuthFailure({ email: submittedEmail }).catch(() => {});
							setError(
								thrown instanceof Error
									? thrown.message
									: "Could not complete sign-in.",
							);
						}
					}}
				>
					<label className="auth-field">
						<span>Email</span>
						<input
							name="email"
							type="email"
							autoComplete="email"
							required
							value={email}
							onChange={(e) => setEmail(e.target.value)}
						/>
					</label>

					<label className="auth-field">
						<span>Password</span>
						<input
							name="password"
							type="password"
							autoComplete={
								mode === "signIn" ? "current-password" : "new-password"
							}
							required
						/>
					</label>

					<input name="flow" type="hidden" value={mode} />

					<button type="submit" className="auth-submit">
						{mode === "signIn" ? "Sign in" : "Create account"}
					</button>
				</form>

				{error && <p className="auth-error">{error}</p>}

				<button
					type="button"
					className="auth-toggle"
					onClick={() => {
						setMode((current) => (current === "signIn" ? "signUp" : "signIn"));
					}}
				>
					{mode === "signIn"
						? "New here? Create an account"
						: "Already have an account? Sign in"}
				</button>
			</div>
		</div>
	);
}
