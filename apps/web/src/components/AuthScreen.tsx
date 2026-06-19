import { SignInButton } from "@clerk/react";
import { Shield } from "lucide-react";

export default function AuthScreen() {
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

				<div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1.5rem" }}>
					<SignInButton mode="modal">
						<button type="button" className="auth-submit">
							Sign in
						</button>
					</SignInButton>
				</div>
			</div>
		</div>
	);
}
