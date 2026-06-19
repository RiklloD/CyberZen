import { ClerkProvider, useAuth, SignInButton, UserButton, SignedIn, SignedOut } from "@clerk/tanstack-react-start";
import { TanStackDevtools } from "@tanstack/react-devtools";
import {
	createRootRoute,
	Navigate,
	Outlet,
	useLocation,
	useNavigate,
} from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import { useMutation, useQuery } from "convex/react";
import { useEffect, useState } from "react";
import AnalyticsConsentBanner from "../components/AnalyticsConsentBanner";
import CommandPalette from "../components/CommandPalette";
import RouteErrorBoundary from "../components/RouteErrorBoundary";
import ShortcutsModal from "../components/ShortcutsModal";
import Sidebar from "../components/Sidebar";
import Toaster from "../components/Toaster";
import { env } from "../env";
import ConvexProvider from "../integrations/convex/provider";
import PostHogProvider from "../integrations/posthog/provider";
import { api } from "../lib/convex";
import {
	attachGlobalShortcutListener,
	registerNavigationShortcuts,
} from "../lib/shortcuts";
import { WorkspaceSlugProvider } from "../lib/workspace";

export const Route = createRootRoute({
	component: RootDocument,
	errorComponent: RouteErrorBoundary,
	head: () => ({
		meta: [
			{ title: "CyberZen — AI-Powered Security Posture Platform" },
			{
				name: "description",
				content:
					"Continuous security posture management with 40+ drift detectors, exploit validation, SBOM tracking, and AI-powered remediation.",
			},
			{
				name: "og:title",
				content: "CyberZen — AI-Powered Security Posture Platform",
			},
			{
				name: "og:description",
				content:
					"From code to cloud: automated vulnerability detection, compliance evidence, and security maturity scoring.",
			},
			{ name: "og:type", content: "website" },
			{ name: "twitter:card", content: "summary_large_image" },
		],
		links: [
			{ rel: "icon", href: "/favicon.ico" },
			{ rel: "apple-touch-icon", href: "/logo192.png" },
			{ rel: "manifest", href: "/manifest.json" },
		],
	}),
});

const PUBLIC_ROUTES = new Set<string>(["/about", "/sign-in", "/sign-up"]);

function RootDocument() {
	return (
		<ClerkProvider>
			<ConvexProvider>
				<AuthBoundary />
			</ConvexProvider>
		</ClerkProvider>
	);
}

function AuthBoundary() {
	const { isSignedIn, isLoaded } = useAuth();
	const location = useLocation();

	const isPublicRoute = PUBLIC_ROUTES.has(location.pathname) || location.pathname.startsWith("/sign-in") || location.pathname.startsWith("/sign-up");

	if (isPublicRoute) {
		return <PublicShell />;
	}

	if (!isLoaded) {
		return <LoadingShell />;
	}

	if (!isSignedIn) {
		return <UnauthenticatedShell />;
	}

	return <RootGate />;
}

function UnauthenticatedShell() {
	return (
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-card-header">
					<div className="auth-card-badge" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: "3rem", height: "3rem", borderRadius: "50%", background: "rgba(59,130,246,0.15)", marginBottom: "1rem" }}>
						<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
							<rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
							<path d="M7 11V7a5 5 0 0110 0v4" />
						</svg>
					</div>
					<p className="auth-card-eyebrow">CyberZen</p>
					<h1 className="auth-card-title">Sign in to your workspace</h1>
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
					<SignUpButton mode="modal">
						<button type="button" className="auth-submit" style={{ background: "transparent", border: "1px solid var(--border, #30363d)", color: "var(--sea-ink, #e6edf3)" }}>
							Create account
						</button>
					</SignUpButton>
				</div>
			</div>
		</div>
	);
}

function PublicShell() {
	return (
		<div className="app-shell-public">
			<div className="app-content">
				<RouteErrorBoundary>
					<Outlet />
				</RouteErrorBoundary>
			</div>
		</div>
	);
}

function RootGate() {
	const navigate = useNavigate();
	const location = useLocation();
	const workspace = useQuery(api.workspaceAuth.currentWorkspace);
	const [processedInviteToken, setProcessedInviteToken] = useState<
		string | null
	>(null);
	const [shortcutsOpen, setShortcutsOpen] = useState(false);

	// Capture invite token once from URL, then immediately strip it so the
	// token never appears in browser history or referrer headers.
	const [inviteToken] = useState<string | null>(() => {
		if (typeof window === "undefined") return null;
		return new URLSearchParams(window.location.search).get("invite");
	});

	useEffect(() => {
		if (inviteToken) {
			const url = new URL(window.location.href);
			url.searchParams.delete("invite");
			window.history.replaceState(null, "", url.pathname + (url.search || ""));
		}
	}, []); // eslint-disable-line react-hooks/exhaustive-deps

	// Register navigation shortcuts + global listener (once).
	// Must run unconditionally so the hook order stays stable across renders —
	// the early returns below would otherwise cause React error #310.
	useEffect(() => {
		attachGlobalShortcutListener();

		// Register "?" to open shortcuts modal
		const handleQuestionMark = (e: KeyboardEvent) => {
			const tag = (e.target as HTMLElement)?.tagName;
			if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
			if (e.key === "?") {
				e.preventDefault();
				setShortcutsOpen((prev) => !prev);
			}
		};
		document.addEventListener("keydown", handleQuestionMark);
		const unsub = registerNavigationShortcuts(
			(to) => void navigate({ to: to as "/" }),
		);
		return () => {
			document.removeEventListener("keydown", handleQuestionMark);
			unsub();
		};
	}, [navigate]);

	if (workspace === undefined) {
		return <LoadingShell />;
	}

	if (!workspace && inviteToken) {
		if (processedInviteToken === inviteToken) {
			return <LoadingShell />;
		}

		return (
			<InviteBootstrap
				inviteToken={inviteToken}
				onComplete={() => {
					setProcessedInviteToken(inviteToken);
				}}
				isProcessed={processedInviteToken === inviteToken}
			/>
		);
	}

	if (!workspace && location.pathname !== "/onboarding") {
		return <Navigate to="/onboarding" />;
	}

	return (
		<WorkspaceSlugProvider
			slug={workspace?.tenant.slug ?? env.VITE_TENANT_SLUG}
		>
			<PostHogProvider>
				<InviteBootstrap
					inviteToken={inviteToken}
					isProcessed={processedInviteToken === inviteToken}
					onComplete={() => {
						if (inviteToken) {
							setProcessedInviteToken(inviteToken);
						}
					}}
				/>
				<div className="app-shell">
					<Sidebar />
					<div className="app-content">
						<RouteErrorBoundary>
							<Outlet />
						</RouteErrorBoundary>
					</div>
				</div>
				<TanStackDevtools
					config={{ position: "bottom-right" }}
					plugins={[
						{
							name: "Tanstack Router",
							render: <TanStackRouterDevtoolsPanel />,
						},
					]}
				/>
				<AnalyticsConsentBanner />
				<CommandPalette />
				<Toaster />
				<ShortcutsModal
					open={shortcutsOpen}
					onClose={() => setShortcutsOpen(false)}
				/>
			</PostHogProvider>
		</WorkspaceSlugProvider>
	);
}

function LoadingShell() {
	return (
		<div className="auth-screen">
			<div className="auth-card">
				<p className="auth-card-eyebrow">CyberZen</p>
				<h1 className="auth-card-title">Loading workspace</h1>
				<p className="auth-card-copy">
					We are checking your authentication session and workspace membership.
				</p>
			</div>
		</div>
	);
}

function InviteBootstrap({
	inviteToken,
	isProcessed,
	onComplete,
}: {
	inviteToken: string | null;
	isProcessed: boolean;
	onComplete: () => void;
}) {
	const acceptInvite = useMutation(api.workspaceAuth.acceptWorkspaceInvite);
	const [status, setStatus] = useState<"idle" | "joining" | "done" | "error">(
		"idle",
	);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		if (!inviteToken || status !== "idle" || isProcessed) {
			return;
		}

		setStatus("joining");
		setError(null);
		void acceptInvite({ token: inviteToken })
			.then(() => {
				onComplete();
				setStatus("done");
			})
			.catch((thrown: unknown) => {
				setStatus("error");
				setError(
					thrown instanceof Error
						? thrown.message
						: "Could not accept the workspace invite.",
				);
			});
	}, [acceptInvite, inviteToken, isProcessed, onComplete, status]);

	if (!inviteToken || status === "done" || isProcessed) {
		return null;
	}

	return (
		<div className="invite-join-shell">
			<div className="auth-card invite-join-card">
				<p className="auth-card-eyebrow">Workspace invite</p>
				<h2 className="auth-card-title">Joining workspace</h2>
				<p className="auth-card-copy">
					We are attaching this account to the invited workspace now.
				</p>
				{status === "error" && <p className="auth-error">{error}</p>}
			</div>
		</div>
	);
}
