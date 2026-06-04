import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "@convex-dev/auth/react";
import { useMutation, useQuery } from "convex/react";
import { ShieldCheck, Smartphone, Key, AlertTriangle, X } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/two-factor")({
	errorComponent: RouteErrorBoundary,
	component: TwoFactorPage,
});

function TwoFactorPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";

	const status = useQuery(
		api.twoFactor.getTwoFactorStatus,
		authToken ? { authToken } : "skip",
	);

	const tenantPolicy = useQuery(
		api.twoFactor.getTenantTwoFactorPolicy,
		authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<ShieldCheck size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Two-Factor Authentication</h1>
						<p className="page-subtitle">
							Manage TOTP-based two-factor authentication for your account
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Current Status */}
				{!status ? (
					<div className="loading-panel h-32 rounded-2xl" />
				) : (
					<StatusSection status={status} authToken={authToken} tenantSlug={TENANT} />
				)}

				{/* Tenant-wide 2FA Policy */}
				{tenantPolicy && (
					<div className="mt-6">
						<div className="section-header mb-3">
							<h2 className="section-title">Organization 2FA Policy</h2>
						</div>
						<div className="grid grid-cols-2 md:grid-cols-4 gap-3">
							<PolicyCard
								label="Total Members"
								value={tenantPolicy.totalMembers}
							/>
							<PolicyCard
								label="Enrolled"
								value={tenantPolicy.enrolledMembers}
								tone="success"
							/>
							<PolicyCard
								label="Not Enrolled"
								value={tenantPolicy.unenrolledMembers}
								tone={tenantPolicy.unenrolledMembers > 0 ? "warning" : "success"}
							/>
							<PolicyCard
								label="Enforcement"
								value={tenantPolicy.enforcementEnabled ? "On" : "Off"}
								tone={tenantPolicy.enforcementEnabled ? "success" : "neutral"}
							/>
						</div>

						{tenantPolicy.unenrolledMembers > 0 && (
							<div className="mt-3 p-3 rounded-lg bg-[var(--warning)]/10 border border-[var(--warning)]/30 flex items-start gap-3">
								<AlertTriangle size={16} className="text-[var(--warning)] flex-shrink-0 mt-0.5" />
								<p className="text-sm text-[var(--warning)]">
									{tenantPolicy.unenrolledMembers} member{tenantPolicy.unenrolledMembers !== 1 ? "s" : ""} {" "}
									have not enrolled in 2FA. Consider enabling enforcement for enhanced security.
								</p>
							</div>
						)}
					</div>
				)}

				{/* How it Works */}
				<div className="mt-6">
					<div className="section-header mb-3">
						<h2 className="section-title">How TOTP 2FA Works</h2>
					</div>
					<div className="grid grid-cols-1 md:grid-cols-3 gap-3">
						<StepCard step={1} title="Scan QR Code" description="Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)" />
						<StepCard step={2} title="Enter Code" description="Enter the 6-digit verification code from your authenticator app to confirm setup" />
						<StepCard step={3} title="Save Backup Codes" description="Store your backup codes in a safe place. They can be used if you lose your device" />
					</div>
				</div>
			</div>
		</main>
	);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatusSection({
	status,
	authToken,
	tenantSlug,
}: {
	status: any;
	authToken: string;
	tenantSlug: string;
}) {
	const [enrolling, setEnrolling] = useState(false);
	const [disabling, setDisabling] = useState(false);

	if (enrolling) {
		return <EnrollmentFlow authToken={authToken} tenantSlug={tenantSlug} onCancel={() => setEnrolling(false)} />;
	}

	if (disabling) {
		return <DisableFlow authToken={authToken} onCancel={() => setDisabling(false)} />;
	}

	return (
		<div className="card p-6">
			<div className="flex items-center justify-between gap-4">
				<div className="flex items-center gap-4">
					<div className="w-12 h-12 rounded-full bg-[var(--signal)]/10 flex items-center justify-center">
						<ShieldCheck size={24} className="text-[var(--signal)]" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<p className="text-lg font-semibold text-[var(--sea-ink)]">
								Two-Factor Authentication
							</p>
							{status.enrolled && status.verified ? (
								<StatusPill label="enabled" tone="success" />
							) : status.enrolled && !status.verified ? (
								<StatusPill label="pending verification" tone="warning" />
							) : (
								<StatusPill label="disabled" tone="danger" />
							)}
						</div> {/* FIX: C6 — mismatched tag was </p>, should be </div> */}
						<p className="text-sm text-[var(--sea-ink-soft)]">
							{status.enrolled && status.verified
								? `Enabled since ${new Date(status.enrolledAt).toLocaleDateString()}`
								: "Add an extra layer of security to your account"}
						</p>
					</div>
				</div>

				{!status.enrolled ? (
					<button
						type="button"
						onClick={() => setEnrolling(true)}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						<Smartphone size={14} className="mr-1.5" />
						Enable 2FA
					</button>
				) : status.enrolled && !status.verified ? (
					<button
						type="button"
						onClick={() => setEnrolling(true)}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						Complete Setup
					</button>
				) : (
					<button
						type="button"
						onClick={() => setDisabling(true)}
						className="secondary-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						Disable 2FA
					</button>
				)}
			</div>
		</div>
	);
}

function EnrollmentFlow({
	authToken,
	tenantSlug,
	onCancel,
}: {
	authToken: string;
	tenantSlug: string;
	onCancel: () => void;
}) {
	const [step, setStep] = useState<"start" | "verify">("start");
	const [code, setCode] = useState("");
	const [enrollmentData, setEnrollmentData] = useState<any>(null);
	const [isPending, startTransition] = useTransition();

	const startEnrollment = useMutation(api.twoFactor.startEnrollment);
	const verifyEnrollment = useMutation(api.twoFactor.verifyEnrollment);

	function handleStart() {
		startTransition(async () => {
			const data = await startEnrollment({ authToken, tenantSlug });
			setEnrollmentData(data);
			setStep("verify");
		});
	}

	function handleVerify() {
		if (code.length !== 6) return;
		startTransition(async () => {
			await verifyEnrollment({ authToken, code });
			onCancel();
		});
	}

	return (
		<div className="card p-6">
			<div className="flex items-center justify-between mb-4">
				<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
					{step === "start" ? "Set Up Two-Factor Authentication" : "Verify TOTP Code"}
				</h3>
				<button type="button" onClick={onCancel} className="drawer-close">
					<X size={18} />
				</button>
			</div>

			{step === "start" ? (
				<div className="space-y-4">
					<div className="p-4 rounded-lg bg-[var(--surface)] border border-[var(--line)] text-center">
						<Smartphone size={32} className="mx-auto mb-2 text-[var(--signal)]" />
						<p className="text-sm text-[var(--sea-ink)]">
							Click below to generate your TOTP secret and QR code
						</p>
					</div>
					<div className="flex justify-end gap-2">
						<button type="button" onClick={onCancel} className="secondary-button" style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}>
							Cancel
						</button>
						<button type="button" onClick={handleStart} disabled={isPending} className="signal-button" style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}>
							{isPending ? "Generating..." : "Generate Secret"}
						</button>
					</div>
				</div>
			) : (
				<div className="space-y-4">
					{/* QR Code placeholder */}
					<div className="p-4 rounded-lg bg-[var(--surface)] border border-[var(--line)]">
						<div className="w-48 h-48 mx-auto bg-white rounded-lg flex items-center justify-center mb-3">
							<div className="text-center">
								<Key size={32} className="mx-auto mb-1 text-[var(--signal)]" />
								<p className="text-[0.6rem] text-gray-500">Scan with authenticator</p>
							</div>
						</div>
						<div className="text-center">
							<p className="text-xs text-[var(--sea-ink-soft)] mb-1">Manual entry key:</p>
							<code className="text-xs bg-[var(--surface)] px-2 py-1 rounded border border-[var(--line)] font-mono">
								{enrollmentData?.secret ?? "••••••••••••••••"}
							</code>
						</div>
					</div>

					{/* Backup Codes */}
					{enrollmentData?.backupCodes && (
						<div className="p-3 rounded-lg bg-[var(--warning)]/10 border border-[var(--warning)]/30">
							<p className="text-xs font-semibold text-[var(--warning)] mb-2">Save these backup codes:</p>
							<div className="grid grid-cols-2 gap-1">
								{enrollmentData.backupCodes.map((bc: string, i: number) => (
									<code key={i} className="text-xs font-mono text-[var(--sea-ink)]">{bc}</code>
								))}
							</div>
						</div>
					)}

					{/* Verification */}
					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
							Enter 6-digit verification code
						</label>
						<input
							type="text"
							value={code}
							onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
							placeholder="000000"
							maxLength={6}
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] text-center font-mono text-lg tracking-widest focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						/>
					</div>

					<div className="flex justify-end gap-2">
						<button type="button" onClick={onCancel} className="secondary-button" style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}>
							Cancel
						</button>
						<button
							type="button"
							onClick={handleVerify}
							disabled={isPending || code.length !== 6}
							className="signal-button"
							style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
						>
							{isPending ? "Verifying..." : "Verify & Enable"}
						</button>
					</div>
				</div>
			)}
		</div>
	);
}

function DisableFlow({ authToken, onCancel }: { authToken: string; onCancel: () => void }) {
	const [code, setCode] = useState("");
	const [isPending, startTransition] = useTransition();
	const disable2fa = useMutation(api.twoFactor.disableTwoFactor);

	function handleDisable() {
		if (code.length !== 6) return;
		startTransition(async () => {
			await disable2fa({ authToken, code });
			onCancel();
		});
	}

	return (
		<div className="card p-6">
			<div className="flex items-center justify-between mb-4">
				<h3 className="text-sm font-semibold text-[var(--danger)]">Disable Two-Factor Authentication</h3>
				<button type="button" onClick={onCancel} className="drawer-close">
					<X size={18} />
				</button>
			</div>

			<div className="p-3 rounded-lg bg-[var(--danger)]/10 border border-[var(--danger)]/30 mb-4">
				<p className="text-sm text-[var(--danger)]">
					This will remove 2FA from your account. Enter your current TOTP code to confirm.
				</p>
			</div>

			<div className="mb-4">
				<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
					Current TOTP Code
				</label>
				<input
					type="text"
					value={code}
					onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
					placeholder="000000"
					maxLength={6}
					className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] text-center font-mono text-lg tracking-widest focus:outline-none focus:ring-2 focus:ring-[var(--danger)]"
				/>
			</div>

			<div className="flex justify-end gap-2">
				<button type="button" onClick={onCancel} className="secondary-button" style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}>
					Cancel
				</button>
				<button
					type="button"
					onClick={handleDisable}
					disabled={isPending || code.length !== 6}
					className="signal-button"
					style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem", background: "var(--danger)" }}
				>
					{isPending ? "Disabling..." : "Disable 2FA"}
				</button>
			</div>
		</div>
	);
}

function PolicyCard({ label, value, tone: _tone = "neutral" }: { label: string; value: number | string; tone?: "success" | "warning" | "neutral" }) {
	return (
		<div className="card card-sm p-3 text-center">
			<p className="text-lg font-bold text-[var(--sea-ink)]">{value}</p>
			<p className="text-xs text-[var(--sea-ink-soft)]">{label}</p>
		</div>
	);
}

function StepCard({ step, title, description }: { step: number; title: string; description: string }) {
	return (
		<div className="card card-sm p-4">
			<div className="w-7 h-7 rounded-full bg-[var(--signal)]/10 flex items-center justify-center mb-2">
				<span className="text-xs font-bold text-[var(--signal)]">{step}</span>
			</div>
			<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">{title}</p>
			<p className="text-xs text-[var(--sea-ink-soft)]">{description}</p>
		</div>
	);
}
