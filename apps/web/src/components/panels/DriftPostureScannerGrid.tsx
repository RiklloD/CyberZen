import type { FunctionReturnType } from "convex/server";
import { Activity } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

export type DriftPostureData = NonNullable<
	FunctionReturnType<typeof api.driftPostureIntel.getLatestDriftPostureBySlug>
>;

export interface DriftPostureScannerGridProps {
	report: DriftPostureData;
}

/**
 * Static map of all 41 scanner workstreams to their display labels.
 * Derived from driftPostureScore.ts category definitions.
 */
const SCANNER_TILES: {
	id: string;
	label: string;
	category: string;
}[] = [
	// Category 1: Application Security
	{ id: "ws60", label: "App Security Config", category: "Application Security" },
	{ id: "ws61", label: "Test Coverage Gap", category: "Application Security" },
	{ id: "ws65", label: "API Security Config", category: "Application Security" },
	{ id: "ws75", label: "Web Server Security", category: "Application Security" },
	{ id: "ws76", label: "Email Security", category: "Application Security" },
	{ id: "ws103", label: "Dep. Manager Config", category: "Application Security" },
	{ id: "ws109", label: "Supply Chain Attestation", category: "Application Security" },
	// Category 2: Infrastructure
	{ id: "ws62", label: "Cloud Security", category: "Infrastructure" },
	{ id: "ws63", label: "K8s/Container Hardening", category: "Infrastructure" },
	{ id: "ws64", label: "Database Security", category: "Infrastructure" },
	{ id: "ws66", label: "Cert & PKI", category: "Infrastructure" },
	{ id: "ws87", label: "Storage & Data Security", category: "Infrastructure" },
	{ id: "ws105", label: "Secret Management", category: "Infrastructure" },
	// Category 3: Runtime & Policy
	{ id: "ws67", label: "Runtime Security Policy", category: "Runtime & Policy" },
	{ id: "ws68", label: "Network Firewall", category: "Runtime & Policy" },
	{ id: "ws72", label: "Service Mesh", category: "Runtime & Policy" },
	{ id: "ws73", label: "CI/CD Pipeline Security", category: "Runtime & Policy" },
	{ id: "ws107", label: "K8s Admission Controller", category: "Runtime & Policy" },
	// Category 4: Identity & Access
	{ id: "ws69", label: "DevSec Tooling/SAST", category: "Identity & Access" },
	{ id: "ws70", label: "IAM & Privileged Access", category: "Identity & Access" },
	{ id: "ws79", label: "SSO & Authentication", category: "Identity & Access" },
	// Category 5: Platform Services
	{ id: "ws77", label: "Serverless & FaaS", category: "Platform Services" },
	{ id: "ws78", label: "Messaging & Events", category: "Platform Services" },
	{ id: "ws80", label: "Data Pipeline & ETL", category: "Platform Services" },
	{ id: "ws81", label: "ML/AI Platform", category: "Platform Services" },
	{ id: "ws82", label: "Artifact Registry", category: "Platform Services" },
	{ id: "ws83", label: "Config Management", category: "Platform Services" },
	{ id: "ws101", label: "AI/ML Dependency Security", category: "Platform Services" },
	// Category 6: Observability & SIEM
	{ id: "ws71", label: "Observability & Monitoring", category: "Observability & SIEM" },
	{ id: "ws86", label: "SIEM & Analytics", category: "Observability & SIEM" },
	{ id: "ws94", label: "Network Monitoring", category: "Observability & SIEM" },
	// Category 7: Network & Connectivity
	{ id: "ws84", label: "VPN & Remote Access", category: "Network & Connectivity" },
	{ id: "ws85", label: "Backup & DR Security", category: "Network & Connectivity" },
	{ id: "ws88", label: "DNS Security", category: "Network & Connectivity" },
	{ id: "ws90", label: "Wireless & RADIUS", category: "Network & Connectivity" },
	// Category 8: Endpoint & Device
	{ id: "ws74", label: "Mobile App Security", category: "Endpoint & Device" },
	{ id: "ws89", label: "OS Security Hardening", category: "Endpoint & Device" },
	{ id: "ws91", label: "IoT & Embedded", category: "Endpoint & Device" },
	{ id: "ws92", label: "Virtualization & Hypervisor", category: "Endpoint & Device" },
	{ id: "ws93", label: "VoIP & Unified Comms", category: "Endpoint & Device" },
	{ id: "ws95", label: "Endpoint Security & EDR", category: "Endpoint & Device" },
];

function tileTone(
	grade: string,
): "success" | "info" | "warning" | "danger" | "neutral" {
	if (grade === "A") return "success";
	if (grade === "B") return "info";
	if (grade === "C") return "warning";
	if (grade === "D" || grade === "F") return "danger";
	return "neutral";
}

export default function DriftPostureScannerGrid({
	report }: DriftPostureScannerGridProps) {
	// Build a lookup: category label → { score, grade, worstRiskLevel }
	const catMap = new Map<
		string,
		{ score: number; grade: string; worstRiskLevel: string }
	>();
	for (const cs of report.categoryScores) {
		catMap.set(cs.label, {
			score: cs.score,
			grade: cs.grade,
			worstRiskLevel: cs.worstRiskLevel });
	}

	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-4">
				<Activity size={16} className="text-[var(--signal)]" />
				<h3 className="section-title mb-0">Scanner Grid</h3>
				<span className="text-xs text-[var(--sea-ink-soft)] ml-auto">
					{SCANNER_TILES.length} workstreams across 8 categories
				</span>
			</div>

			<div className="grid gap-2 grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
				{SCANNER_TILES.map((tile) => {
					const cat = catMap.get(tile.category);
					const score = cat?.score ?? 100;
					const grade = cat?.grade ?? "A";
					const tone = tileTone(grade);

					return (
						<button
							key={tile.id}
							type="button"
							className="text-left rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 hover:border-[var(--signal)] transition-colors group"
							title={`${tile.label} — ${tile.category}`}
						>
							<div className="flex items-center justify-between mb-1.5">
								<span className="text-[0.6rem] font-mono text-[var(--sea-ink-soft)] uppercase">
									{tile.id}
								</span>
								<StatusPill label={grade} tone={tone} />
							</div>
							<p className="text-xs font-medium text-[var(--sea-ink)] leading-snug truncate group-hover:text-[var(--signal)]">
								{tile.label}
							</p>
							<p className="mt-1 text-[0.65rem] text-[var(--sea-ink-soft)] truncate">
								{tile.category}
							</p>
							<div className="mt-2 w-full h-1 rounded-full bg-[var(--border)] overflow-hidden">
								<div
									className="h-full rounded-full transition-all duration-300"
									style={{
										width: `${score}%`,
										backgroundColor:
											tone === "success"
												? "var(--success)"
												: tone === "info"
													? "var(--signal)"
													: tone === "warning"
														? "var(--warning)"
														: tone === "danger"
															? "var(--danger)"
															: "var(--border)" }}
								/>
							</div>
						</button>
					);
				})}
			</div>

			<p className="mt-3 text-xs text-[var(--sea-ink-soft)]">
				Individual scanner detail panels (§1.19) will be available as tabs/accordion in a future update.
			</p>
		</div>
	);
}
