import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Boxes } from "lucide-react";
import { useState } from "react";
import { api } from "../../convex/_generated/api";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import { formatTimestamp } from "../lib/utils";

export const Route = createFileRoute("/sbom")({ component: SbomPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];
type OverviewSnapshot = NonNullable<OverviewRepository["latestSnapshot"]>;
type OverviewComponent = OverviewSnapshot["previewComponents"][number];

const TENANT = TENANT_SLUG;

function componentLayerTone(
	layer: string,
	hasVulns = false,
): "success" | "warning" | "danger" | "info" | "neutral" {
	if (hasVulns) return "danger";
	if (layer === "direct") return "success";
	if (layer === "build") return "warning";
	if (layer === "ai_model") return "info";
	return "neutral";
}

function SbomPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-40 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const reposWithSbom = overview.repositories.filter(
		(r: OverviewRepository) => r.latestSnapshot !== undefined,
	);
	const active = selectedRepo
		? reposWithSbom.find((r: OverviewRepository) => r._id === selectedRepo)
		: reposWithSbom[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Boxes size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">SBOM Explorer</h1>
						<p className="page-subtitle">
							{overview.stats.sbomComponents} total components ·{" "}
							{reposWithSbom.length} repositories with active snapshots
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Repository selector */}
				{reposWithSbom.length > 1 && (
					<div className="tab-bar mb-4">
						{reposWithSbom.map((r: OverviewRepository) => (
							<button
								key={r._id}
								type="button"
								className={`tab-btn ${active?._id === r._id ? "is-active" : ""}`}
								onClick={() => setSelectedRepo(r._id)}
							>
								{r.fullName.split("/").pop()}
							</button>
						))}
					</div>
				)}

				{active?.latestSnapshot ? (
					<SbomRepoView
						tenantSlug={TENANT}
						repo={active}
						snapshot={active.latestSnapshot}
					/>
				) : (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<Boxes size={24} className="mb-2 opacity-40" />
						<p>No SBOM snapshots available.</p>
					</div>
				)}
			</div>
		</main>
	);
}

function SbomRepoView({
	tenantSlug,
	repo,
	snapshot,
}: {
	tenantSlug: string;
	repo: OverviewRepository;
	snapshot: OverviewSnapshot;
}) {
	const repositoryFullName = repo.fullName;

	const quality = useQuery(api.sbomQualityIntel.getSbomQualityForRepository, {
		tenantSlug,
		repositoryFullName,
	});
	const attestation = useQuery(
		api.sbomAttestationIntel.getLatestAttestation,
		{ tenantSlug, repositoryFullName },
	);
	const cveScan = useQuery(api.cveVersionScanIntel.getLatestCveScan, {
		tenantSlug,
		repositoryFullName,
	});
	const containerScan = useQuery(
		api.containerImageIntel.getLatestContainerImageScan,
		{ tenantSlug, repositoryFullName },
	);

	return (
		<div className="space-y-4">
			{/* Snapshot overview */}
			<div className="card">
				<div className="flex flex-wrap items-start justify-between gap-3">
					<div>
						<p className="panel-label mb-1">Latest Snapshot</p>
						<h2 className="text-sm font-bold text-[var(--sea-ink)]">
							{repo.fullName}
						</h2>
					<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
						{formatTimestamp(snapshot.capturedAt)}
					</p>
					</div>
					<div className="flex flex-wrap gap-2">
						<StatusPill
							label={`${snapshot.previewComponents.length} preview components`}
							tone="neutral"
						/>
						{snapshot.vulnerablePreview.length > 0 && (
							<StatusPill
								label={`${snapshot.vulnerablePreview.length} vulnerable`}
								tone="danger"
							/>
						)}
					</div>
				</div>

				{/* Component preview */}
				<div className="mt-4">
					<p className="panel-label mb-2">Component preview</p>
					<div className="space-y-1.5">
						{snapshot.previewComponents.slice(0, 10).map((c: OverviewComponent) => (
							<div
								key={`${c.name}-${c.version}`}
								className="flex flex-wrap items-center gap-2"
							>
								<StatusPill
									label={c.layer}
									tone={componentLayerTone(c.layer, c.hasKnownVulnerabilities)}
								/>
								<span className="font-mono text-xs text-[var(--sea-ink)]">
									{c.name}@{c.version}
								</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">
									{c.ecosystem}
								</span>
								{c.hasKnownVulnerabilities && (
									<StatusPill label="vulnerable" tone="danger" />
								)}
							</div>
						))}
					</div>
				</div>

				{/* Vulnerable components */}
				{snapshot.vulnerablePreview.length > 0 && (
					<div className="mt-4">
						<p className="panel-label mb-2">
							Vulnerable Components ({snapshot.vulnerablePreview.length})
						</p>
						<div className="space-y-1.5">
							{snapshot.vulnerablePreview.map((c) => (
								<div
									key={`${c.name}-${c.version}`}
									className="flex flex-wrap items-center gap-2 inset-panel"
								>
									<StatusPill label="vulnerable" tone="danger" />
									<span className="font-mono text-xs text-[var(--sea-ink)]">
										{c.name}@{c.version}
									</span>
									<StatusPill label={c.ecosystem} tone="neutral" />
									<StatusPill label={c.layer} tone="neutral" />
								</div>
							))}
						</div>
					</div>
				)}

				{/* Comparison diff */}
				{snapshot.comparison && (
					<div className="mt-4">
						<p className="panel-label mb-2">Changes since last snapshot</p>
						<div className="flex flex-wrap gap-2 mb-2">
							{snapshot.comparison.addedPreview.length > 0 && (
								<StatusPill
									label={`${snapshot.comparison.addedPreview.length} added`}
									tone="info"
								/>
							)}
							{snapshot.comparison.removedCount > 0 && (
								<StatusPill
									label={`${snapshot.comparison.removedCount} removed`}
									tone="warning"
								/>
							)}
							{snapshot.comparison.updatedPreview.length > 0 && (
								<StatusPill
									label={`${snapshot.comparison.updatedPreview.length} updated`}
									tone="neutral"
								/>
							)}
						</div>
						{snapshot.comparison.addedPreview.slice(0, 5).map((c) => (
							<div key={`${c.name}-${c.version}`} className="flex flex-wrap items-center gap-2 mt-1">
								<StatusPill label="+ added" tone="info" />
								<span className="font-mono text-xs">{c.name}@{c.version}</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">{c.ecosystem}</span>
							</div>
						))}
						{snapshot.comparison.updatedPreview.slice(0, 5).map((c) => (
							<div key={c.name} className="flex flex-wrap items-center gap-2 mt-1">
								<StatusPill label="↑ updated" tone="neutral" />
								<span className="font-mono text-xs">{c.name}</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">
									{c.previousVersion} → {c.nextVersion}
								</span>
							</div>
						))}
					</div>
				)}
			</div>

			{/* SBOM Quality + Attestation + CVE scan + Container scan in a grid */}
			<div className="grid gap-4 sm:grid-cols-2">
				{quality && (
					<div className="card card-sm">
						<p className="panel-label mb-2">SBOM Quality</p>
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={`score ${quality.overallScore}/100`}
							tone={quality.overallScore >= 80 ? "success" : quality.overallScore >= 60 ? "warning" : "danger"}
						/>
						<StatusPill label={quality.grade} tone="neutral" />
					</div>
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">{quality.summary}</p>
					</div>
				)}

				{attestation && (
					<div className="card card-sm">
						<p className="panel-label mb-2">SBOM Attestation</p>
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={attestation.status}
							tone={
								attestation.status === "valid"
									? "success"
									: attestation.status === "tampered"
										? "danger"
										: "warning"
							}
						/>
						<StatusPill
							label={`v${attestation.attestationVersion}`}
							tone="neutral"
						/>
					</div>
					<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
						{attestation.componentCount} components attested
					</p>
					<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
						{formatTimestamp(attestation.attestedAt)}
					</p>
					</div>
				)}

				{cveScan && (
					<div className="card card-sm">
						<p className="panel-label mb-2">CVE Version Scan</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={`${cveScan.totalVulnerable} CVE matches`}
							tone={cveScan.totalVulnerable > 0 ? "danger" : "success"}
						/>
							{cveScan.criticalCount > 0 && (
								<StatusPill label={`${cveScan.criticalCount} critical`} tone="danger" />
							)}
							{cveScan.highCount > 0 && (
								<StatusPill label={`${cveScan.highCount} high`} tone="warning" />
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{cveScan.summary}
						</p>
					</div>
				)}

				{containerScan && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Container Image Scan</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={`${containerScan.totalImages} images`}
								tone="neutral"
							/>
						{containerScan.criticalCount > 0 && (
							<StatusPill
								label={`${containerScan.criticalCount} critical`}
								tone="danger"
							/>
						)}
						{containerScan.highCount > 0 && (
							<StatusPill
								label={`${containerScan.highCount} high`}
								tone="warning"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{containerScan.summary}
						</p>
					</div>
				)}
			</div>
		</div>
	);
}
