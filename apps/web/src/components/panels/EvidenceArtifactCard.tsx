import type { FunctionReturnType } from "convex/server";
import { Download, FileText } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatDate } from "../../lib/utils";

type EvidenceBundle = NonNullable<
	FunctionReturnType<
		typeof api.complianceEvidenceIntel.getAllFrameworkEvidence
	>
>["bundles"][number];

type Artifact = EvidenceBundle["artifacts"][number];

function artifactStatusTone(
	status: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (status === "collected") return "success";
	if (status === "stale") return "warning";
	if (status === "missing") return "danger";
	return "neutral";
}

function handleDownload(artifact: Artifact) {
	const blob = new Blob([JSON.stringify(artifact, null, 2)], {
		type: "application/json" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = `${artifact.controlId}-${artifact.artifactType}.json`;
	a.click();
	URL.revokeObjectURL(url);
}

export type EvidenceArtifactCardProps = {
	artifact: Artifact;
};

export default function EvidenceArtifactCard({
	artifact }: EvidenceArtifactCardProps) {
	return (
		<div className="card card-sm flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div className="flex items-start gap-3 min-w-0">
				<FileText
					size={16}
					className="mt-0.5 shrink-0 text-[var(--sea-ink-soft)]"
				/>
				<div className="min-w-0">
					<div className="flex flex-wrap items-center gap-1.5">
						<span className="text-sm font-semibold text-[var(--sea-ink)]">
							{artifact.controlId}
						</span>
						<StatusPill
							label={artifact.status.replace(/_/g, " ")}
							tone={artifactStatusTone(artifact.status)}
						/>
						<StatusPill
							label={artifact.artifactType.replace(/_/g, " ")}
							tone="neutral"
						/>
					</div>
					{artifact.description && (
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5 truncate">
							{artifact.description}
						</p>
					)}
					<div className="flex flex-wrap gap-2 text-xs text-[var(--sea-ink-soft)] mt-1">
						{artifact.collectedAt && (
							<span>Collected {formatDate(artifact.collectedAt)}</span>
						)}
						{artifact.evidenceHash && (
							<span title={artifact.evidenceHash}>
								Hash: {artifact.evidenceHash.slice(0, 12)}…
							</span>
						)}
					</div>
				</div>
			</div>

			<button
				type="button"
				onClick={() => handleDownload(artifact)}
				className="signal-button secondary-button text-xs shrink-0 self-start sm:self-center"
				disabled={artifact.status === "missing"}
			>
				<Download size={12} className="inline -mt-0.5 mr-1" />
				Download
			</button>
		</div>
	);
}
