import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { FileCheck2 } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import {
	driftLevelTone,
	frameworkScoreTone,
} from "../lib/utils";

export const Route = createFileRoute("/compliance")({ component: CompliancePage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];

const TENANT = TENANT_SLUG;

function CompliancePage() {
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

	const { repositories } = overview;
	const activeRepo =
		selectedRepo
			? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
			: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<FileCheck2 size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Compliance</h1>
						<p className="page-subtitle">
							Regulatory drift · SOC 2 · GDPR · HIPAA · PCI-DSS · NIS2
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{repositories.length > 1 && (
					<div className="tab-bar mb-4">
						{repositories.map((r: OverviewRepository) => (
							<button
								key={r._id}
								type="button"
								className={`tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`}
								onClick={() => setSelectedRepo(r._id)}
							>
								{r.fullName.split("/").pop()}
							</button>
						))}
					</div>
				)}

				{activeRepo && (
					<RepoComplianceIntelligence
						tenantSlug={TENANT}
						repositoryFullName={activeRepo.fullName}
					/>
				)}
			</div>
		</main>
	);
}

function RepoComplianceIntelligence({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const regulatoryDrift = useQuery(
		api.regulatoryDriftIntel.getLatestRegulatoryDrift,
		{ tenantSlug, repositoryFullName },
	);
	const complianceAttestation = useQuery(
		api.complianceAttestationIntel.getLatestComplianceAttestation,
		{ tenantSlug, repositoryFullName },
	);
	const complianceRemediation = useQuery(
		api.complianceRemediationIntel.getLatestComplianceRemediationPlan,
		{ tenantSlug, repositoryFullName },
	);
	const licenseCompliance = useQuery(
		api.licenseComplianceIntel.getLatestLicenseCompliance,
		{ tenantSlug, repositoryFullName },
	);
	const licenseScan = useQuery(
		api.licenseScanIntel.getLatestLicenseComplianceScan,
		{ tenantSlug, repositoryFullName },
	);
	const securityDebt = useQuery(
		api.securityDebtIntel.getLatestSecurityDebtBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const databaseSecurity = useQuery(
		api.databaseSecurityDriftIntel.getLatestDatabaseSecurityDriftBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const sensitiveFiles = useQuery(
		api.sensitiveFileIntel.getLatestSensitiveFileScanBySlug,
		{ tenantSlug, repositoryFullName },
	);

	return (
		<div className="space-y-4">
			{/* Regulatory Drift */}
			{regulatoryDrift && (
				<div className="card">
					<p className="panel-label mb-2">Regulatory Drift</p>
					<div className="flex flex-wrap gap-2 mb-3">
						<StatusPill
							label={regulatoryDrift.overallDriftLevel.replace("_", " ")}
							tone={driftLevelTone(regulatoryDrift.overallDriftLevel)}
						/>
						{regulatoryDrift.openGapCount > 0 && (
							<StatusPill
								label={`${regulatoryDrift.openGapCount} open gaps`}
								tone="neutral"
							/>
						)}
						{regulatoryDrift.criticalGapCount > 0 && (
							<StatusPill
								label={`${regulatoryDrift.criticalGapCount} critical`}
								tone="danger"
							/>
						)}
					</div>

					{/* Framework scores */}
					<div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
						{[
							{ key: "soc2", label: "SOC 2", score: regulatoryDrift.soc2Score },
							{ key: "gdpr", label: "GDPR", score: regulatoryDrift.gdprScore },
							{ key: "hipaa", label: "HIPAA", score: regulatoryDrift.hipaaScore },
							{ key: "pci_dss", label: "PCI-DSS", score: regulatoryDrift.pciDssScore },
							{ key: "nis2", label: "NIS2", score: regulatoryDrift.nis2Score },
						].map(({ key, label, score }) => (
							<div key={key} className="inset-panel text-center">
								<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
									{label}
								</div>
								<div
									className={`text-lg font-bold ${
										score >= 80
											? "text-[var(--success)]"
											: score >= 60
												? "text-[var(--warning)]"
												: "text-[var(--danger)]"
									}`}
								>
									{score}
								</div>
								<StatusPill
									label={score >= 80 ? "good" : score >= 60 ? "at risk" : "failing"}
									tone={frameworkScoreTone(score)}
								/>
							</div>
						))}
					</div>

					<p className="mt-3 text-xs text-[var(--sea-ink-soft)]">
						{regulatoryDrift.summary}
					</p>
				</div>
			)}

			{/* Compliance grid */}
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{complianceAttestation && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Compliance Attestation</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={complianceAttestation.overallStatus.replace(/_/g, " ")}
								tone={
									complianceAttestation.overallStatus === "compliant"
										? "success"
										: complianceAttestation.overallStatus === "at_risk"
											? "warning"
											: "danger"
								}
							/>
							<StatusPill
								label={`${complianceAttestation.fullyCompliantCount} fully compliant`}
								tone="neutral"
							/>
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{complianceAttestation.summary}
						</p>
					</div>
				)}

				{complianceRemediation && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Compliance Remediation</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={`${complianceRemediation.actions.length} actions`}
								tone={complianceRemediation.actions.length > 0 ? "warning" : "success"}
							/>
						{complianceRemediation.criticalActions > 0 && (
							<StatusPill
								label={`${complianceRemediation.criticalActions} critical`}
								tone="danger"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{complianceRemediation.summary}
						</p>
					</div>
				)}

				{(licenseCompliance || licenseScan) && (
					<div className="card card-sm">
						<p className="panel-label mb-2">License Compliance</p>
						{licenseCompliance && (
							<div className="flex flex-wrap gap-1.5 mb-1">
								{licenseCompliance.violations.length > 0 && (
									<StatusPill
										label={`${licenseCompliance.violations.length} violations`}
										tone="danger"
									/>
								)}
								<StatusPill
									label={`${licenseCompliance.totalComponents} components checked`}
									tone="neutral"
								/>
							</div>
						)}
						{licenseScan && (
							<p className="text-xs text-[var(--sea-ink-soft)]">
								{licenseScan.summary}
							</p>
						)}
					</div>
				)}

				{securityDebt && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Security Debt</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={`score ${securityDebt.debtScore}`}
								tone={
									securityDebt.debtScore > 70
										? "danger"
										: securityDebt.debtScore > 40
											? "warning"
											: "success"
								}
							/>
							<StatusPill label={securityDebt.trend} tone="neutral" />
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{securityDebt.summary}
						</p>
					</div>
				)}

				{databaseSecurity && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Database Security</p>
						<div className="flex flex-wrap gap-1.5">
							{databaseSecurity.criticalCount > 0 && (
								<StatusPill
									label={`${databaseSecurity.criticalCount} critical`}
									tone="danger"
								/>
							)}
							{databaseSecurity.highCount > 0 && (
								<StatusPill
									label={`${databaseSecurity.highCount} high`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{databaseSecurity.summary}
						</p>
					</div>
				)}

				{sensitiveFiles && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Sensitive Files</p>
						<div className="flex flex-wrap gap-1.5">
							{sensitiveFiles.criticalCount > 0 && (
								<StatusPill
									label={`${sensitiveFiles.criticalCount} critical`}
									tone="danger"
								/>
							)}
							{sensitiveFiles.highCount > 0 && (
								<StatusPill
									label={`${sensitiveFiles.highCount} high risk`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{sensitiveFiles.summary}
						</p>
					</div>
				)}
			</div>
		</div>
	);
}

