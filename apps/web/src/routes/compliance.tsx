import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { FileCheck2 } from "lucide-react";
import { useState } from "react";
import StatusPill from "../components/StatusPill";
import ComplianceEvidencePanel from "../components/panels/ComplianceEvidencePanel";
import RegulatoryDriftPanel from "../components/panels/RegulatoryDriftPanel";
import ComplianceAttestationPanel from "../components/panels/ComplianceAttestationPanel";
import ComplianceRemediationPanel from "../components/panels/ComplianceRemediationPanel";
import LicenseCompliancePanel from "../components/panels/LicenseCompliancePanel";
import SecurityDebtPanel from "../components/panels/SecurityDebtPanel";
import SensitiveFileScanPanel from "../components/panels/SensitiveFileScanPanel";
import ExportMenu from "../components/ExportMenu";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import { useFeatureFlag } from "../lib/featureFlags";
import QueryErrorFallback from "../components/QueryErrorFallback";

export const Route = createFileRoute("/compliance")({
	errorComponent: QueryErrorFallback,
	component: CompliancePage,
});

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function CompliancePage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
	const [activeSection, setActiveSection] = useState<
		"intelligence" | "evidence"
	>("intelligence");
	const allEvidence = useQuery(
		api.complianceEvidenceIntel.getAllFrameworkEvidence,
		{ tenantSlug: TENANT },
	);

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
	const activeRepo = selectedRepo
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
					<div className="ml-auto">
						<ExportMenu tenantSlug={TENANT} variant="compliance" />
					</div>
				</div>
			</div>

		<div className="page-body">
			{/* Section tabs */}
			<div className="tab-bar mb-4">
				<button
					type="button"
					className={`tab-btn ${activeSection === "intelligence" ? "is-active" : ""}`}
					onClick={() => setActiveSection("intelligence")}
				>
					Intelligence
				</button>
				<button
					type="button"
					className={`tab-btn ${activeSection === "evidence" ? "is-active" : ""}`}
					onClick={() => setActiveSection("evidence")}
				>
					Evidence
				</button>
			</div>

			{activeSection === "evidence" ? (
				allEvidence ? (
					<ComplianceEvidencePanel evidence={allEvidence} />
				) : (
					<div className="grid gap-3 sm:grid-cols-2">
						{["a", "b"].map((k) => (
							<div key={k} className="loading-panel h-40 rounded-2xl" />
						))}
					</div>
				)
			) : (
				<>
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
				</>
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
	const hasAttestation = useFeatureFlag("compliance_attestation");
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
				<RegulatoryDriftPanel data={regulatoryDrift} />
			)}

			{/* Compliance grid */}
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{complianceAttestation && hasAttestation && (
					<ComplianceAttestationPanel data={complianceAttestation} />
				)}

				{/* §8.7 — Upsell card for non-Enterprise tenants */}
				{!hasAttestation && (
					<div className="card card-sm border border-dashed border-[var(--sea-ink-soft)] flex flex-col items-center justify-center gap-2 py-6">
						<FileCheck2 size={24} className="text-[var(--sea-ink-soft)]" />
						<p className="text-sm font-medium">Compliance Attestation</p>
						<p className="text-xs text-[var(--sea-ink-soft)] text-center max-w-[200px]">
							Automated compliance attestation reports are available on the Enterprise plan.
						</p>
						<a
							href="/settings/billing"
							className="signal-button text-xs mt-1"
						>
							Upgrade to Enterprise
						</a>
					</div>
				)}

				{complianceRemediation && (
					<ComplianceRemediationPanel data={complianceRemediation} />
				)}

				{(licenseCompliance || licenseScan) && (
					<LicenseCompliancePanel
						licenseCompliance={licenseCompliance ?? undefined}
						licenseScan={licenseScan ?? undefined}
					/>
				)}

				{securityDebt && (
					<SecurityDebtPanel data={securityDebt} />
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
					<SensitiveFileScanPanel data={sensitiveFiles} />
				)}
			</div>
		</div>
	);
}
