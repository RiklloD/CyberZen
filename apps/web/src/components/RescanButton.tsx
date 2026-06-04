import { useMutation } from "convex/react";
import { RefreshCw } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import { track } from "../lib/analytics";

/**
 * Scanner types that can be re-run. Must match the union defined in
 * `convex/events.ts → scannerType`.
 */
export type ScannerType =
	| "secret_detection"
	| "iac_scan"
	| "cicd_scan"
	| "crypto_weakness"
	| "sensitive_file"
	| "commit_message"
	| "git_integrity"
	| "high_risk_change"
	| "secret_mgmt_drift"
	| "dep_mgr_security_drift"
	| "ai_ml_security_drift"
	| "k8s_admission_drift"
	| "supply_chain_attestation_drift"
	| "endpoint_security_drift"
	| "network_monitoring_drift"
	| "voip_security_drift"
	| "virtualization_security_drift"
	| "iot_embedded_security_drift"
	| "wireless_radius_drift"
	| "os_security_hardening_drift"
	| "dns_security_drift"
	| "storage_data_security_drift"
	| "siem_security_drift"
	| "backup_dr_security_drift"
	| "vpn_remote_access_drift"
	| "cfg_mgmt_security_drift"
	| "artifact_registry_drift"
	| "ml_ai_platform_drift"
	| "data_pipeline_drift"
	| "sso_provider_drift"
	| "messaging_security_drift"
	| "serverless_faas_drift"
	| "email_security_drift"
	| "web_server_security_drift"
	| "mobile_app_security_drift"
	| "cicd_pipeline_security_drift"
	| "full_scan";

interface RescanButtonProps {
	scannerType: ScannerType;
	tenantSlug: string;
	repositoryFullName: string;
	label?: string;
}

export default function RescanButton({
	scannerType,
	tenantSlug,
	repositoryFullName,
	label = "Re-scan",
}: RescanButtonProps) {
	const dispatch = useMutation(api.events.dispatchScannerForRepository);
	const [loading, setLoading] = useState(false);
	const [lastResult, setLastResult] = useState<
		"success" | "error" | null
	>(null);

	const handleClick = async () => {
		setLoading(true);
		setLastResult(null);
		try {
			await dispatch({
				tenantSlug,
				repositoryFullName,
				scannerType,
			});
			track("scan.triggered", {
				scannerSlug: scannerType,
				repositoryName: repositoryFullName,
				triggerType: "manual",
			});
			setLastResult("success");
		} catch {
			setLastResult("error");
		} finally {
			setLoading(false);
			// Auto-clear status after 3s
			setTimeout(() => setLastResult(null), 3000);
		}
	};

	const toneClass =
		lastResult === "success"
			? "text-[var(--success)]"
			: lastResult === "error"
				? "text-[var(--danger)]"
				: "text-[var(--sea-ink-soft)]";

	return (
		<button
			type="button"
			onClick={handleClick}
			disabled={loading}
			className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-md border border-[var(--line)] bg-transparent hover:bg-[var(--surface)] transition-colors disabled:opacity-50 ${toneClass}`}
			title={`Re-run ${scannerType.replace(/_/g, " ")} scanner`}
		>
			<RefreshCw
				size={12}
				className={loading ? "animate-spin" : ""}
			/>
			<span>{lastResult === "success" ? "Queued" : lastResult === "error" ? "Failed" : label}</span>
		</button>
	);
}
