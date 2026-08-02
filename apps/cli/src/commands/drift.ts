import type { Command } from "commander";
import { api } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";
import { repositoryName, requiredTenant } from "../lib/tenant";

const DOMAINS = [
	"posture",
	"network-monitoring",
	"voip-security",
	"virtualization-security",
	"iot-embedded-security",
	"wireless-radius",
	"os-security-hardening",
	"dns-security",
	"storage-data-security",
	"siem-security",
	"backup-dr-security",
	"vpn-remote-access",
	"cfg-mgmt-security",
	"artifact-registry",
	"ml-ai-platform",
	"data-pipeline",
	"sso-provider",
	"messaging-security",
	"serverless-faas",
	"email-security",
	"web-server-security",
	"mobile-app-security",
	"cicd-pipeline-security",
	"service-mesh-security",
	"observability-security",
	"identity-access",
	"dev-sec-tools",
	"network-firewall",
	"runtime-security",
	"supply-chain-attestation",
	"k8s-admission",
	"secret-mgmt",
	"dep-mgr-security",
	"ai-ml-security",
] as const;

export function registerDrift(program: Command): void {
	const drift = program
		.command("drift")
		.description("Repository security drift analysis");
	drift
		.command("list")
		.description("List supported drift domains")
		.action((_o, command: Command) =>
			render(
				DOMAINS.map((domain) => ({ domain })),
				globalsOf(command),
			),
		);
	drift
		.command("get <domain>")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(
			async (
				domain: string,
				options: { tenant?: string; repo?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				if (!(DOMAINS as readonly string[]).includes(domain))
					throw new Error(`Unknown drift domain: ${domain}`);
				render(
					await api({
						path: `/api/repository/${domain === "posture" ? "drift-posture" : `${domain}-drift`}`,
						query: {
							tenantSlug: requiredTenant(options.tenant ?? globals.tenant),
							repositoryFullName: repositoryName(options.repo),
						},
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);
}
