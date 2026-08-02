import type { Command } from "commander";

/**
 * Central command registry. Each feature group lives in its own module and
 * exports a `registerX(program)` function. Groups are added here as they are
 * implemented (see docs/plans/2026-08-02-cyberzen-cli.md).
 */
import { registerAgents } from "./agents";
import { registerAuth } from "./auth";
import { registerBilling } from "./billing";
import { registerDashboard } from "./dashboard";
import { registerDrift } from "./drift";
import { registerFindings } from "./findings";
import { registerIntegrations } from "./integrations";
import { registerJobs } from "./jobs";
import { registerLink } from "./link";
import { registerMemory } from "./memory";
import { registerOperations } from "./operations";
import { registerRepos } from "./repos";
import { registerSbom } from "./sbom";
import { registerSystem } from "./system";
import { registerTenants } from "./tenants";

export function registerAll(program: Command): void {
	registerAuth(program);
	registerAgents(program);
	registerBilling(program);
	registerIntegrations(program);
	registerJobs(program);
	registerTenants(program);
	registerDashboard(program);
	registerLink(program);
	registerMemory(program);
	registerFindings(program);
	registerRepos(program);
	registerSbom(program);
	registerDrift(program);
	registerOperations(program);
	registerSystem(program);
}
