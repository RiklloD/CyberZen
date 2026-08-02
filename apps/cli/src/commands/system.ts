import type { Command } from 'commander'
import { render } from '../lib/output'
import { globalsOf } from '../lib/globalFlags'
import { api } from '../lib/api'

export interface CommandManifestEntry {
  command: string
  transport: 'local' | 'http' | 'convex-bridge'
  endpoint?: string
  machineOutput: boolean
}

export const COMMAND_MANIFEST: CommandManifestEntry[] = [
  { command: 'auth login', transport: 'local', machineOutput: true },
  { command: 'auth whoami', transport: 'local', machineOutput: true },
  { command: 'auth logout', transport: 'local', machineOutput: true },
  { command: 'link', transport: 'local', machineOutput: true },
  { command: 'findings list', transport: 'http', endpoint: 'GET /api/findings', machineOutput: true },
  { command: 'findings get', transport: 'http', endpoint: 'GET /api/findings/detail', machineOutput: true },
  { command: 'findings status', transport: 'http', endpoint: 'PATCH /api/findings/status', machineOutput: true },
  { command: 'repos scan', transport: 'http', endpoint: 'POST /api/repositories/scan', machineOutput: true },
  { command: 'repos health', transport: 'http', endpoint: 'GET /api/repository/health-score', machineOutput: true },
  { command: 'sbom *', transport: 'http', endpoint: 'GET /api/sbom/*', machineOutput: true },
  { command: 'drift get', transport: 'http', endpoint: 'GET /api/repository/*-drift', machineOutput: true },
  { command: 'gates *', transport: 'http', machineOutput: true },
  { command: 'attack *', transport: 'http', machineOutput: true },
  { command: 'trust *', transport: 'http', machineOutput: true },
  { command: 'threat *', transport: 'http', machineOutput: true },
  { command: 'compliance *', transport: 'http', machineOutput: true },
  { command: 'reports *', transport: 'http', machineOutput: true },
  { command: 'sla *', transport: 'http', machineOutput: true },
  { command: 'remediation *', transport: 'http', machineOutput: true },
  { command: 'webhooks *', transport: 'http', endpoint: 'GET|POST|DELETE /api/webhooks', machineOutput: true },
  { command: 'siem push', transport: 'http', endpoint: 'POST /api/siem/push', machineOutput: true },
  { command: 'sandbox *', transport: 'http', machineOutput: true },
  { command: 'marketplace *', transport: 'http', machineOutput: true },
  { command: 'mssp *', transport: 'http', machineOutput: true },
]

export function registerSystem(program: Command): void {
  const system = program.command('system').description('CLI and platform utilities')
  system.command('schema')
    .description('Print the machine-readable CLI capability manifest')
    .action((_options: unknown, command: Command) => render(COMMAND_MANIFEST, { ...globalsOf(command), json: true }))
  system.command('version').action((_options: unknown, command: Command) => {
    render({ cli: process.env.CYBERZEN_CLI_VERSION ?? '0.1.0' }, globalsOf(command))
  })
  system.command('status').description('Check the CyberZen platform health endpoint').action(async (_options: unknown, command: Command) => {
    const globals = globalsOf(command)
    render(await api({ path: '/api/observability/metrics', timeout: globals.timeout }), globals)
  })
}

export function registerStatus(program: Command): void {
  program.command('status').description('Check CyberZen platform status').action(async (_options: unknown, command: Command) => {
    const globals = globalsOf(command)
    render(await api({ path: '/api/observability/metrics', timeout: globals.timeout }), globals)
  })
}
