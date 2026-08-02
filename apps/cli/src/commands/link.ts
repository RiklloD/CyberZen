import type { Command } from 'commander'
import { globalsOf } from '../lib/globalFlags'
import { render } from '../lib/output'
import { linkProject, readProject, resolveTenant, unlinkProject } from '../lib/project'
import { UsageError } from '../lib/errors'

export function registerLink(program: Command): void {
  const link = program.command('link').description('Link the current directory to a CyberZen tenant')
  link.option('--tenant <slug>', 'Tenant slug').option('--repo <owner/name>', 'Default repository')
    .action((options: { tenant?: string; repo?: string }, command: Command) => {
      const globals = globalsOf(command)
      const tenant = options.tenant ?? globals.tenant
      if (!tenant) throw new UsageError('A tenant is required.', 'Use `cyberzen link --tenant <slug>`.')
      const path = linkProject({ tenantSlug: tenant, repoFullName: options.repo })
      render({ linked: true, tenant, repo: options.repo, path }, globals)
    })

  program.command('unlink')
    .description('Remove the current directory CyberZen link')
    .action((_options: unknown, command: Command) => {
      const globals = globalsOf(command)
      render({ unlinked: unlinkProject() }, globals)
    })

  program.command('link-status')
    .description('Show the current directory CyberZen link')
    .action((_options: unknown, command: Command) => {
      const globals = globalsOf(command)
      const project = readProject()
      render({ linked: Boolean(project), ...project }, globals)
    })

  // Alias the explicit status spelling without duplicating behavior.
  program.command('link:status', { hidden: true })
    .action((_options: unknown, command: Command) => {
      const globals = globalsOf(command)
      const project = readProject()
      render({ linked: Boolean(project), ...project }, globals)
    })

  void resolveTenant
}
