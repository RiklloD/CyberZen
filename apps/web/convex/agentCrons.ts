// ═══════════════════════════════════════════════════════════════════════════
// AGENT CRON SCHEDULER — Automated agent triggers
// ═══════════════════════════════════════════════════════════════════════════
//
// Internal actions called by crons to:
// 1. Auto-trigger remediation for new high-severity findings
// 2. Run Red-Blue adversarial rounds on a schedule
// 3. Run surface reduction and regulatory scans periodically
//

import { v } from 'convex/values'
import { internalAction, internalQuery } from './_generated/server'
import { internal } from './_generated/api'

// ─── Query: Get open findings that haven't been analyzed yet ─────────────────

export const getUnanalyzedFindings = internalQuery({
  args: {},
  handler: async (ctx) => {
    // Get all open findings that don't have a remediation proposal yet
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_status', (q) => q.eq('status', 'open'))
      .take(50)

    // Filter out those that already have a remediation proposal
    const result = []
    for (const finding of openFindings) {
      if (finding.severity === 'critical' || finding.severity === 'high') {
        const existingProposal = await ctx.db
          .query('remediationProposals')
          .withIndex('by_finding', (q) => q.eq('findingId', finding._id))
          .first()
        if (!existingProposal) {
          result.push(finding)
        }
      }
    }
    return result
  },
})

// ─── Auto-trigger remediation for new critical/high findings ────────────────

export const autoRemediateNewFindings = internalAction({
  args: {},
  handler: async (ctx) => {
    const unanalyzed = await ctx.runQuery(internal.agentCrons.getUnanalyzedFindings, {})
    console.log(`[Agent Crons] Found ${unanalyzed.length} unanalyzed high-severity findings`)

    for (const finding of unanalyzed.slice(0, 5)) { // cap at 5 per run to control cost
      try {
        // Create task
        const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
          tenantId: finding.tenantId,
          repositoryId: finding.repositoryId,
          findingId: finding._id,
          agentType: 'remediation',
          trigger: 'auto_finding_detected',
          priority: finding.severity === 'critical' ? 'critical' : 'high',
          inputSummary: `Auto-remediation for: ${finding.title} (${finding.severity})`,
        })

        // Schedule remediation
        await ctx.scheduler.runAfter(0, internal.agents.remediationAgent.analyze, {
          taskId,
          findingId: finding._id,
          tenantId: finding.tenantId,
          repositoryId: finding.repositoryId,
        })

        // Schedule exploit validation (in parallel)
        const validationTaskId = await ctx.runMutation(internal.agentData.createAgentTask, {
          tenantId: finding.tenantId,
          repositoryId: finding.repositoryId,
          findingId: finding._id,
          agentType: 'exploit_validation',
          trigger: 'auto_finding_detected',
          priority: 'high',
          inputSummary: `Auto-validation for: ${finding.title}`,
        })
        await ctx.scheduler.runAfter(0, internal.agents.exploitValidationAgent.validate, {
          taskId: validationTaskId,
          findingId: finding._id,
          tenantId: finding.tenantId,
          repositoryId: finding.repositoryId,
        })

        console.log(`[Agent Crons] Triggered remediation + validation for finding ${finding._id}`)
      } catch (err) {
        console.error(`[Agent Crons] Failed to process finding ${finding._id}:`, err)
      }
    }
  },
})

// ─── Red-Blue adversarial rounds (every 6 hours) ────────────────────────────

export const getReposForRedTeam = internalQuery({
  args: {},
  handler: async (ctx) => {
    const all = await ctx.db.query('repositories').take(10) // cap to control cost
    return all.filter((r: any) => !r.disconnectedAt)
  },
})

export const runRedBlueRounds = internalAction({
  args: {},
  handler: async (ctx) => {
    const repos = await ctx.runQuery(internal.agentCrons.getReposForRedTeam, {})
    console.log(`[Agent Crons] Running Red-Blue rounds for ${repos.length} repositories`)

    for (const repo of repos.slice(0, 3)) { // cap at 3 per run
      try {
        // Get current round number (must go through a query — actions have no ctx.db)
        const lastAttack = await ctx.runQuery(internal.agentData.getLatestAttackForRepo, {
          repositoryId: repo._id,
        })

        const roundNumber = (lastAttack?.roundNumber ?? 0) + 1

        // Only run if it's been at least 6 hours since last round
        if (lastAttack && (Date.now() - lastAttack.createdAt) < 6 * 60 * 60 * 1000) {
          continue
        }

        const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
          tenantId: repo.tenantId,
          repositoryId: repo._id,
          agentType: 'red_team',
          trigger: 'scheduled_adversarial_round',
          priority: 'medium',
          inputSummary: `Scheduled Red Team round ${roundNumber} for ${repo.fullName}`,
        })

        await ctx.scheduler.runAfter(0, internal.agents.redTeamAgent.runRound, {
          taskId,
          tenantId: repo.tenantId,
          repositoryId: repo._id,
          roundNumber,
        })

        console.log(`[Agent Crons] Triggered Red Team round ${roundNumber} for ${repo.fullName}`)
      } catch (err) {
        console.error(`[Agent Crons] Red Team failed for ${repo.fullName}:`, err)
      }
    }
  },
})

// ─── Blue Team rule generation (after Red Team completes) ───────────────────

export const generateBlueTeamRulesForRepos = internalAction({
  args: {},
  handler: async (ctx) => {
    const repos = await ctx.runQuery(internal.agentCrons.getReposForRedTeam, {})

    for (const repo of repos.slice(0, 3)) {
      try {
        // Check if there are successful attacks without detection rules
        const successfulAttacks = await ctx.runQuery(internal.agents.blueTeamAgent.getSuccessfulAttacks, {
          repositoryId: repo._id,
        })

        if (successfulAttacks.length === 0) continue

        const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
          tenantId: repo.tenantId,
          repositoryId: repo._id,
          agentType: 'blue_team',
          trigger: 'auto_after_red_team',
          priority: 'medium',
          inputSummary: `Blue Team rule generation for ${repo.fullName} (${successfulAttacks.length} attacks to defend)`,
        })

        await ctx.scheduler.runAfter(0, internal.agents.blueTeamAgent.generateRules, {
          taskId,
          tenantId: repo.tenantId,
          repositoryId: repo._id,
        })
      } catch (err) {
        console.error(`[Agent Crons] Blue Team failed for ${repo.fullName}:`, err)
      }
    }
  },
})
