# Sentinel LLM Agent System — Full Feature Design

> **Date:** 2026-06-18
> **Status:** Design — Ready for Implementation
> **Owner:** CyberZen / Sentinel Product
> **Supersedes:** The template-based approach in current codebase
> **Depends on:** Existing Convex infrastructure, `events.ts` workflow engine, `schema.ts` tables

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [LLM Provider Layer](#3-llm-provider-layer)
4. [Agent Orchestration Engine](#4-agent-orchestration-engine)
5. [Agent Specifications](#5-agent-specifications)
6. [Memory & Learning System](#6-memory--learning-system)
7. [Reasoning & Audit Trail](#7-reasoning--audit-trail)
8. [Sandbox Execution Environment](#8-sandbox-execution-environment)
9. [PR Generation Agent (Deep Dive)](#9-pr-generation-agent-deep-dive)
10. [Cost Management & Rate Limiting](#10-cost-management--rate-limiting)
11. [Schema Changes](#11-schema-changes)
12. [Implementation Phases](#12-implementation-phases)
13. [Risk & Mitigations](#13-risk--mitigations)

---

## 1. Executive Summary

The current CyberZen platform has a complete backend (150+ Convex modules, 8,600+ tests) and a full frontend (46 routes, 100+ panels), but **zero LLM integration**. Every "intelligent" feature — remediation playbooks, PR generation, attack paths, Red/Blue agents — uses deterministic templates.

This design introduces an **AI orchestration layer** that connects the existing data pipeline to LLM providers (OpenAI, Anthropic, local models), enabling:

- **Reasoning about code** — not just CVE matching, but understanding what code does and why it's vulnerable
- **Autonomous PR generation** — fixes with full reasoning chains, PoC code, and blast radius context
- **Adversarial Red-Blue agents** — LLM-powered attack and defense that learn per-codebase
- **Continuous learning** — every finding, fix, and false positive improves the system for that customer

The design preserves the existing Convex architecture. LLM calls happen in Convex **actions** (external API calls), while all data access stays in **queries** and **mutations**. No changes to the workflow engine's core loop.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EXISTING LAYER                                │
│  GitHub Webhook → ingestionEvent → workflowRun → workflowTasks       │
│  findings · sbomComponents · blastRadius · gateDecisions             │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    NEW: AGENT ORCHESTRATION LAYER                    │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Agent Router │  │ Task Planner │  │  Memory Controller       │  │
│  │  (mutation)   │  │  (action)    │  │  (query + mutation)      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────────┘  │
│         │                 │                      │                   │
│         ▼                 ▼                      ▼                   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              SPECIALIZED AGENTS (Convex Actions)              │   │
│  │                                                               │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │   │
│  │  │ Remediation  │ │ PR Generate │ │ Exploit Validation  │   │   │
│  │  │ Agent        │ │ Agent       │ │ Agent               │   │   │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘   │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │   │
│  │  │ Red Team     │ │ Blue Team   │ │ Blast Radius        │   │   │
│  │  │ Agent        │ │ Agent       │ │ Reasoning Agent     │   │   │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘   │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │   │
│  │  │ Prompt Inj.  │ │ Regulatory  │ │ Surface Reduction   │   │   │
│  │  │ Agent        │ │ Drift Agent │ │ Agent               │   │   │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                             │                                        │
│                             ▼                                        │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              LLM PROVIDER LAYER                               │   │
│  │  OpenAI · Anthropic · Local (Ollama) · Custom endpoints       │   │
│  │  Unified interface · Retry · Rate limit · Cost tracking       │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **LLM calls in Convex actions** | Actions can make external HTTP calls; queries/mutations cannot. All LLM invocations go through actions that call queries/mutations for data access. |
| **Unified provider interface** | Single `LLMClient` abstraction over OpenAI/Anthropic/local — swap providers without changing agent code. |
| **Memory in existing Convex tables** | Extend `projectMemories`, `memoryPatterns`, `memoryEpisodes` — already schema'd, indexed, tenant-scoped. |
| **Reasoning logs as first-class entities** | Every LLM call produces a structured reasoning log stored in `agentReasoningLogs` — full auditability. |
| **No new infrastructure** | No Redis, no Kafka, no separate orchestration service. Convex actions + crons + existing schema handle everything. |

---

## 3. LLM Provider Layer

### 3.1 Unified LLM Client

A single TypeScript module (`convex/lib/llmClient.ts`) that abstracts over providers:

```typescript
// convex/lib/llmClient.ts

export type LLMProvider = 'openai' | 'anthropic' | 'ollama' | 'custom'

export type LLMRequest = {
  provider: LLMProvider
  model: string
  messages: LLMMessage[]
  temperature?: number        // 0.0 - 1.0, default 0.1 for security tasks
  maxTokens?: number          // default 4096
  responseFormat?: 'text' | 'json'
  tools?: LLMTool[]           // for function-calling agents
  systemPrompt?: string
  stopSequences?: string[]
}

export type LLMMessage = {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string
  toolCallId?: string
}

export type LLMTool = {
  name: string
  description: string
  parameters: Record<string, unknown>  // JSON Schema
}

export type LLMResponse = {
  content: string
  toolCalls?: LLMToolCall[]
  usage: {
    promptTokens: number
    completionTokens: number
    totalTokens: number
    estimatedCostUsd: number
  }
  model: string
  provider: LLMProvider
  latencyMs: number
  requestId: string
}

export type LLMToolCall = {
  id: string
  name: string
  arguments: Record<string, unknown>
}
```

### 3.2 Provider Implementations

| Provider | Models | Use Case | Env Var |
|----------|--------|----------|---------|
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `o3` | Primary reasoning, code generation | `OPENAI_API_KEY` |
| **Anthropic** | `claude-sonnet-4-6`, `claude-haiku` | Deep analysis, long context | `ANTHROPIC_API_KEY` |
| **Ollama** | `codellama`, `deepseek-coder` | Local/dev, zero cost, air-gapped | `OLLAMA_BASE_URL` |
| **Custom** | Any OpenAI-compatible API | Enterprise on-prem, custom models | `CUSTOM_LLM_BASE_URL`, `CUSTOM_LLM_API_KEY` |

### 3.3 Provider Selection Strategy

```typescript
// convex/lib/llmRouter.ts

export function selectProvider(task: AgentTask): LLMProviderConfig {
  // Tier 1: Complex reasoning (Red Agent strategy, blast radius chains)
  if (task.complexity === 'high' && task.codeInvolved) {
    return { provider: 'anthropic', model: 'claude-sonnet-4-6', temperature: 0.1 }
  }

  // Tier 2: Code generation (PR fixes, exploit payloads)
  if (task.type === 'code_generation') {
    return { provider: 'openai', model: 'gpt-4o', temperature: 0.0 }
  }

  // Tier 3: Classification / extraction (finding triage, regulatory parsing)
  if (task.type === 'classification') {
    return { provider: 'openai', model: 'gpt-4o-mini', temperature: 0.0 }
  }

  // Tier 4: Bulk processing (SBOM analysis, batch scoring)
  if (task.type === 'bulk_processing') {
    return { provider: 'openai', model: 'gpt-4o-mini', temperature: 0.0 }
  }

  // Fallback
  return { provider: 'openai', model: 'gpt-4o-mini', temperature: 0.1 }
}
```

### 3.4 Retry & Circuit Breaker

```typescript
// convex/lib/llmRetry.ts

export async function callWithRetry<T>(
  fn: () => Promise<T>,
  opts: { maxRetries: number; baseDelayMs: number; maxDelayMs: number }
): Promise<T> {
  // Exponential backoff with jitter
  // Retry on: 429 (rate limit), 500-599 (server error), timeout
  // Do NOT retry on: 400 (bad request), 401 (auth), 403 (forbidden)
}

export class CircuitBreaker {
  // Per-provider circuit breaker
  // Opens after 5 consecutive failures
  // Half-open after 60 seconds
  // Tracks: state, failureCount, lastFailureAt, nextRetryAt
}
```

### 3.5 Cost Tracking

Every LLM call records usage in the `llmUsageRecords` table:

```typescript
// Written after every LLM call
{
  tenantId: Id<"tenants">,
  agentType: string,           // 'pr_generation' | 'red_team' | etc.
  provider: LLMProvider,
  model: string,
  promptTokens: number,
  completionTokens: number,
  estimatedCostUsd: number,
  taskId: string,              // links to agentTask or workflowRun
  timestamp: number,
}
```

A daily cron aggregates usage per tenant for billing integration (§10).

---

## 4. Agent Orchestration Engine

### 4.1 Agent Router

The **Agent Router** is a Convex mutation that receives events from the existing workflow engine and dispatches them to the appropriate LLM-powered agent.

```typescript
// convex/agentOrchestrator.ts

export const routeAgentTask = mutation({
  args: {
    trigger: v.union(
      v.literal('finding_detected'),
      v.literal('pr_requested'),
      v.literal('exploit_validation_requested'),
      v.literal('red_team_round'),
      v.literal('blast_radius_analysis'),
      v.literal('regulatory_update'),
      v.literal('surface_reduction_scan'),
      v.literal('prompt_injection_scan'),
    ),
    context: v.object({
      findingId: v.optional(v.id('findings')),
      repositoryId: v.id('repositories'),
      tenantId: v.id('tenants'),
      workflowRunId: v.optional(v.id('workflowRuns')),
      priority: v.union(v.literal('critical'), v.literal('high'), v.literal('medium'), v.literal('low')),
    }),
    metadata: v.optional(v.any()),
  },
  handler: async (ctx, args) => {
    // 1. Create agentTask record (queued)
    // 2. Determine which agent(s) to spawn
    // 3. Schedule agent action via ctx.scheduler.runAfter(0, ...)
    // 4. Return taskId for tracking
  },
})
```

### 4.2 Task Lifecycle

```
Event (from workflow engine or cron)
    │
    ▼
Agent Router (mutation)
    │ Creates agentTask record: status = 'queued'
    │
    ▼
Agent Scheduler (ctx.scheduler.runAfter(0, agentAction))
    │
    ▼
Agent Action (Convex action)
    │ 1. Load context via queries
    │ 2. Load memory via queries
    │ 3. Build LLM prompt
    │ 4. Call LLM via provider layer
    │ 5. Parse response
    │ 6. Execute tool calls (if any)
    │ 7. Write results via mutations
    │ 8. Write reasoning log via mutation
    │ 9. Update agentTask: status = 'completed' | 'failed'
    │
    ▼
Post-Agent Hook (mutation)
    │ - Update finding status if applicable
    │ - Trigger PR generation if exploit confirmed
    │ - Update memory patterns
    │ - Emit webhook events
    │ - Update dashboard stats
```

### 4.3 Parallelism

Multiple agent tasks run in parallel within a workflow:

```typescript
// In the agent action for a full scan workflow:
const [remediationResult, blastRadiusResult, exploitResult] = await Promise.all([
  ctx.runAction(internal.agents.remediationAgent.analyze, { findingId, context }),
  ctx.runAction(internal.agents.blastRadiusAgent.analyze, { findingId, context }),
  ctx.runAction(internal.agents.exploitValidationAgent.validate, { findingId, context }),
])
```

### 4.4 Agent Task Table

```typescript
agentTasks: defineTable({
  tenantId: v.id('tenants'),
  repositoryId: v.id('repositories'),
  workflowRunId: v.optional(v.id('workflowRuns')),
  findingId: v.optional(v.id('findings')),
  agentType: v.string(),          // 'remediation' | 'pr_generation' | 'red_team' | etc.
  trigger: v.string(),            // what caused this task
  status: v.union(                // lifecycle
    v.literal('queued'),
    v.literal('running'),
    v.literal('completed'),
    v.literal('failed'),
    v.literal('cancelled'),
  ),
  priority: v.string(),
  inputSummary: v.string(),       // human-readable summary of what the agent received
  outputSummary: v.optional(v.string()), // human-readable summary of what the agent produced
  reasoningLogId: v.optional(v.id('agentReasoningLogs')),
  llmProvider: v.optional(v.string()),
  llmModel: v.optional(v.string()),
  tokenUsage: v.optional(v.object({
    prompt: v.number(),
    completion: v.number(),
    total: v.number(),
    costUsd: v.number(),
  })),
  startedAt: v.optional(v.number()),
  completedAt: v.optional(v.number()),
  error: v.optional(v.string()),
  retryCount: v.number(),
  maxRetries: v.number(),
})
  .index('by_tenant', ['tenantId'])
  .index('by_repository', ['repositoryId'])
  .index('by_status', ['status'])
  .index('by_workflow_run', ['workflowRunId'])
  .index('by_finding', ['findingId'])
  .index('by_agent_type', ['agentType'])
  .index('by_tenant_and_status', ['tenantId', 'status'])
```

---

## 5. Agent Specifications

### 5.1 Remediation Agent

**Purpose:** Given a finding, analyze the vulnerable code and generate a fix.

```
Inputs:
  - Finding record (severity, vuln class, affected files, affected packages)
  - Source code of affected files (fetched via GitHub API)
  - SBOM context (current version, available patches)
  - Customer memory (team coding style, historical fix patterns)
  - Blast radius context (what services are affected)

Process:
  1. Classify finding type (dependency_cve | secret_exposure | misconfiguration | sast_finding | injection | auth_bypass)
  2. Load relevant source code (affected files + imports + tests)
  3. Load customer's historical fix patterns for this vuln class
  4. Build context-aware prompt:
     - System: "You are a senior security engineer. Generate a minimal, focused fix."
     - Context: source code, finding details, blast radius, team style
     - Task: "Generate the fix. Explain what the vulnerability is, why it's exploitable, and why this fix is correct."
  5. Parse LLM response into:
     - Fix code (diff format)
     - Reasoning chain (vulnerability → exploit path → impact → fix rationale)
     - Post-fix test suggestions
  6. Validate fix in sandbox (if available):
     - Run linting
     - Run type checking
     - Run existing test suite
     - Run post-fix exploit validation (PoC must fail)
  7. Store results

Outputs:
  - RemediationProposal (diff, reasoning, test suggestions)
  - ReasoningLog (full LLM conversation)
  - MemoryUpdate (new fix pattern for this team)
```

**Prompt Template:**

```typescript
const REMEDIATION_SYSTEM_PROMPT = `You are Sentinel, an autonomous security engineer.
Your task is to analyze a security finding and generate a minimal, focused fix.

RULES:
1. Generate ONLY the code change needed — no unrelated refactoring
2. The fix must pass the existing test suite
3. The fix must not introduce new vulnerabilities
4. Explain your reasoning in plain language a junior developer can understand
5. If the fix requires architectural changes beyond a simple patch, say so explicitly
6. Include a suggested test case that would catch regression

OUTPUT FORMAT (JSON):
{
  "vulnerability_explanation": "...",
  "exploit_path": "...",
  "business_impact": "...",
  "fix_description": "...",
  "fix_diff": "...",
  "fix_rationale": "...",
  "post_fix_test": "...",
  "requires_architectural_change": false,
  "confidence": 0.95
}`
```

### 5.2 PR Generation Agent

**Purpose:** Take a validated remediation proposal and create a production-ready PR.

```
Inputs:
  - RemediationProposal (from Remediation Agent)
  - Blast Radius analysis
  - PoC artifact (from Exploit Validation)
  - Customer memory (PR style, label conventions, reviewer assignments)
  - Repository metadata (CODEOWNERS, branch protection rules)

Process:
  1. Load team PR conventions from memory
  2. Generate PR title: [SENTINEL] <severity>: <vulnerability description>
  3. Generate PR body with structured sections:
     - Vulnerability Summary
     - Business Impact (from blast radius)
     - Proof of Concept (collapsed)
     - Fix Explanation
     - Post-Fix Validation Results
     - Regulatory Implications (if any)
  4. Apply labels (sentinel-auto, severity:<level>, class:<vuln-class>)
  5. Assign reviewers (from CODEOWNERS)
  6. Create branch, commit fix, open PR via GitHub API
  7. Run post-fix validation in sandbox
  8. Update finding status to 'pr_opened'

Outputs:
  - Pull Request (URL, number)
  - PRRecord (stored in prGeneration table)
  - ReasoningLog
```

### 5.3 Exploit Validation Agent

**Purpose:** Attempt to reproduce a vulnerability in a sandbox to confirm it's real.

```
Inputs:
  - Finding record
  - Source code
  - Sandbox environment descriptor (if available)
  - Historical exploit attempts for this codebase

Process:
  1. Generate exploit payload based on vuln class:
     - SQL injection: craft SQL payloads for the specific query pattern
     - Secret exposure: verify the secret is actually usable
     - Misconfiguration: attempt to exploit the misconfiguration
     - Auth bypass: craft requests that bypass the auth check
     - SSRF: attempt to reach internal services
  2. Execute exploit in sandbox (or simulate if no sandbox)
  3. Classify outcome:
     - Exploited Successfully → generate PoC
     - Partially Exploitable → flag for human review
     - Not Exploitable → discard silently
  4. Generate PoC artifact:
     - HTTP request / curl command
     - Expected output proving exploitation
     - Minimal reproduction script

Outputs:
  - ValidationResult (exploited | partial | not_exploitable)
  - PoCArtifact (code + expected output)
  - ReasoningLog
```

### 5.4 Red Team Agent

**Purpose:** Actively probe the application for vulnerabilities using adversarial strategies.

```
Inputs:
  - Repository metadata (endpoints, tech stack, dependencies)
  - Previous Red Agent memory (attack history, successful strategies)
  - Current findings (to avoid re-testing known issues)
  - Sandbox environment (if available)

Process:
  1. Load attack history from memory
  2. Select strategy using LLM reasoning:
     - "Given what I know about this codebase, what attack vectors are most promising?"
     - Consider: tech stack, framework-specific attacks, dependency risk, auth patterns
  3. Generate attack plan (ordered list of attempts)
  4. Execute attacks (in sandbox or via static analysis)
  5. Evaluate results
  6. Update memory with outcomes

Outputs:
  - New findings (if vulnerabilities discovered)
  - AttackSignatureSet (for Blue Agent)
  - MemoryUpdate (attack knowledge graph)
  - ReasoningLog (full strategy reasoning)
```

### 5.5 Blue Team Agent

**Purpose:** Generate detection rules based on Red Agent findings.

```
Inputs:
  - Red Agent attack signatures
  - Application logs (if available)
  - Existing detection rules
  - Customer memory (detection history)

Process:
  1. Analyze Red Agent's successful attacks
  2. Generate detection rules:
     - WAF rules (ModSecurity, CloudFlare WAF)
     - Log query patterns (Splunk, Elastic)
     - SIEM alert rules
     - Rate limiting rules
  3. Test rules against Red Agent's attack log
  4. Minimize false positive risk

Outputs:
  - DetectionRuleSet (WAF rules, SIEM queries, log patterns)
  - ReasoningLog
```

### 5.6 Blast Radius Reasoning Agent

**Purpose:** Given a vulnerability, reason about the full attack path and business impact.

```
Inputs:
  - Finding (affected component, vuln class)
  - SBOM data (dependency graph)
  - Architecture graph (service dependencies, data flows)
  - Infrastructure config (IAM roles, network segmentation)

Process:
  1. Build attack path using LLM reasoning over the architecture graph:
     - "If an attacker exploits this SQL injection, what can they reach?"
     - Trace: network paths → privilege escalation → data access → lateral movement
  2. Quantify business impact:
     - Data exposure (PII count, sensitivity classification)
     - Regulatory exposure (GDPR fines, HIPAA penalties)
     - Revenue impact (services on critical path)
  3. Generate human-readable attack chain narrative

Outputs:
  - BlastRadiusAnalysis (graph, attack chains, business impact)
  - ReasoningLog
```

### 5.7 Prompt Injection Agent

**Purpose:** Detect and test LLM-related attack surfaces in the codebase.

```
Inputs:
  - Source code (all files)
  - Dependency list (looking for LLM frameworks: LangChain, LlamaIndex, Vercel AI SDK, etc.)

Process:
  1. Scan codebase for LLM API calls (OpenAI, Anthropic, Cohere, Ollama imports)
  2. Map data flow: user input → prompt construction → LLM call → output handling
  3. For each LLM call chain:
     - Generate adversarial payloads (role override, context exfil, tool hijacking)
     - Test payloads against the prompt structure
     - Classify injection resistance
  4. Generate mitigation recommendations

Outputs:
  - PromptInjectionFindings (vulnerable call chains, payloads, severity)
  - MitigationCode (input sanitization, output validation)
  - ReasoningLog
```

### 5.8 Regulatory Drift Agent

**Purpose:** Map regulatory changes to code-level implications.

```
Inputs:
  - Regulatory update text
  - Customer's regulatory profile (jurisdictions, data types, industry)
  - Codebase analysis (data handling patterns)

Process:
  1. Parse regulatory text to extract technical obligations
  2. Map obligations to codebase: which services handle regulated data?
  3. Generate gap analysis: does the codebase currently comply?
  4. For gaps: generate fix plan (code changes + policy changes)

Outputs:
  - RegulatoryGapReport (obligations, gaps, fix plans)
  - ReasoningLog
```

### 5.9 Surface Reduction Agent

**Purpose:** Identify and propose removal of unnecessary attack surface.

```
Inputs:
  - Source code
  - Dependency list
  - Traffic data (if available from observability integrations)
  - IAM configuration (if available)

Process:
  1. Detect dead code (functions defined but never called)
  2. Detect unused dependencies
  3. Detect overly permissive IAM
  4. Detect exposed debug/admin endpoints
  5. Prioritize by risk (what's most likely to be exploited?)
  6. Generate removal PRs

Outputs:
  - SurfaceReductionReport (items found, priority, proposed PRs)
  - ReasoningLog
```

---

## 6. Memory & Learning System

### 6.1 Architecture

The memory system extends the existing `projectMemories`, `memoryPatterns`, `memoryEpisodes`, and `memoryPredictions` tables in `schema.ts`. No new tables needed for the core memory — just new data flowing through them.

```
┌──────────────────────────────────────────────────────┐
│                 MEMORY HIERARCHY                      │
│                                                       │
│  Short-term (active workflow context)                 │
│  ├─ Stored in: agentTask.inputSummary + LLM context  │
│  ├─ TTL: workflow lifetime                            │
│  └─ Access: current agent only                        │
│                                                       │
│  Medium-term (per-run findings, trends)               │
│  ├─ Stored in: memoryEpisodes                         │
│  ├─ TTL: 90 days (configurable per tenant)            │
│  └─ Access: any agent for this repository             │
│                                                       │
│  Long-term (patterns, style, knowledge)               │
│  ├─ Stored in: memoryPatterns + projectMemories       │
│  ├─ TTL: contract lifetime                            │
│  └─ Access: any agent for this tenant                 │
│                                                       │
│  Predictive (what the system expects to find)         │
│  ├─ Stored in: memoryPredictions                      │
│  ├─ TTL: until confirmed/disproved                    │
│  └─ Access: planner agent for prioritization          │
└──────────────────────────────────────────────────────┘
```

### 6.2 What Gets Learned

| Memory Type | Stored In | Updated By | Used By |
|-------------|-----------|------------|---------|
| **Vulnerability patterns** | `memoryPatterns` (type: `recurring_vulnerability`) | Remediation Agent, Red Team Agent | Planner (prioritization), Remediation (context) |
| **Fix patterns** | `memoryPatterns` (type: `recurring_fix`) | PR Generation Agent | Remediation (style matching) |
| **Developer patterns** | `memoryPatterns` (type: `developer_pattern`) | PR Generation Agent | PR Generation (conventions) |
| **False positive signals** | `memoryPatterns` (type: `false_positive_signal`) | Finding triage (user action) | All agents (filter noise) |
| **Attack knowledge** | `memoryPatterns` (type: `code_path_risk`) | Red Team Agent | Red Team (strategy selection) |
| **Temporal patterns** | `memoryPatterns` (type: `temporal_pattern`) | Cron (daily analysis) | Planner (timing) |
| **Dependency risk** | `memoryPatterns` (type: `dependency_risk`) | Supply Chain Agent | Planner (prioritization) |
| **Prediction accuracy** | `memoryPredictions` | Feedback loop | Self-calibration |

### 6.3 Learning Loop

```
Agent produces finding
    │
    ▼
Finding stored in `findings` table
    │
    ▼
User triages finding (true positive / false positive / accepted risk)
    │
    ▼
Feedback recorded in `memoryFeedback`
    │
    ▼
Learning Engine (cron, daily):
    │ 1. Process unprocessed episodes
    │ 2. Update pattern confidence scores
    │ 3. Adjust agent behavior based on feedback
    │ 4. Generate new predictions
    │ 5. Archive stale predictions
    │
    ▼
Next agent run uses updated memory
```

### 6.4 Customer Isolation

- All memory is strictly tenant-scoped via `tenantId` indexes
- No cross-tenant data leakage — queries always filter by `tenantId`
- Global model improvements (vulnerability fingerprints) are aggregated/anonymized
- Memory deleted on tenant deletion (existing cascade behavior)

---

## 7. Reasoning & Audit Trail

### 7.1 Reasoning Log Structure

Every LLM agent call produces a structured reasoning log:

```typescript
agentReasoningLogs: defineTable({
  tenantId: v.id('tenants'),
  agentTaskId: v.id('agentTasks'),
  agentType: v.string(),
  
  // The conversation
  messages: v.array(v.object({
    role: v.union(v.literal('system'), v.literal('user'), v.literal('assistant'), v.literal('tool')),
    content: v.string(),
    timestamp: v.number(),
  })),
  
  // Tool calls made by the agent
  toolCalls: v.array(v.object({
    name: v.string(),
    arguments: v.string(),    // JSON
    result: v.string(),
    timestamp: v.number(),
  })),
  
  // Final structured output
  output: v.any(),            // Agent-specific structured result
  
  // Metadata
  llmProvider: v.string(),
  llmModel: v.string(),
  totalTokens: v.number(),
  totalCostUsd: v.number(),
  latencyMs: v.number(),
  
  // Audit
  createdAt: v.number(),
})
  .index('by_agent_task', ['agentTaskId'])
  .index('by_tenant', ['tenantId'])
  .index('by_agent_type', ['agentType'])
  .index('by_created_at', ['createdAt'])
```

### 7.2 Transparency Principle

Every PR opened by Sentinel includes the full reasoning chain:

```markdown
## Vulnerability Summary
[LLM-generated explanation of what the vulnerability is]

## Exploit Path
[LLM-generated description of how an attacker would exploit this]

## Business Impact
[Blast radius analysis: affected services, data exposure, regulatory risk]

## Proof of Concept
<details>
<summary>Click to expand PoC</summary>
[Exploit code / curl commands]
</details>

## Fix Explanation
[LLM-generated explanation of why this fix works]

## Post-Fix Validation
- ✅ Linting passed
- ✅ Type checking passed
- ✅ Existing tests pass
- ✅ PoC fails on patched code

---
*Generated by Sentinel — autonomous security platform*
*Reasoning log: [link to full audit trail in dashboard]*
```

---

## 8. Sandbox Execution Environment

### 8.1 Phase 1: Static Sandbox (MVP)

For the initial implementation, the "sandbox" is a Convex action that:

1. Creates a temporary directory
2. Clones the repository at the target commit
3. Applies the proposed fix (diff)
4. Runs linting (`bun run lint` or equivalent)
5. Runs type checking (`bun run typecheck` or equivalent)
6. Runs tests (`bun test` or equivalent)
7. Cleans up

This runs in the Convex action runtime (no Docker, no VMs). It's sufficient for:
- Validating that fixes compile
- Validating that fixes pass tests
- Validating that fixes don't break existing functionality

### 8.2 Phase 2: Container Sandbox (Full Validation)

For exploit validation and Red Team operations, a container-based sandbox:

1. **Infrastructure:** A single Docker host (or small K8s cluster) managed by CyberZen
2. **Lifecycle:** Ephemeral containers spun up per validation, destroyed after
3. **Isolation:** Network namespace isolation, resource limits, no egress
4. **Seeding:** Synthetic data (real schema, fake PII)

This enables:
- Running the actual application and attempting exploits
- Red Team agent probing live endpoints
- Post-fix validation (run PoC against patched code)

### 8.3 Phase 3: Production-Grade Sandbox (Enterprise)

Full production-clone sandbox per the spec:
- Kubernetes-based
- Multi-service orchestration
- Network isolation
- Warm pool for fast startup

This is a Phase 3+ concern and not needed for the initial LLM agent launch.

---

## 9. PR Generation Agent (Deep Dive)

This is the most impactful agent — it's the user-facing output that proves Sentinel's value.

### 9.1 Current State (Template-Based)

```typescript
// Current: convex/lib/prGeneration.ts
export function buildPrProposalContent(finding, packages) {
  // Returns static template text
  // No LLM reasoning
  // No code fix generation
  // No blast radius context
}
```

### 9.2 New State (LLM-Powered)

```typescript
// New: convex/agents/prGenerationAgent.ts

export const generatePR = internalAction({
  args: {
    findingId: v.id('findings'),
    remediationProposalId: v.id('remediationProposals'),
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, args) => {
    // 1. Load finding + remediation proposal
    const finding = await ctx.runQuery(internal.agents.data.getFinding, { id: args.findingId })
    const proposal = await ctx.runQuery(internal.agents.data.getProposal, { id: args.remediationProposalId })
    const blastRadius = await ctx.runQuery(internal.agents.data.getBlastRadius, { findingId: args.findingId })
    const memory = await ctx.runQuery(internal.agents.data.getCustomerMemory, { tenantId: args.tenantId })

    // 2. Build PR content using LLM
    const prContent = await callLLM({
      provider: selectProvider({ type: 'code_generation', complexity: 'medium' }),
      systemPrompt: PR_GENERATION_SYSTEM_PROMPT,
      messages: [
        { role: 'user', content: buildPRPrompt(finding, proposal, blastRadius, memory) }
      ],
      responseFormat: 'json',
    })

    // 3. Parse and validate
    const parsed = JSON.parse(prContent.content)

    // 4. Create branch, commit, open PR via GitHub API
    const pr = await createGitHubPR({
      title: parsed.title,
      body: parsed.body,
      branch: `sentinel/fix/${finding._id}`,
      files: proposal.fixFiles,
      labels: parsed.labels,
      assignees: parsed.assignees,
    })

    // 5. Update finding status
    await ctx.runMutation(internal.agents.data.updateFindingStatus, {
      findingId: args.findingId,
      status: 'pr_opened',
      prUrl: pr.url,
    })

    // 6. Write reasoning log
    await ctx.runMutation(internal.agents.data.writeReasoningLog, {
      agentTaskId: args.agentTaskId,
      messages: prContent.messages,
      output: parsed,
      llmProvider: prContent.provider,
      llmModel: prContent.model,
      totalTokens: prContent.usage.totalTokens,
      totalCostUsd: prContent.usage.estimatedCostUsd,
    })

    return { prUrl: pr.url, prNumber: pr.number }
  },
})
```

### 9.3 PR Content Quality Standards

Every PR must:
1. **Title:** `[SENTINEL] <severity>: <concise description>` — max 72 chars
2. **Body sections:** Summary, Impact, PoC (collapsed), Fix, Validation, Regulatory
3. **Code change:** Minimal — only the fix, no unrelated refactoring
4. **Labels:** `sentinel-auto`, `severity:<level>`, `class:<vuln-class>`
5. **Reviewers:** From CODEOWNERS for affected files

---

## 10. Cost Management & Rate Limiting

### 10.1 Per-Tenant Budgets

```typescript
// In tenant settings or plan configuration
{
  monthlyLLMBudgetUsd: number,     // hard cap
  currentMonthSpendUsd: number,    // tracked in real-time
  alertThresholdPercent: number,   // warn at 80%
  autoDisableAtPercent: number,    // stop agents at 100%
}
```

### 10.2 Cost Optimization

| Strategy | Savings | Implementation |
|----------|---------|----------------|
| **Model tiering** | 60-80% | Use `gpt-4o-mini` for classification, `gpt-4o` for reasoning |
| **Prompt caching** | 30-50% | Cache system prompts + static context (Anthropic prompt caching) |
| **Batch processing** | 20-30% | Group similar findings into single LLM calls |
| **Local models** | 100% | Use Ollama for non-critical tasks in dev/enterprise |
| **Response streaming** | 0% (UX) | Stream long responses for better perceived performance |

### 10.3 Rate Limiting

```typescript
// convex/lib/llmRateLimit.ts
export class RateLimiter {
  // Per-provider rate limits (respect provider limits)
  // Per-tenant rate limits (prevent abuse)
  // Global rate limits (control total spend)
  
  async checkLimit(tenantId: string, provider: string): Promise<{ allowed: boolean; retryAfterMs?: number }> {
    // Check: tenant budget, provider rate limit, global budget
  }
}
```

---

## 11. Schema Changes

### 11.1 New Tables

```typescript
// Add to convex/schema.ts

// Agent task tracking
agentTasks: defineTable({
  // ... (see §4.4 for full schema)
})
  .index('by_tenant', ['tenantId'])
  .index('by_repository', ['repositoryId'])
  .index('by_status', ['status'])
  .index('by_workflow_run', ['workflowRunId'])
  .index('by_finding', ['findingId'])
  .index('by_agent_type', ['agentType'])
  .index('by_tenant_and_status', ['tenantId', 'status'])

// Reasoning audit trail
agentReasoningLogs: defineTable({
  // ... (see §7.1 for full schema)
})
  .index('by_agent_task', ['agentTaskId'])
  .index('by_tenant', ['tenantId'])
  .index('by_agent_type', ['agentType'])
  .index('by_created_at', ['createdAt'])

// LLM usage tracking
llmUsageRecords: defineTable({
  tenantId: v.id('tenants'),
  agentType: v.string(),
  provider: v.string(),
  model: v.string(),
  promptTokens: v.number(),
  completionTokens: v.number(),
  estimatedCostUsd: v.number(),
  taskId: v.string(),
  timestamp: v.number(),
})
  .index('by_tenant', ['tenantId'])
  .index('by_tenant_and_timestamp', ['tenantId', 'timestamp'])
  .index('by_provider', ['provider'])

// Remediation proposals (LLM-generated)
remediationProposals: defineTable({
  findingId: v.id('findings'),
  tenantId: v.id('tenants'),
  repositoryId: v.id('repositories'),
  agentTaskId: v.id('agentTasks'),
  status: v.union(
    v.literal('proposed'),
    v.literal('validated'),
    v.literal('pr_opened'),
    v.literal('rejected'),
    v.literal('superseded'),
  ),
  vulnerabilityExplanation: v.string(),
  exploitPath: v.string(),
  businessImpact: v.string(),
  fixDescription: v.string(),
  fixDiff: v.string(),
  fixRationale: v.string(),
  postFixTest: v.string(),
  requiresArchitecturalChange: v.boolean(),
  confidence: v.number(),
  validationResults: v.optional(v.object({
    lintPassed: v.boolean(),
    typecheckPassed: v.boolean(),
    testsPassed: v.boolean(),
    exploitFailedOnPatch: v.boolean(),
  })),
  prUrl: v.optional(v.string()),
  createdAt: v.number(),
  updatedAt: v.number(),
})
  .index('by_finding', ['findingId'])
  .index('by_tenant', ['tenantId'])
  .index('by_status', ['status'])
  .index('by_repository', ['repositoryId'])

// Exploit validation results
exploitValidationResults: defineTable({
  findingId: v.id('findings'),
  tenantId: v.id('tenants'),
  agentTaskId: v.id('agentTasks'),
  outcome: v.union(
    v.literal('exploited'),
    v.literal('partial'),
    v.literal('not_exploitable'),
  ),
  pocCode: v.string(),
  pocExpectedOutput: v.string(),
  pocType: v.union(v.literal('curl'), v.literal('python'), v.literal('javascript')),
  executionLog: v.string(),
  confidence: v.number(),
  createdAt: v.number(),
})
  .index('by_finding', ['findingId'])
  .index('by_tenant', ['tenantId'])
  .index('by_outcome', ['outcome'])

// Red Team attack history
redTeamAttacks: defineTable({
  tenantId: v.id('tenants'),
  repositoryId: v.id('repositories'),
  roundNumber: v.number(),
  strategy: v.string(),
  attackVector: v.string(),
  targetEndpoint: v.optional(v.string()),
  payload: v.string(),
  outcome: v.union(v.literal('success'), v.literal('partial'), v.literal('failure')),
  evidence: v.optional(v.string()),
  newFindingId: v.optional(v.id('findings')),
  agentTaskId: v.id('agentTasks'),
  createdAt: v.number(),
})
  .index('by_tenant', ['tenantId'])
  .index('by_repository', ['repositoryId'])
  .index('by_round', ['roundNumber'])
  .index('by_outcome', ['outcome'])

// Blue Team detection rules
blueTeamDetectionRules: defineTable({
  tenantId: v.id('tenants'),
  repositoryId: v.id('repositories'),
  ruleType: v.union(v.literal('waf'), v.literal('siem'), v.literal('log_query'), v.literal('rate_limit')),
  ruleName: v.string(),
  ruleContent: v.string(),     // actual rule code (ModSecurity, Splunk SPL, etc.)
  basedOnAttackId: v.optional(v.id('redTeamAttacks')),
  effectiveness: v.optional(v.number()), // 0-1, how well it detects
  falsePositiveRisk: v.number(),         // 0-1
  agentTaskId: v.id('agentTasks'),
  createdAt: v.number(),
})
  .index('by_tenant', ['tenantId'])
  .index('by_repository', ['repositoryId'])
  .index('by_rule_type', ['ruleType'])
```

### 11.2 Modified Tables

```typescript
// Extend findings table
findings: defineTable({
  // ... existing fields ...
  
  // New LLM agent fields
  agentAnalysisId: v.optional(v.id('agentTasks')),
  remediationProposalId: v.optional(v.id('remediationProposals')),
  exploitValidationId: v.optional(v.id('exploitValidationResults')),
  llmConfidence: v.optional(v.number()),  // agent's confidence in this finding
  reasoningLogUrl: v.optional(v.string()),
})

// Extend tenants table
tenants: defineTable({
  // ... existing fields ...
  
  // LLM configuration
  llmConfig: v.optional(v.object({
    preferredProvider: v.optional(v.string()),
    monthlyBudgetUsd: v.number(),
    autoRemediationEnabled: v.boolean(),
    autoPrEnabled: v.boolean(),
    redTeamEnabled: v.boolean(),
  })),
})
```

---

## 12. Implementation Phases

### Phase 1: Foundation (Weeks 1-3)

**Goal:** LLM provider layer + Remediation Agent + PR Generation Agent

| Task | Effort | Priority |
|------|--------|----------|
| `convex/lib/llmClient.ts` — unified provider interface | 2 days | P0 |
| `convex/lib/llmRetry.ts` — retry + circuit breaker | 1 day | P0 |
| `convex/lib/llmRouter.ts` — model selection strategy | 1 day | P0 |
| Schema additions: `agentTasks`, `agentReasoningLogs`, `llmUsageRecords`, `remediationProposals` | 1 day | P0 |
| `convex/agents/remediationAgent.ts` — LLM-powered fix generation | 3 days | P0 |
| `convex/agents/prGenerationAgent.ts` — LLM-powered PR creation | 2 days | P0 |
| `convex/agentOrchestrator.ts` — task routing + lifecycle | 2 days | P0 |
| Wire into existing workflow engine (`events.ts`) | 1 day | P0 |
| Frontend: Agent task viewer + reasoning log viewer | 2 days | P0 |
| Testing + validation | 2 days | P0 |

**Deliverable:** When a finding is detected, the system generates an LLM-powered fix, validates it, and opens a PR with a full reasoning chain.

### Phase 2: Intelligence (Weeks 4-6)

**Goal:** Exploit Validation Agent + Blast Radius Agent + Memory learning loop

| Task | Effort | Priority |
|------|--------|----------|
| Schema additions: `exploitValidationResults` | 0.5 day | P0 |
| `convex/agents/exploitValidationAgent.ts` — PoC generation + validation | 3 days | P0 |
| `convex/agents/blastRadiusAgent.ts` — LLM reasoning over architecture | 2 days | P1 |
| Memory learning loop (daily cron processing episodes → patterns) | 2 days | P1 |
| Frontend: Exploit validation viewer + blast radius reasoning | 2 days | P1 |
| Static sandbox (lint + typecheck + test in action runtime) | 2 days | P0 |

**Deliverable:** Every finding is validated before alerting. Blast radius is reasoned about, not just computed. The system learns from feedback.

### Phase 3: Adversarial (Weeks 7-10)

**Goal:** Red Team Agent + Blue Team Agent + Prompt Injection Agent

| Task | Effort | Priority |
|------|--------|----------|
| Schema additions: `redTeamAttacks`, `blueTeamDetectionRules` | 0.5 day | P1 |
| `convex/agents/redTeamAgent.ts` — adversarial attack generation | 4 days | P1 |
| `convex/agents/blueTeamAgent.ts` — detection rule generation | 3 days | P1 |
| `convex/agents/promptInjectionAgent.ts` — LLM call chain analysis | 3 days | P1 |
| Red-Blue adversarial loop (cron-based rounds) | 2 days | P1 |
| Frontend: Red/Blue round viewer + detection rule manager | 2 days | P1 |

**Deliverable:** The system actively probes for vulnerabilities and generates detection rules. The Red/Blue adversarial loop runs continuously.

### Phase 4: Autonomy (Weeks 11-14)

**Goal:** Surface Reduction Agent + Regulatory Drift Agent + Container sandbox

| Task | Effort | Priority |
|------|--------|----------|
| `convex/agents/surfaceReductionAgent.ts` — dead code + unused deps | 3 days | P2 |
| `convex/agents/regulatoryDriftAgent.ts` — regulatory → code mapping | 3 days | P2 |
| Container sandbox infrastructure (Docker-based exploit validation) | 5 days | P1 |
| Cost optimization (prompt caching, batch processing) | 2 days | P1 |
| Per-tenant LLM budget management UI | 2 days | P1 |

**Deliverable:** Full autonomous security agent suite. Container-based exploit validation. Cost-managed LLM usage.

---

## 13. Risk & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **LLM generates incorrect fix** | PR breaks production | Sandbox validation (lint + test + exploit must fail on patch). Human review required before merge. |
| **LLM hallucinates vulnerability** | False positive alert | Exploit-first validation — never alert on unvalidated findings. Confidence threshold. |
| **LLM cost spirals** | Budget overrun | Per-tenant budgets, rate limiting, model tiering, cost tracking dashboard. |
| **Provider outage** | Agent system down | Multi-provider fallback (OpenAI → Anthropic → local). Circuit breaker. Graceful degradation to template-based. |
| **Customer code sent to LLM** | Privacy concern | Configurable: use cloud LLM (encrypted), local LLM (Ollama), or disable LLM features entirely. Never used for training. |
| **Agent reasoning log contains secrets** | Data leak in audit trail | PII/secret masking in reasoning logs (extend existing `piiMasker.ts`). |
| **Red Team agent causes damage** | Service disruption | All Red Team activity in sandboxed environment only. No production access. Rate-limited. |
| **Convex action timeout** | Long LLM calls fail | Chunk long analyses into multiple action calls. Use streaming where supported. Set 60s timeout per call. |

---

## Appendix A: Environment Variables

```bash
# LLM Providers (at least one required)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
OLLAMA_BASE_URL=http://localhost:11434
CUSTOM_LLM_BASE_URL=https://your-endpoint.com/v1
CUSTOM_LLM_API_KEY=...

# LLM Configuration
LLM_DEFAULT_PROVIDER=openai          # openai | anthropic | ollama | custom
LLM_MONTHLY_BUDGET_USD=1000          # global default budget per tenant
LLM_ENABLE_LOCAL_FALLBACK=true       # fall back to Ollama if cloud fails

# Sandbox (Phase 2+)
SANDBOX_DOCKER_HOST=...              # Docker host for container sandbox
SANDBOX_NETWORK_ISOLATION=true       # enable network namespace isolation
```

## Appendix B: File Structure

```
apps/web/convex/
├── lib/
│   ├── llmClient.ts              # Unified LLM provider interface
│   ├── llmRetry.ts               # Retry + circuit breaker
│   ├── llmRouter.ts              # Model selection strategy
│   ├── llmRateLimit.ts           # Per-tenant rate limiting
│   └── llmCostTracker.ts         # Usage aggregation + budget enforcement
├── agents/
│   ├── remediationAgent.ts       # Fix generation
│   ├── prGenerationAgent.ts      # PR creation with reasoning
│   ├── exploitValidationAgent.ts # PoC generation + validation
│   ├── blastRadiusAgent.ts       # Attack path reasoning
│   ├── redTeamAgent.ts           # Adversarial attack generation
│   ├── blueTeamAgent.ts          # Detection rule generation
│   ├── promptInjectionAgent.ts   # LLM call chain analysis
│   ├── surfaceReductionAgent.ts  # Dead code + unused deps
│   ├── regulatoryDriftAgent.ts   # Regulatory → code mapping
│   └── data.ts                   # Shared data access helpers for agents
├── agentOrchestrator.ts          # Task routing + lifecycle management
└── agentCrons.ts                 # Scheduled agent tasks (Red-Blue rounds, learning)
```
