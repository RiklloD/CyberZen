import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityRank(s: string): number {
  const ranks: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    informational: 0,
  }
  return ranks[s] ?? 0
}

const attackPathResult = v.object({
  graph: v.string(),
  blastRadius: v.number(),
  chokePoints: v.array(v.string()),
  reachableTargets: v.array(v.string()),
  computedAt: v.number(),
})

// ---------------------------------------------------------------------------
// buildDependencyGraph — constructs directed graph from SBOM + finding data
// ---------------------------------------------------------------------------

export const buildDependencyGraph = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    // Latest SBOM snapshot
    const sbomSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    const components = sbomSnapshot
      ? await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) => q.eq('snapshotId', sbomSnapshot._id))
          .take(200)
      : []

    // Open findings for this repository
    const findings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'open'),
      )
      .take(100)

    type GraphNode = {
      id: string
      type: 'package' | 'service' | 'data_store'
      label: string
      version?: string
      ecosystem?: string
      vulnerabilityCount: number
      severity?: string
      isDirect?: boolean
    }
    type GraphEdge = { from: string; to: string; type: 'dependency' | 'data_flow' }

    const nodes: GraphNode[] = []
    const edges: GraphEdge[] = []
    const nodeSet = new Set<string>()

    // Map vulnerable packages to their worst severity
    const vulnPackages = new Map<string, string>()
    for (const f of findings) {
      for (const pkg of f.affectedPackages) {
        const current = vulnPackages.get(pkg)
        if (!current || severityRank(f.severity) > severityRank(current)) {
          vulnPackages.set(pkg, f.severity)
        }
      }
    }

    // Build nodes from SBOM components
    for (const comp of components) {
      const nodeId = `${comp.name}@${comp.version}`
      if (!nodeSet.has(nodeId)) {
        nodeSet.add(nodeId)
        nodes.push({
          id: nodeId,
          type: comp.layer === 'service' ? 'service' : 'package',
          label: comp.name,
          version: comp.version,
          ecosystem: comp.ecosystem,
          vulnerabilityCount: vulnPackages.has(comp.name) ? 1 : 0,
          severity: vulnPackages.get(comp.name),
          isDirect: comp.isDirect,
        })
      }
    }

    // Fall back to synthesizing nodes from finding packages when no SBOM data
    if (nodes.length === 0) {
      const allPkgs = new Set<string>()
      for (const f of findings) {
        for (const pkg of f.affectedPackages) allPkgs.add(pkg)
      }
      for (const pkg of allPkgs) {
        nodes.push({
          id: pkg,
          type: 'package',
          label: pkg,
          vulnerabilityCount: 1,
          severity: vulnPackages.get(pkg),
        })
      }
    }

    // Build edges: direct deps connect to transitive deps within the same ecosystem
    const byEcosystem = new Map<string, string[]>()
    for (const node of nodes) {
      if (node.ecosystem) {
        const arr = byEcosystem.get(node.ecosystem) ?? []
        arr.push(node.id)
        byEcosystem.set(node.ecosystem, arr)
      }
    }

    for (const ids of byEcosystem.values()) {
      // Direct deps connect forward in the list (simulates transitive chain)
      const directs = ids.filter((id) => {
        const n = nodes.find((x) => x.id === id)
        return n?.isDirect === true
      })
      const transitives = ids.filter((id) => !directs.includes(id))

      for (const d of directs) {
        for (const t of transitives.slice(0, 5)) {
          edges.push({ from: d, to: t, type: 'dependency' })
        }
      }

      // Chain transitives among themselves
      for (let i = 0; i < transitives.length - 1 && i < 8; i++) {
        edges.push({ from: transitives[i], to: transitives[i + 1], type: 'dependency' })
      }
    }

    const sensitiveTargets = nodes
      .filter((n) => n.type === 'service' || n.type === 'data_store')
      .map((n) => n.id)

    const graph = JSON.stringify({ nodes, edges })

    const existing = await ctx.db
      .query('attackPaths')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .filter((q) => q.eq(q.field('findingId'), undefined))
      .first()

    const data = {
      tenantId: repo.tenantId,
      repositoryId: args.repositoryId,
      graph,
      blastRadius: 0,
      chokePoints: [] as string[],
      reachableTargets: sensitiveTargets.slice(0, 10),
      computedAt: Date.now(),
    }

    if (existing) {
      await ctx.db.patch(existing._id, data)
      return existing._id
    }
    return ctx.db.insert('attackPaths', data)
  },
})

// ---------------------------------------------------------------------------
// computeAttackPaths — BFS from vulnerable component to sensitive assets
// ---------------------------------------------------------------------------

export const computeAttackPaths = mutation({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error('Finding not found')

    const repo = await ctx.db.get(finding.repositoryId)
    if (!repo) throw new Error('Repository not found')

    type GraphData = {
      nodes: Array<{
        id: string
        type: string
        label: string
        vulnerabilityCount: number
      }>
      edges: Array<{ from: string; to: string; type: string }>
    }

    const baseGraph = await ctx.db
      .query('attackPaths')
      .withIndex('by_repository', (q) =>
        q.eq('repositoryId', finding.repositoryId),
      )
      .filter((q) => q.eq(q.field('findingId'), undefined))
      .first()

    const graphData: GraphData = baseGraph
      ? (JSON.parse(baseGraph.graph) as GraphData)
      : { nodes: [], edges: [] }

    // Build adjacency list for BFS
    const adjacency = new Map<string, string[]>()
    for (const edge of graphData.edges) {
      const neighbors = adjacency.get(edge.from) ?? []
      neighbors.push(edge.to)
      adjacency.set(edge.from, neighbors)
    }

    // Start nodes: vulnerable packages from this finding
    const startNodes = finding.affectedPackages.filter((pkg) =>
      graphData.nodes.some((n) => n.id === pkg || n.label === pkg),
    )
    if (startNodes.length === 0 && finding.affectedPackages.length > 0) {
      startNodes.push(...finding.affectedPackages)
    }

    // BFS up to 5 hops
    const visited = new Set<string>(startNodes)
    let frontier = [...startNodes]
    const reachable: string[] = []

    for (let hop = 0; hop < 5 && frontier.length > 0; hop++) {
      const next: string[] = []
      for (const node of frontier) {
        for (const neighbor of adjacency.get(node) ?? []) {
          if (!visited.has(neighbor)) {
            visited.add(neighbor)
            reachable.push(neighbor)
            next.push(neighbor)
          }
        }
      }
      frontier = next
    }

    const reachableSet = new Set(reachable)

    // Chokepoints: nodes with ≥2 reachable neighbors
    const chokePoints: string[] = []
    for (const node of graphData.nodes) {
      const outgoing = adjacency.get(node.id) ?? []
      if (outgoing.filter((n) => reachableSet.has(n)).length >= 2) {
        chokePoints.push(node.label)
      }
    }

    // Sensitive targets among reachable nodes
    const sensitiveTargets = graphData.nodes
      .filter(
        (n) =>
          (n.type === 'service' || n.type === 'data_store') && reachableSet.has(n.id),
      )
      .map((n) => n.label)

    // Blast radius = severity base + reachability + sensitive exposure
    const severityBase =
      ({ critical: 40, high: 30, medium: 20, low: 10, informational: 0 } as Record<
        string,
        number
      >)[finding.severity] ?? 20
    const reachabilityScore = Math.min(
      40,
      Math.round((reachable.length / Math.max(graphData.nodes.length, 1)) * 40),
    )
    const sensitivityScore = Math.min(20, sensitiveTargets.length * 5)
    const blastRadius = severityBase + reachabilityScore + sensitivityScore

    const existing = await ctx.db
      .query('attackPaths')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .first()

    const data = {
      tenantId: repo.tenantId,
      repositoryId: finding.repositoryId,
      findingId: args.findingId,
      graph: baseGraph?.graph ?? JSON.stringify({ nodes: [], edges: [] }),
      blastRadius,
      chokePoints: chokePoints.slice(0, 5),
      reachableTargets: [
        ...sensitiveTargets,
        ...reachable.slice(0, 5 - sensitiveTargets.length),
      ].slice(0, 10),
      computedAt: Date.now(),
    }

    if (existing) {
      await ctx.db.patch(existing._id, data)
      return existing._id
    }
    return ctx.db.insert('attackPaths', data)
  },
})

// ---------------------------------------------------------------------------
// Internal variant for cron/scheduler use
// ---------------------------------------------------------------------------

export const computeAttackPathsInternal = internalMutation({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) return

    const repo = await ctx.db.get(finding.repositoryId)
    if (!repo) return

    type GraphData = {
      nodes: Array<{ id: string; type: string; label: string; vulnerabilityCount: number }>
      edges: Array<{ from: string; to: string; type: string }>
    }

    const baseGraph = await ctx.db
      .query('attackPaths')
      .withIndex('by_repository', (q) =>
        q.eq('repositoryId', finding.repositoryId),
      )
      .filter((q) => q.eq(q.field('findingId'), undefined))
      .first()

    const graphData: GraphData = baseGraph
      ? (JSON.parse(baseGraph.graph) as GraphData)
      : { nodes: [], edges: [] }

    const adjacency = new Map<string, string[]>()
    for (const edge of graphData.edges) {
      const neighbors = adjacency.get(edge.from) ?? []
      neighbors.push(edge.to)
      adjacency.set(edge.from, neighbors)
    }

    const startNodes = finding.affectedPackages.filter((pkg) =>
      graphData.nodes.some((n) => n.id === pkg || n.label === pkg),
    )
    if (startNodes.length === 0 && finding.affectedPackages.length > 0) {
      startNodes.push(...finding.affectedPackages)
    }

    const visited = new Set<string>(startNodes)
    let frontier = [...startNodes]
    const reachable: string[] = []

    for (let hop = 0; hop < 5 && frontier.length > 0; hop++) {
      const next: string[] = []
      for (const node of frontier) {
        for (const neighbor of adjacency.get(node) ?? []) {
          if (!visited.has(neighbor)) {
            visited.add(neighbor)
            reachable.push(neighbor)
            next.push(neighbor)
          }
        }
      }
      frontier = next
    }

    const reachableSet = new Set(reachable)
    const chokePoints: string[] = []
    for (const node of graphData.nodes) {
      const outgoing = adjacency.get(node.id) ?? []
      if (outgoing.filter((n) => reachableSet.has(n)).length >= 2) {
        chokePoints.push(node.label)
      }
    }

    const sensitiveTargets = graphData.nodes
      .filter(
        (n) =>
          (n.type === 'service' || n.type === 'data_store') && reachableSet.has(n.id),
      )
      .map((n) => n.label)

    const severityBase =
      ({ critical: 40, high: 30, medium: 20, low: 10, informational: 0 } as Record<
        string,
        number
      >)[finding.severity] ?? 20
    const reachabilityScore = Math.min(
      40,
      Math.round((reachable.length / Math.max(graphData.nodes.length, 1)) * 40),
    )
    const sensitivityScore = Math.min(20, sensitiveTargets.length * 5)
    const blastRadius = severityBase + reachabilityScore + sensitivityScore

    const existing = await ctx.db
      .query('attackPaths')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .first()

    const data = {
      tenantId: repo.tenantId,
      repositoryId: finding.repositoryId,
      findingId: args.findingId,
      graph: baseGraph?.graph ?? JSON.stringify({ nodes: [], edges: [] }),
      blastRadius,
      chokePoints: chokePoints.slice(0, 5),
      reachableTargets: [
        ...sensitiveTargets,
        ...reachable.slice(0, 5 - sensitiveTargets.length),
      ].slice(0, 10),
      computedAt: Date.now(),
    }

    if (existing) {
      await ctx.db.patch(existing._id, data)
    } else {
      await ctx.db.insert('attackPaths', data)
    }
  },
})

// ---------------------------------------------------------------------------
// getAttackPathVisualization — full graph for a repository (frontend render)
// ---------------------------------------------------------------------------

export const getAttackPathVisualization = query({
  args: { repositoryId: v.id('repositories') },
  returns: v.union(v.null(), attackPathResult),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query('attackPaths')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .filter((q) => q.eq(q.field('findingId'), undefined))
      .first()

    if (!record) return null
    return {
      graph: record.graph,
      blastRadius: record.blastRadius,
      chokePoints: record.chokePoints,
      reachableTargets: record.reachableTargets,
      computedAt: record.computedAt,
    }
  },
})

// ---------------------------------------------------------------------------
// getAttackPathForFinding — attack path data for a specific finding
// ---------------------------------------------------------------------------

export const getAttackPathForFinding = query({
  args: { findingId: v.id('findings') },
  returns: v.union(v.null(), attackPathResult),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query('attackPaths')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .first()

    if (!record) return null
    return {
      graph: record.graph,
      blastRadius: record.blastRadius,
      chokePoints: record.chokePoints,
      reachableTargets: record.reachableTargets,
      computedAt: record.computedAt,
    }
  },
})

// ---------------------------------------------------------------------------
// getCriticalPaths — top 10 highest blast-radius paths across a tenant
// ---------------------------------------------------------------------------

export const getCriticalPaths = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('attackPaths'),
      findingId: v.optional(v.id('findings')),
      repositoryId: v.id('repositories'),
      blastRadius: v.number(),
      chokePoints: v.array(v.string()),
      reachableTargets: v.array(v.string()),
      computedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    const records = await ctx.db
      .query('attackPaths')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .filter((q) => q.neq(q.field('findingId'), undefined))
      .order('desc')
      .take(50)

    return records
      .sort((a, b) => b.blastRadius - a.blastRadius)
      .slice(0, 10)
      .map((r) => ({
        _id: r._id,
        findingId: r.findingId,
        repositoryId: r.repositoryId,
        blastRadius: r.blastRadius,
        chokePoints: r.chokePoints,
        reachableTargets: r.reachableTargets,
        computedAt: r.computedAt,
      }))
  },
})
