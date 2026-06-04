export type SnapshotComponentForDiff = {
  ecosystem: string
  name: string
  version: string
  layer: string
  sourceFile: string
  hasKnownVulnerabilities?: boolean
}

export type SnapshotDiffEntry = {
  ecosystem: string
  name: string
  layer: string
  sourceFile: string
  version: string
}

export type SnapshotVersionChangeEntry = {
  ecosystem: string
  name: string
  layer: string
  sourceFile: string
  previousVersion: string
  nextVersion: string
}

export type SnapshotComparison = {
  addedCount: number
  removedCount: number
  updatedCount: number
  changedComponentCount: number
  vulnerableComponentDelta: number
  added: SnapshotDiffEntry[]
  removed: SnapshotDiffEntry[]
  updated: SnapshotVersionChangeEntry[]
}

function componentKey(component: SnapshotComponentForDiff) {
  return [
    component.ecosystem,
    component.name,
    component.layer,
    component.sourceFile,
  ].join('::')
}

function countVulnerableComponents(components: SnapshotComponentForDiff[]) {
  return components.filter((component) => component.hasKnownVulnerabilities).length
}

export function compareSnapshotComponents(
  previousComponents: SnapshotComponentForDiff[],
  nextComponents: SnapshotComponentForDiff[],
): SnapshotComparison {
  const previousByKey = new Map(
    previousComponents.map((component) => [componentKey(component), component]),
  )
  const nextByKey = new Map(
    nextComponents.map((component) => [componentKey(component), component]),
  )

  const added: SnapshotDiffEntry[] = []
  const removed: SnapshotDiffEntry[] = []
  const updated: SnapshotVersionChangeEntry[] = []

  for (const [key, nextComponent] of nextByKey) {
    const previousComponent = previousByKey.get(key)
    if (!previousComponent) {
      added.push({
        ecosystem: nextComponent.ecosystem,
        name: nextComponent.name,
        layer: nextComponent.layer,
        sourceFile: nextComponent.sourceFile,
        version: nextComponent.version,
      })
      continue
    }

    if (previousComponent.version !== nextComponent.version) {
      updated.push({
        ecosystem: nextComponent.ecosystem,
        name: nextComponent.name,
        layer: nextComponent.layer,
        sourceFile: nextComponent.sourceFile,
        previousVersion: previousComponent.version,
        nextVersion: nextComponent.version,
      })
    }
  }

  for (const [key, previousComponent] of previousByKey) {
    if (nextByKey.has(key)) {
      continue
    }

    removed.push({
      ecosystem: previousComponent.ecosystem,
      name: previousComponent.name,
      layer: previousComponent.layer,
      sourceFile: previousComponent.sourceFile,
      version: previousComponent.version,
    })
  }

  const sortKey = (value: { ecosystem: string; name: string; sourceFile: string }) =>
    `${value.ecosystem}:${value.name}:${value.sourceFile}`

  added.sort((left, right) => sortKey(left).localeCompare(sortKey(right)))
  removed.sort((left, right) => sortKey(left).localeCompare(sortKey(right)))
  updated.sort((left, right) => sortKey(left).localeCompare(sortKey(right)))

  return {
    addedCount: added.length,
    removedCount: removed.length,
    updatedCount: updated.length,
    changedComponentCount: added.length + removed.length + updated.length,
    vulnerableComponentDelta:
      countVulnerableComponents(nextComponents) -
      countVulnerableComponents(previousComponents),
    added,
    removed,
    updated,
  }
}
