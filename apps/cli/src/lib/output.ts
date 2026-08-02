import type { GlobalFlags } from './globalFlags'

export interface RenderOptions extends Partial<GlobalFlags> {
  columns?: string[]
}

/** Render command data without contaminating stdout with diagnostics. */
export function render(data: unknown, options: RenderOptions = {}): void {
  if (options.json || process.env.CYBERZEN_OUTPUT === 'json') {
    if (options.ndjson && Array.isArray(data)) {
      process.stdout.write(`${data.map((item) => JSON.stringify(item)).join('\n')}\n`)
      return
    }
    process.stdout.write(`${JSON.stringify(data, null, 2)}\n`)
    return
  }

  if (data === null || data === undefined) return
  if (Array.isArray(data)) {
    renderTable(data, options.columns, options.color !== false)
    return
  }
  if (isRecord(data)) {
    renderKeyValue(data, options.color !== false)
    return
  }
  process.stdout.write(`${String(data)}\n`)
}

export function renderKeyValue(value: Record<string, unknown>, color = true): void {
  const rows = Object.entries(value).map(([key, item]) => [key, formatValue(item)] as const)
  const width = Math.max(0, ...rows.map(([key]) => key.length))
  for (const [key, item] of rows) {
    const label = color ? `\x1b[36m${key.padEnd(width)}\x1b[0m` : key.padEnd(width)
    process.stdout.write(`${label}  ${item}\n`)
  }
}

export function renderTable(
  values: unknown[],
  requestedColumns?: string[],
  color = true,
): void {
  if (values.length === 0) {
    process.stdout.write('No results.\n')
    return
  }
  const records = values.filter(isRecord)
  if (records.length !== values.length) {
    for (const value of values) process.stdout.write(`${formatValue(value)}\n`)
    return
  }

  const columns = requestedColumns?.length
    ? requestedColumns
    : [...new Set(records.flatMap((record) => Object.keys(record)))]
  const rows = records.map((record) => columns.map((column) => formatValue(record[column])))
  const widths = columns.map((column, index) =>
    Math.max(column.length, ...rows.map((row) => row[index]?.length ?? 0)),
  )
  const header = columns.map((column, index) => column.padEnd(widths[index] ?? column.length)).join('  ')
  const rule = widths.map((width) => '-'.repeat(width)).join('  ')
  process.stdout.write(`${color ? `\x1b[1m${header}\x1b[0m` : header}\n${rule}\n`)
  for (const row of rows) process.stdout.write(`${row.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join('  ')}\n`)
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
