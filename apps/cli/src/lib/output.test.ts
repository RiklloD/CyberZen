import { describe, expect, test } from 'bun:test'
import { render } from './output'

function capture(fn: () => void): string {
  const original = process.stdout.write
  let output = ''
  process.stdout.write = ((chunk: string | Uint8Array) => {
    output += String(chunk)
    return true
  }) as typeof process.stdout.write
  try {
    fn()
    return output
  } finally {
    process.stdout.write = original
  }
}

describe('output renderer', () => {
  test('renders JSON exactly as machine-readable output', () => {
    const output = capture(() => render({ id: 1, status: 'open' }, { json: true }))
    expect(JSON.parse(output)).toEqual({ id: 1, status: 'open' })
  })

  test('renders arrays as NDJSON', () => {
    const output = capture(() => render([{ id: 1 }, { id: 2 }], { json: true, ndjson: true }))
    expect(output).toBe('{"id":1}\n{"id":2}\n')
  })

  test('renders a table without ANSI color when disabled', () => {
    const output = capture(() => render([{ id: 1, status: 'open' }], { color: false }))
    expect(output).toContain('id  status')
    expect(output).toContain('1   open')
    expect(output).not.toContain('\x1b[')
  })

  test('renders empty arrays explicitly', () => {
    expect(capture(() => render([], { color: false }))).toBe('No results.\n')
  })
})
