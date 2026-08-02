import type { GlobalFlags } from "./globalFlags.js";

export interface RenderOptions
	extends Pick<GlobalFlags, "json" | "ndjson" | "color"> {
	columns?: string[];
}

function stringify(value: unknown): string {
	return JSON.stringify(value, (_key, item) =>
		typeof item === "bigint" ? item.toString() : item,
	);
}

function cell(value: unknown): string {
	if (value === null || value === undefined) return "";
	if (typeof value === "object") return stringify(value);
	return String(value);
}

function flattenRows(data: unknown): Record<string, unknown>[] {
	if (Array.isArray(data))
		return data.map((item) =>
			item && typeof item === "object"
				? (item as Record<string, unknown>)
				: { value: item },
		);
	if (data && typeof data === "object")
		return [data as Record<string, unknown>];
	return [{ value: data }];
}

function table(data: unknown, options: RenderOptions): string {
	const rows = flattenRows(data);
	const keys = options.columns?.length
		? options.columns
		: [...new Set(rows.flatMap((row) => Object.keys(row)))];
	if (keys.length === 0) return "";

	const values = rows.map((row) => keys.map((key) => cell(row[key])));
	const widths = keys.map((key, index) =>
		Math.max(key.length, ...values.map((row) => row[index]?.length ?? 0)),
	);
	const header = keys
		.map((key, index) => key.padEnd(widths[index] ?? key.length))
		.join("  ");
	const divider = widths.map((width) => "-".repeat(width)).join("  ");
	const body = values
		.map((row) =>
			row
				.map((value, index) => value.padEnd(widths[index] ?? value.length))
				.join("  "),
		)
		.join("\n");
	return `${header}\n${divider}${body ? `\n${body}` : ""}`;
}

/** Render command data. Data goes to stdout; diagnostics belong on stderr. */
export function render(data: unknown, options: RenderOptions): void {
	if (options.json) {
		if (options.ndjson && Array.isArray(data)) {
			process.stdout.write(`${data.map(stringify).join("\n")}\n`);
		} else {
			process.stdout.write(`${stringify(data)}\n`);
		}
		return;
	}
	process.stdout.write(`${table(data, options)}\n`);
}

export function renderKeyValue(
	data: Record<string, unknown>,
	options: RenderOptions,
): void {
	if (options.json) {
		render(data, options);
		return;
	}
	const lines = Object.entries(data).map(
		([key, value]) => `${key}: ${cell(value)}`,
	);
	process.stdout.write(`${lines.join("\n")}\n`);
}
