import { describe, expect, test } from "bun:test";
import { render } from "./output.js";

describe("output renderer", () => {
	test("renders JSON as one machine-readable value", () => {
		const original = process.stdout.write;
		let output = "";
		process.stdout.write = ((chunk: string | Uint8Array) => {
			output += String(chunk);
			return true;
		}) as typeof process.stdout.write;
		try {
			render([{ id: 1 }, { id: 2 }], {
				json: true,
				ndjson: false,
				color: false,
			});
			expect(output).toBe('[{"id":1},{"id":2}]\n');
		} finally {
			process.stdout.write = original;
		}
	});

	test("renders arrays as NDJSON when requested", () => {
		const original = process.stdout.write;
		let output = "";
		process.stdout.write = ((chunk: string | Uint8Array) => {
			output += String(chunk);
			return true;
		}) as typeof process.stdout.write;
		try {
			render([{ id: 1 }, { id: 2 }], {
				json: true,
				ndjson: true,
				color: false,
			});
			expect(output).toBe('{"id":1}\n{"id":2}\n');
		} finally {
			process.stdout.write = original;
		}
	});

	test("renders table headers, separator, and rows", () => {
		const original = process.stdout.write;
		let output = "";
		process.stdout.write = ((chunk: string | Uint8Array) => {
			output += String(chunk);
			return true;
		}) as typeof process.stdout.write;
		try {
			render([{ id: "r1", status: "open" }], {
				json: false,
				ndjson: false,
				color: false,
			});
			expect(output).toContain("id");
			expect(output).toContain("status");
			expect(output).toContain("r1");
			expect(output).toContain("open");
		} finally {
			process.stdout.write = original;
		}
	});
});
