// Browser shim for @tanstack/start-storage-context.
// In client-only SPA mode (defaultSsr: false), there is no server runtime
// to populate AsyncLocalStorage. This module provides the same interface
// so that @clerk/react doesn't crash at import time.

type StartContext = Record<string, unknown>;

const GLOBAL_STORAGE_KEY = Symbol.for("tanstack-start:start-storage-context");

// Fake AsyncLocalStorage for browser — stores context in a module-level variable
let currentContext: StartContext | undefined;

class BrowserAsyncLocalStorage {
	getStore(): StartContext | undefined {
		return currentContext;
	}
	async run<T>(context: StartContext, fn: () => T | Promise<T>): Promise<T> {
		const prev = currentContext;
		currentContext = context;
		try {
			return await fn();
		} finally {
			currentContext = prev;
		}
	}
}

// Initialize global storage (mirrors what the real module does)
const globalObj = globalThis as any;
if (!globalObj[GLOBAL_STORAGE_KEY]) {
	globalObj[GLOBAL_STORAGE_KEY] = new BrowserAsyncLocalStorage();
}
const startStorage: BrowserAsyncLocalStorage = globalObj[GLOBAL_STORAGE_KEY];

export async function runWithStartContext(context: StartContext, fn: () => any) {
	return startStorage.run(context, fn);
}

export function getStartContext(opts?: { throwIfNotFound?: boolean }): StartContext | undefined {
	const context = startStorage.getStore();
	if (!context && opts?.throwIfNotFound !== false) {
		// In client-only mode, return an empty context instead of throwing
		return {} as StartContext;
	}
	return context;
}

export { startStorage, BrowserAsyncLocalStorage as AsyncLocalStorage };
