// Stub for node:async_hooks — not available in browser.
// Used by @tanstack/start-storage-context which is pulled in
// by @clerk/react but only needed for SSR.
export class AsyncLocalStorage {
	getStore() {
		return undefined;
	}
	run(_store, fn, ...args) {
		return fn(...args);
	}
}
