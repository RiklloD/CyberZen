/**
 * §6.16 — Keyboard Shortcuts Registry.
 *
 * Centralised shortcut definitions used by ShortcutsModal and
 * the global keydown listener in __root.tsx.
 *
 * Shortcuts are grouped by category for the help overlay.
 */

export type ShortcutDef = {
	/** Human-readable label */
	label: string;
	/** Key sequence (e.g. "g r" = press g then r) */
	keys: string;
	/** Category for grouping in the help modal */
	category: "navigation" | "search" | "general";
	/** Action to run */
	action: () => void;
};

const NAV_REGISTRY: ShortcutDef[] = [];
let globalListenerAttached = false;

/**
 * Register a shortcut. Returns an unsubscribe function.
 */
export function registerShortcut(def: Omit<ShortcutDef, "category"> & { category?: ShortcutDef["category"] }): () => void {
	const entry: ShortcutDef = {
		...def,
		category: def.category ?? "general",
	};
	NAV_REGISTRY.push(entry);
	return () => {
		const idx = NAV_REGISTRY.indexOf(entry);
		if (idx >= 0) NAV_REGISTRY.splice(idx, 1);
	};
}

/**
 * Get all registered shortcuts (for the help modal).
 */
export function getShortcuts(): ShortcutDef[] {
	return [...NAV_REGISTRY];
}

/**
 * Sequence-trigger state for "g + key" style shortcuts.
 */
let seqFirst = false;
let seqTimer: ReturnType<typeof setTimeout> | null = null;

function resetSeq() {
	seqFirst = false;
	if (seqTimer) clearTimeout(seqTimer);
	seqTimer = null;
}

/**
 * Attach a global keydown listener that fires registered shortcuts.
 * Call once from __root.tsx.
 */
export function attachGlobalShortcutListener() {
	if (globalListenerAttached) return;
	globalListenerAttached = true;

	document.addEventListener("keydown", (e) => {
		// Don't intercept when typing in inputs/textareas
		const tag = (e.target as HTMLElement)?.tagName;
		if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
			// Still allow Escape
			if (e.key === "Escape") {
				fireMatching("Escape");
			}
			return;
		}

		const key = e.key;

		// Sequence: "g" first key
		if (key === "g" && !seqFirst) {
			seqFirst = true;
			seqTimer = setTimeout(resetSeq, 1500);
			return;
		}

		// If in "g" sequence, look for "g <key>"
		if (seqFirst && key !== "g") {
			fireMatching(`g ${key}`);
			resetSeq();
			return;
		}

		// Direct shortcuts
		if (key === "/" || key === "?" || key === "Escape") {
			fireMatching(key);
			return;
		}

		// Cmd/Ctrl+K is handled in CommandPalette directly
	});
}

function fireMatching(keys: string) {
	for (const s of NAV_REGISTRY) {
		if (s.keys === keys) {
			s.action();
			return;
		}
	}
}

/**
 * Pre-defined common navigation shortcuts.
 * Call from __root.tsx with the navigate function.
 */
export function registerNavigationShortcuts(navigate: (to: string) => void) {
	const unsubs: (() => void)[] = [];

	unsubs.push(
		registerShortcut({
			label: "Go to Repositories",
			keys: "g r",
			category: "navigation",
			action: () => navigate("/repositories"),
		}),
	);
	unsubs.push(
		registerShortcut({
			label: "Go to Findings",
			keys: "g f",
			category: "navigation",
			action: () => navigate("/findings"),
		}),
	);
	unsubs.push(
		registerShortcut({
			label: "Go to Compliance",
			keys: "g c",
			category: "navigation",
			action: () => navigate("/compliance"),
		}),
	);
	unsubs.push(
		registerShortcut({
			label: "Go to Dashboard",
			keys: "g d",
			category: "navigation",
			action: () => navigate("/"),
		}),
	);
	unsubs.push(
		registerShortcut({
			label: "Go to Settings",
			keys: "g s",
			category: "navigation",
			action: () => navigate("/settings"),
		}),
	);

	return () => unsubs.forEach((u) => u());
}
