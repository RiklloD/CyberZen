import { Keyboard, X } from "lucide-react";
import { useEffect, useState } from "react";
import { getShortcuts, type ShortcutDef } from "../lib/shortcuts";

/**
 * §6.16 — Keyboard Shortcuts Help Modal.
 *
 * Toggled by pressing "?" anywhere (except in input fields).
 * Shows all registered shortcuts grouped by category.
 */

type Props = {
	open: boolean;
	onClose: () => void;
};

const CATEGORY_LABELS: Record<string, string> = {
	navigation: "Navigation",
	search: "Search",
	general: "General",
};

function formatKeys(keys: string): string {
	return keys
		.split(" ")
		.map((k) => {
			if (k === "/") return "/";
			if (k === "?") return "?";
			return k.toUpperCase();
		})
		.join(" ");
}

export default function ShortcutsModal({ open, onClose }: Props) {
	const [shortcuts, setShortcuts] = useState<ShortcutDef[]>([]);

	useEffect(() => {
		if (open) {
			setShortcuts(getShortcuts());
		}
	}, [open]);

	// Close on Escape
	useEffect(() => {
		if (!open) return;
		function handleKey(e: KeyboardEvent) {
			if (e.key === "Escape") onClose();
		}
		document.addEventListener("keydown", handleKey);
		return () => document.removeEventListener("keydown", handleKey);
	}, [open, onClose]);

	if (!open) return null;

	// Group by category
	const groups: Record<string, ShortcutDef[]> = {};
	for (const s of shortcuts) {
		(groups[s.category] ??= []).push(s);
	}

	// Also show built-in shortcuts that aren't in the registry
	const builtin: ShortcutDef[] = [
		{
			label: "Open command palette",
			keys: "⌘K / Ctrl+K",
			category: "general",
			action: () => {},
		},
		{
			label: "Show keyboard shortcuts",
			keys: "?",
			category: "general",
			action: () => {},
		},
		{
			label: "Open search",
			keys: "/",
			category: "search",
			action: () => {},
		},
		{
			label: "Close modal / overlay",
			keys: "Escape",
			category: "general",
			action: () => {},
		},
	];

	// Merge builtins
	for (const b of builtin) {
		(groups[b.category] ??= []).push(b);
	}

	const categoryOrder = ["general", "navigation", "search"];

	return (
		<div className="modal-overlay" onClick={onClose}>
			<div className="modal-card" onClick={(e) => e.stopPropagation()}>
				<div className="modal-header">
					<div className="flex items-center gap-2">
						<Keyboard size={18} className="text-[var(--signal)]" />
						<h2 className="modal-title">Keyboard Shortcuts</h2>
					</div>
					<button
						type="button"
						className="modal-close"
						onClick={onClose}
						aria-label="Close"
					>
						<X size={16} />
					</button>
				</div>

				<div className="modal-body space-y-5">
					{categoryOrder.map((cat) => {
						const items = groups[cat];
						if (!items || items.length === 0) return null;
						return (
							<div key={cat}>
								<h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--sea-ink-soft)] mb-2">
									{CATEGORY_LABELS[cat] ?? cat}
								</h3>
								<div className="space-y-1">
									{items.map((s, i) => (
										<div
											key={`${s.label}-${i}`}
											className="flex items-center justify-between px-3 py-2 rounded-lg hover:bg-[var(--surface-soft)] transition-colors"
										>
											<span className="text-sm text-[var(--sea-ink)]">
												{s.label}
											</span>
											<kbd className="kbd">
												{formatKeys(s.keys)}
											</kbd>
										</div>
									))}
								</div>
							</div>
						);
					})}
				</div>
			</div>
		</div>
	);
}
