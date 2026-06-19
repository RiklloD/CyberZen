import { createFileRoute } from "@tanstack/react-router";
import { FilterX, Plus, Trash2, Edit3, X, Clock } from "lucide-react";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

type SuppressionRule = NonNullable<FunctionReturnType<typeof api.suppressionRules.listRules>>[number];

export const Route = createFileRoute("/settings/suppression")({
	errorComponent: RouteErrorBoundary,
	component: SuppressionRulesPage });

const SCOPE_OPTIONS = [
	{ value: "all" as const, label: "All Findings" },
	{ value: "repository" as const, label: "Repository" },
	{ value: "severity" as const, label: "Severity" },
	{ value: "package" as const, label: "Package" },
	{ value: "vuln_class" as const, label: "Vulnerability Class" },
];

function SuppressionRulesPage() {
	const TENANT = useTenantSlug();
	const rules = useQuery(api.suppressionRules.listRules, {
		tenantSlug: TENANT });

	const createRule = useMutation(api.suppressionRules.createRule);
	const updateRule = useMutation(api.suppressionRules.updateRule);
	const deleteRule = useMutation(api.suppressionRules.deleteRule);

	const [editorOpen, setEditorOpen] = useState(false);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [formPattern, setFormPattern] = useState("");
	const [formScope, setFormScope] = useState<
		"all" | "repository" | "severity" | "package" | "vuln_class"
	>("all");
	const [formScopeValue, setFormScopeValue] = useState("");
	const [formJustification, setFormJustification] = useState("");
	const [formExpiresAt, setFormExpiresAt] = useState("");
	const [formEnabled, setFormEnabled] = useState(true);

	function openCreate() {
		setEditingId(null);
		setFormPattern("");
		setFormScope("all");
		setFormScopeValue("");
		setFormJustification("");
		setFormExpiresAt("");
		setFormEnabled(true);
		setEditorOpen(true);
	}

	function openEdit(
		id: string,
		pattern: string,
		scope: string,
		scopeValue?: string,
		justification?: string,
		expiresAt?: number,
		enabled?: boolean,
	) {
		setEditingId(id);
		setFormPattern(pattern);
		setFormScope(scope as typeof formScope);
		setFormScopeValue(scopeValue ?? "");
		setFormJustification(justification ?? "");
		setFormExpiresAt(expiresAt ? new Date(expiresAt).toISOString().slice(0, 16) : "");
		setFormEnabled(enabled ?? true);
		setEditorOpen(true);
	}

	function handleSave() {
		if (!formPattern || !formJustification) return;

		const expiresAt = formExpiresAt ? new Date(formExpiresAt).getTime() : undefined;

		if (editingId) {
			updateRule({
				ruleId: editingId as any,
				pattern: formPattern,
				scope: formScope,
				scopeValue: formScopeValue || undefined,
				justification: formJustification,
				expiresAt,
				enabled: formEnabled });
		} else {
			createRule({
				tenantSlug: TENANT,
				pattern: formPattern,
				scope: formScope,
				scopeValue: formScopeValue || undefined,
				justification: formJustification,
				expiresAt,
				enabled: formEnabled });
		}
		setEditorOpen(false);
	}

	function handleDelete(id: string) {
		if (confirm("Delete this suppression rule?")) {
			deleteRule({ ruleId: id as any });
		}
	}

	function handleToggle(id: string, enabled: boolean) {
		updateRule({ ruleId: id as any, enabled: !enabled });
	}

	function isExpired(expiresAt?: number) {
		return expiresAt != null && expiresAt < Date.now();
	}

	const scopeLabel = (scope: string) =>
		SCOPE_OPTIONS.find((o) => o.value === scope)?.label ?? scope;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-3">
						<FilterX size={20} className="text-[var(--signal)]" />
						<div>
							<h1 className="page-title">Suppression Rules</h1>
							<p className="page-subtitle">
								Manage finding suppression patterns and expiry
							</p>
						</div>
					</div>
					<button type="button" className="signal-button" onClick={openCreate}>
						<Plus size={14} />
						Add Rule
					</button>
				</div>
			</div>

			<div className="page-body">
				<div className="panel">
					{rules === undefined && (
						<div className="p-6 text-sm text-[var(--sea-ink-soft)]">
							Loading suppression rules...
						</div>
					)}

					{rules !== undefined && rules.length === 0 && (
						<div className="flex flex-col items-center justify-center gap-3 py-16 text-[var(--sea-ink-soft)]">
							<FilterX size={32} className="opacity-30" />
							<p className="text-sm">
								No suppression rules configured. Findings will not be suppressed.
							</p>
						</div>
					)}

					{rules !== undefined && rules.length > 0 && (
						<div className="overflow-x-auto">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b border-[var(--line)]">
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Pattern
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Scope
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Expires
										</th>
										<th className="px-4 py-3 text-center font-semibold text-[var(--sea-ink-soft)]">
											Status
										</th>
										<th className="px-4 py-3 text-right font-semibold text-[var(--sea-ink-soft)]">
											Actions
										</th>
									</tr>
								</thead>
								<tbody>
									{rules.map((r: SuppressionRule) => (
										<tr key={r._id} className="border-b border-[var(--line)]">
											<td className="px-4 py-3">
												<code className="text-xs font-mono text-[var(--sea-ink)] bg-[var(--chip-bg)] rounded px-1.5 py-0.5">
													{r.pattern}
												</code>
												<div className="text-xs text-[var(--sea-ink-soft)] mt-1 max-w-xs truncate">
													{r.justification}
												</div>
											</td>
											<td className="px-4 py-3">
												<span className="inline-flex rounded-full bg-[var(--chip-bg)] border border-[var(--chip-line)] px-2 py-0.5 text-[0.6rem] font-medium text-[var(--sea-ink-soft)]">
													{scopeLabel(r.scope)}
													{r.scopeValue ? `: ${r.scopeValue}` : ""}
												</span>
											</td>
											<td className="px-4 py-3 text-xs text-[var(--sea-ink-soft)]">
												{r.expiresAt ? (
													<span
														className={
															isExpired(r.expiresAt)
																? "text-red-500 font-medium"
																: ""
														}
													>
														<Clock size={10} className="inline mr-1" />
														{new Date(r.expiresAt).toLocaleDateString()}
														{isExpired(r.expiresAt) && " (expired)"}
													</span>
												) : (
													"Never"
												)}
											</td>
											<td className="px-4 py-3 text-center">
												<button
													type="button"
													onClick={() => handleToggle(r._id, r.enabled)}
													className={`inline-flex rounded-full px-2 py-0.5 text-[0.6rem] font-semibold cursor-pointer ${
														r.enabled
															? "bg-green-100 text-green-700"
															: "bg-gray-100 text-gray-500"
													}`}
												>
													{r.enabled ? "Active" : "Disabled"}
												</button>
											</td>
											<td className="px-4 py-3">
												<div className="flex items-center justify-end gap-1">
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
														onClick={() =>
															openEdit(
																r._id,
																r.pattern,
																r.scope,
																r.scopeValue ?? undefined,
																r.justification,
																r.expiresAt ?? undefined,
																r.enabled,
															)
														}
														aria-label="Edit rule"
													>
														<Edit3 size={14} />
													</button>
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-red-500"
														onClick={() => handleDelete(r._id)}
														aria-label="Delete rule"
													>
														<Trash2 size={14} />
													</button>
												</div>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>
			</div>

			{/* Editor Drawer */}
			{editorOpen && (
				<>
					<div
						className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm"
						onClick={() => setEditorOpen(false)}
						aria-hidden="true"
					/>
					<aside className="fixed right-0 top-0 z-50 flex h-full w-full max-w-lg flex-col border-l border-[var(--line)] bg-[var(--panel-bg)] shadow-2xl">
						<div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3">
							<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
								{editingId ? "Edit Rule" : "Add Suppression Rule"}
							</h2>
							<button
								type="button"
								className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)]"
								onClick={() => setEditorOpen(false)}
								aria-label="Close"
							>
								<X size={16} />
							</button>
						</div>

						<div className="flex-1 overflow-y-auto p-4 space-y-4">
							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Pattern (regex or exact match)
								</label>
								<input
									type="text"
									className="input-field w-full font-mono"
									placeholder="e.g., CVE-2024-\\d+ or lodash@<4.17.21"
									value={formPattern}
									onChange={(e) => setFormPattern(e.target.value)}
								/>
							</div>

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Scope
								</label>
								<select
									className="input-field w-full"
									value={formScope}
									onChange={(e) => setFormScope(e.target.value as typeof formScope)}
								>
									{SCOPE_OPTIONS.map((opt) => (
										<option key={opt.value} value={opt.value}>
											{opt.label}
										</option>
									))}
								</select>
							</div>

							{formScope !== "all" && (
								<div>
									<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
										Scope Value
									</label>
									<input
										type="text"
										className="input-field w-full"
										placeholder={
											formScope === "repository"
												? "org/repo-name"
												: formScope === "severity"
													? "critical, high, medium, low"
													: formScope === "package"
														? "lodash"
														: "SQL Injection"
										}
										value={formScopeValue}
										onChange={(e) => setFormScopeValue(e.target.value)}
									/>
								</div>
							)}

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Justification (required)
								</label>
								<textarea
									className="input-field w-full min-h-[80px] resize-y"
									placeholder="Why is this finding being suppressed?"
									value={formJustification}
									onChange={(e) => setFormJustification(e.target.value)}
								/>
							</div>

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Expires At (optional)
								</label>
								<input
									type="datetime-local"
									className="input-field w-full"
									value={formExpiresAt}
									onChange={(e) => setFormExpiresAt(e.target.value)}
								/>
							</div>

							<div className="flex items-center gap-2">
								<input
									type="checkbox"
									id="rule-enabled"
									checked={formEnabled}
									onChange={(e) => setFormEnabled(e.target.checked)}
									className="rounded border-[var(--chip-line)]"
								/>
								<label
									htmlFor="rule-enabled"
									className="text-xs font-medium text-[var(--sea-ink)]"
								>
									Enabled
								</label>
							</div>
						</div>

						<div className="border-t border-[var(--line)] px-4 py-3">
							<div className="flex justify-end gap-2">
								<button
									type="button"
									className="secondary-button"
									onClick={() => setEditorOpen(false)}
								>
									Cancel
								</button>
								<button
									type="button"
									className="signal-button"
									onClick={handleSave}
									disabled={!formPattern || !formJustification}
								>
									{editingId ? "Update" : "Create"} Rule
								</button>
							</div>
						</div>
					</aside>
				</>
			)}
		</main>
	);
}
