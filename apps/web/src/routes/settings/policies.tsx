import { createFileRoute } from "@tanstack/react-router";
import { ShieldQuestion, Plus, Trash2, Edit3, X, Code2 } from "lucide-react";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

type CustomPolicy = NonNullable<FunctionReturnType<typeof api.customPolicies.listPolicies>>[number];

export const Route = createFileRoute("/settings/policies")({
	errorComponent: RouteErrorBoundary,
	component: CustomPolicyBuilderPage });

const CONDITION_TEMPLATES = [
	{ label: "Severity is Critical", dsl: '{"condition":"severity","operator":"eq","value":"critical"}' },
	{ label: "Severity is High or Critical", dsl: '{"condition":"severity","operator":"in","value":["critical","high"]}' },
	{ label: "Exploit Validated", dsl: '{"condition":"validationStatus","operator":"eq","value":"validated"}' },
	{ label: "Package matches", dsl: '{"condition":"package","operator":"contains","value":"PACKAGE_NAME"}' },
	{ label: "Repository is", dsl: '{"condition":"repository","operator":"eq","value":"REPO_NAME"}' },
	{ label: "Confidence above", dsl: '{"condition":"confidence","operator":"gt","value":0.8}' },
];

function CustomPolicyBuilderPage() {
	const TENANT = useTenantSlug();
	const policies = useQuery(api.customPolicies.listPolicies, {
		tenantSlug: TENANT });

	const createPolicy = useMutation(api.customPolicies.createPolicy);
	const updatePolicy = useMutation(api.customPolicies.updatePolicy);
	const deletePolicy = useMutation(api.customPolicies.deletePolicy);

	const [editorOpen, setEditorOpen] = useState(false);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [formName, setFormName] = useState("");
	const [formDescription, setFormDescription] = useState("");
	const [formDsl, setFormDsl] = useState("");
	const [formEnabled, setFormEnabled] = useState(true);
	const [showTemplates, setShowTemplates] = useState(false);
	const [dslError, setDslError] = useState<string | null>(null);

	function openCreate() {
		setEditingId(null);
		setFormName("");
		setFormDescription("");
		setFormDsl('{\n  "conditions": [],\n  "action": "block"\n}');
		setFormEnabled(true);
		setEditorOpen(true);
	}

	function openEdit(
		id: string,
		name: string,
		dsl: string,
		desc?: string,
		enabled?: boolean,
	) {
		setEditingId(id);
		setFormName(name);
		setFormDescription(desc ?? "");
		setFormDsl(dsl);
		setFormEnabled(enabled ?? true);
		setEditorOpen(true);
	}

	function handleSave() {
		if (!formName || !formDsl) return;

		try {
			JSON.parse(formDsl);
		} catch {
			setDslError("Invalid JSON — fix syntax errors before saving.");
			return;
		}
		setDslError(null);

		if (editingId) {
			updatePolicy({
				policyId: editingId as any,
				name: formName,
				description: formDescription || undefined,
				dsl: formDsl,
				enabled: formEnabled });
		} else {
			createPolicy({
				tenantSlug: TENANT,
				name: formName,
				description: formDescription || undefined,
				dsl: formDsl,
				enabled: formEnabled });
		}
		setEditorOpen(false);
	}

	function handleDelete(id: string) {
		if (confirm("Delete this custom policy?")) {
			deletePolicy({ policyId: id as any });
		}
	}

	function handleToggle(id: string, enabled: boolean) {
		updatePolicy({ policyId: id as any, enabled: !enabled });
	}

	function applyTemplate(dsl: string) {
		setFormDsl(dsl);
		setShowTemplates(false);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-3">
						<ShieldQuestion size={20} className="text-[var(--signal)]" />
						<div>
							<h1 className="page-title">Custom Policy Builder</h1>
							<p className="page-subtitle">
								Create and manage custom security policies with a visual DSL
							</p>
						</div>
					</div>
					<button type="button" className="signal-button" onClick={openCreate}>
						<Plus size={14} />
						New Policy
					</button>
				</div>
			</div>

			<div className="page-body">
				<div className="panel">
					{policies === undefined && (
						<div className="p-6 text-sm text-[var(--sea-ink-soft)]">
							Loading policies...
						</div>
					)}

					{policies !== undefined && policies.length === 0 && (
						<div className="flex flex-col items-center justify-center gap-3 py-16 text-[var(--sea-ink-soft)]">
							<ShieldQuestion size={32} className="opacity-30" />
							<p className="text-sm">
								No custom policies. Create one to enforce custom security rules.
							</p>
						</div>
					)}

					{policies !== undefined && policies.length > 0 && (
						<div className="overflow-x-auto">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b border-[var(--line)]">
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Policy Name
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											DSL Preview
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Updated
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
									{policies.map((p: CustomPolicy) => (
										<tr key={p._id} className="border-b border-[var(--line)]">
											<td className="px-4 py-3">
												<div className="font-medium text-[var(--sea-ink)]">
													{p.name}
												</div>
												{p.description && (
													<div className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
														{p.description}
													</div>
												)}
											</td>
											<td className="px-4 py-3">
												<pre className="text-[0.65rem] font-mono text-[var(--sea-ink-soft)] bg-[var(--chip-bg)] rounded px-2 py-1 max-w-xs truncate">
													{p.dsl.slice(0, 120)}
													{p.dsl.length > 120 ? "..." : ""}
												</pre>
											</td>
											<td className="px-4 py-3 text-xs text-[var(--sea-ink-soft)]">
												{new Date(p.updatedAt).toLocaleDateString()}
											</td>
											<td className="px-4 py-3 text-center">
												<button
													type="button"
													onClick={() => handleToggle(p._id, p.enabled)}
													className={`inline-flex rounded-full px-2 py-0.5 text-[0.6rem] font-semibold cursor-pointer ${
														p.enabled
															? "bg-green-100 text-green-700"
															: "bg-gray-100 text-gray-500"
													}`}
												>
													{p.enabled ? "Active" : "Disabled"}
												</button>
											</td>
											<td className="px-4 py-3">
												<div className="flex items-center justify-end gap-1">
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
														onClick={() =>
															openEdit(
																p._id,
																p.name,
																p.dsl,
																p.description ?? undefined,
																p.enabled,
															)
														}
														aria-label="Edit policy"
													>
														<Edit3 size={14} />
													</button>
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-red-500"
														onClick={() => handleDelete(p._id)}
														aria-label="Delete policy"
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
					<aside className="fixed right-0 top-0 z-50 flex h-full w-full max-w-2xl flex-col border-l border-[var(--line)] bg-[var(--panel-bg)] shadow-2xl">
						<div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3">
							<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
								{editingId ? "Edit Policy" : "New Policy"}
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
									Policy Name
								</label>
								<input
									type="text"
									className="input-field w-full"
									placeholder="e.g., Block Critical Exploits"
									value={formName}
									onChange={(e) => setFormName(e.target.value)}
								/>
							</div>

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Description (optional)
								</label>
								<input
									type="text"
									className="input-field w-full"
									placeholder="What this policy enforces"
									value={formDescription}
									onChange={(e) => setFormDescription(e.target.value)}
								/>
							</div>

							<div>
								<div className="flex items-center justify-between mb-1">
									<label className="text-xs font-semibold text-[var(--sea-ink-soft)]">
										Policy DSL (JSON)
									</label>
									<button
										type="button"
										className="text-[0.65rem] text-[var(--signal)] hover:underline"
										onClick={() => setShowTemplates(!showTemplates)}
									>
										<Code2 size={10} className="inline mr-1" />
										{showTemplates ? "Hide" : "Show"} Templates
									</button>
								</div>

								{showTemplates && (
									<div className="mb-2 flex flex-wrap gap-1">
										{CONDITION_TEMPLATES.map((t) => (
											<button
												key={t.label}
												type="button"
												className="inline-flex rounded-full border border-[var(--chip-line)] bg-[var(--chip-bg)] px-2 py-0.5 text-[0.6rem] font-medium text-[var(--sea-ink-soft)] hover:border-[var(--signal)] hover:text-[var(--signal)] transition-colors"
												onClick={() => applyTemplate(t.dsl)}
											>
												{t.label}
											</button>
										))}
									</div>
								)}

								<textarea
									className="input-field w-full font-mono text-xs min-h-[200px] resize-y"
									value={formDsl}
									onChange={(e) => { setFormDsl(e.target.value); setDslError(null); }}
									spellCheck={false}
								/>
								{dslError && (
									<p className="mt-1 text-xs text-red-600">{dslError}</p>
								)}
								</div>

							<div className="flex items-center gap-2">
								<input
									type="checkbox"
									id="policy-enabled"
									checked={formEnabled}
									onChange={(e) => setFormEnabled(e.target.checked)}
									className="rounded border-[var(--chip-line)]"
								/>
								<label
									htmlFor="policy-enabled"
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
									disabled={!formName || !formDsl}
								>
									{editingId ? "Update" : "Create"} Policy
								</button>
							</div>
						</div>
					</aside>
				</>
			)}
		</main>
	);
}
