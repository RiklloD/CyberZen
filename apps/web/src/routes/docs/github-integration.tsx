import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
	Check,
	ChevronRight,
	Copy,
	Download,
	Github,
	Key,
	Terminal } from "lucide-react";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";
import { ACTION_YML, ENTRYPOINT_SH, README_MD } from "../../data/github-action-scaffold";

export const Route = createFileRoute("/docs/github-integration")({
	errorComponent: RouteErrorBoundary,
	component: GithubIntegrationPage });

function useCopy(timeout = 1500) {
	const [copied, setCopied] = useState(false);
	function copy(text: string) {
		navigator.clipboard.writeText(text).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), timeout);
		});
	}
	return { copied, copy };
}

function CodeBlock({
	code,
	label }: {
	code: string;
	language?: string;
	label?: string;
}) {
	const { copied, copy } = useCopy();
	return (
		<div className="relative rounded-xl border border-[var(--line)] bg-[var(--surface-soft)] overflow-hidden">
			{label && (
				<div className="flex items-center justify-between px-4 py-2 border-b border-[var(--line)] bg-[var(--surface)]">
					<span className="text-xs font-mono text-[var(--sea-ink-soft)]">
						{label}
					</span>
					<button
						type="button"
						onClick={() => copy(code)}
						className="flex items-center gap-1.5 text-xs text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
					>
						{copied ? (
							<Check size={12} className="text-green-500" />
						) : (
							<Copy size={12} />
						)}
						{copied ? "Copied!" : "Copy"}
					</button>
				</div>
			)}
			{!label && (
				<button
					type="button"
					onClick={() => copy(code)}
					className="absolute top-3 right-3 flex items-center gap-1.5 text-xs text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors z-10"
				>
					{copied ? (
						<Check size={12} className="text-green-500" />
					) : (
						<Copy size={12} />
					)}
					{copied ? "Copied!" : "Copy"}
				</button>
			)}
			<pre className="p-4 overflow-x-auto text-xs leading-relaxed text-[var(--sea-ink)] font-mono whitespace-pre">
				{code}
			</pre>
		</div>
	);
}

const QUICK_START_YAML = `name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: CyberZen Security Scan
        uses: cyberzen/scan-action@v1
        with:
          api-key: \${{ secrets.CYBERZEN_API_KEY }}
          workspace: my-workspace
          fail-on-severity: high`;

const STEPS = [
	{
		number: 1,
		title: "Create an API key",
		description:
			'Go to Settings → API Keys and create a key with "repositories:write" and "findings:read" scopes.',
		action: (
			<Link
				to="/settings/api-keys"
				className="inline-flex items-center gap-1.5 text-xs signal-button py-1.5 px-3"
			>
				<Key size={12} />
				Open API Keys
			</Link>
		) },
	{
		number: 2,
		title: "Add the secret to GitHub",
		description:
			'In your GitHub repository, go to Settings → Secrets → Actions and add a new secret named "CYBERZEN_API_KEY" with the key value.' },
	{
		number: 3,
		title: "Find your workspace slug",
		description:
			'Your workspace slug is the short identifier shown in Settings → General (e.g. "acme-corp"). It is also visible in the URL bar.',
		action: (
			<Link
				to="/settings/general"
				className="inline-flex items-center gap-1.5 text-xs signal-button secondary-button py-1.5 px-3"
			>
				Open General Settings
			</Link>
		) },
	{
		number: 4,
		title: "Add the workflow file",
		description:
			"Create .github/workflows/security.yml in your repository with the content shown in the Quick Start tab." },
	{
		number: 5,
		title: "Verify the first run",
		description:
			"Push to a branch or open a pull request. The action will appear under the Checks tab. After completion, results appear in your CyberZen dashboard." },
];

type Tab = "quickstart" | "action-yml" | "entrypoint" | "readme";

export default function GithubIntegrationPage() {
	const [activeTab, setActiveTab] = useState<Tab>("quickstart");

	function downloadFile(content: string, filename: string, type = "text/plain") {
		const blob = new Blob([content], { type });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = filename;
		a.click();
		URL.revokeObjectURL(url);
	}

	const tabs: { id: Tab; label: string }[] = [
		{ id: "quickstart", label: "Quick Start" },
		{ id: "action-yml", label: "action.yml" },
		{ id: "entrypoint", label: "entrypoint.sh" },
		{ id: "readme", label: "README" },
	];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Github size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">GitHub Actions Integration</h1>
						<p className="page-subtitle">
							Gate CI/CD on security findings with the CyberZen marketplace
							action
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-8">
				{/* Overview banner */}
				<div className="card bg-[var(--signal-soft)] border-[var(--signal)] flex flex-col sm:flex-row sm:items-center gap-4">
					<div className="flex-1">
						<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
							cyberzen/scan-action
						</p>
						<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed">
							The official CyberZen GitHub Action. Integrates AI-powered
							security scanning directly into your pull request workflow and
							blocks merges on configurable severity thresholds.
						</p>
					</div>
					<div className="flex gap-2 shrink-0">
						<button
							type="button"
							onClick={() =>
								downloadFile(ACTION_YML, "action.yml", "text/yaml")
							}
							className="signal-button secondary-button flex items-center gap-1.5 py-1.5 px-3 text-xs"
						>
							<Download size={12} />
							action.yml
						</button>
						<button
							type="button"
							onClick={() =>
								downloadFile(ENTRYPOINT_SH, "entrypoint.sh", "text/plain")
							}
							className="signal-button secondary-button flex items-center gap-1.5 py-1.5 px-3 text-xs"
						>
							<Terminal size={12} />
							entrypoint.sh
						</button>
					</div>
				</div>

				{/* Setup Wizard */}
				<section>
					<h2 className="section-title mb-4">Setup Wizard</h2>
					<ol className="space-y-4">
						{STEPS.map((step) => (
							<li
								key={step.number}
								className="flex gap-4 items-start card card-sm"
							>
								<div className="shrink-0 w-7 h-7 rounded-full bg-[var(--signal-soft)] text-[var(--signal)] flex items-center justify-center text-xs font-bold">
									{step.number}
								</div>
								<div className="flex-1 min-w-0">
									<p className="text-sm font-semibold text-[var(--sea-ink)] mb-0.5">
										{step.title}
									</p>
									<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed mb-2">
										{step.description}
									</p>
									{step.action}
								</div>
								<ChevronRight
									size={14}
									className="shrink-0 text-[var(--sea-ink-soft)] mt-1"
								/>
							</li>
						))}
					</ol>
				</section>

				{/* Scaffold files */}
				<section>
					<div className="flex items-center justify-between mb-4">
						<h2 className="section-title">Action Files</h2>
					</div>

					<div className="flex gap-1 mb-4 border-b border-[var(--line)]">
						{tabs.map((tab) => (
							<button
								key={tab.id}
								type="button"
								onClick={() => setActiveTab(tab.id)}
								className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
									activeTab === tab.id
										? "border-[var(--signal)] text-[var(--signal)]"
										: "border-transparent text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)]"
								}`}
							>
								{tab.label}
							</button>
						))}
					</div>

					{activeTab === "quickstart" && (
						<CodeBlock
							code={QUICK_START_YAML}
							language="yaml"
							label=".github/workflows/security.yml"
						/>
					)}
					{activeTab === "action-yml" && (
						<CodeBlock code={ACTION_YML} language="yaml" label="action.yml" />
					)}
					{activeTab === "entrypoint" && (
						<CodeBlock
							code={ENTRYPOINT_SH}
							language="bash"
							label="entrypoint.sh"
						/>
					)}
					{activeTab === "readme" && (
						<CodeBlock code={README_MD} language="markdown" label="README.md" />
					)}
				</section>

				{/* Badge markdown */}
				<section>
					<h2 className="section-title mb-3">Status Badge</h2>
					<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
						Add this badge to your repository README to show real-time security
						posture.
					</p>
					<CodeBlock
						code={`[![CyberZen Security](https://api.cyberzen.dev/badge/{workspace}/{repo})](https://app.cyberzen.dev/{workspace})`}
						label="Badge markdown"
					/>
				</section>

				{/* Links */}
				<section className="flex flex-wrap gap-3">
					<Link
						to="/docs/api"
						className="signal-button secondary-button flex items-center gap-1.5 text-xs"
					>
						API Reference
					</Link>
					<Link
						to="/settings/api-keys"
						className="signal-button secondary-button flex items-center gap-1.5 text-xs"
					>
						<Key size={12} />
						Manage API Keys
					</Link>
				</section>
			</div>
		</main>
	);
}
