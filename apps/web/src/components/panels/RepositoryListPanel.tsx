import { useMutation } from "convex/react";
import { MoreVertical, Unplug, RefreshCw } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import type { FunctionReturnType } from "convex/server";

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

/**
 * §3.14 — Per-repo dropdown menu with Disconnect / Reconnect.
 *
 * Each repo card now shows a small "⋮" (MoreVertical) icon button.
 * Clicking it opens a dropdown with:
 *   • Disconnect — calls `api.repositories.disconnect`
 *   • Reconnect — calls `api.repositories.reconnect`
 */

export default function RepositoryListPanel({
	repos,
	selected,
	onSelect,
	tenantSlug,
}: {
	repos: OverviewRepository[];
	selected: string | null;
	onSelect: (id: string) => void;
	tenantSlug: string;
}) {
	return (
		<div className="repo-grid mb-6">
			{repos.map((repo: OverviewRepository) => (
				<RepoCard
					key={repo._id}
					repo={repo}
					isSelected={selected === repo._id}
					onSelect={onSelect}
					tenantSlug={tenantSlug}
				/>
			))}
		</div>
	);
}

function RepoCard({
	repo,
	isSelected,
	onSelect,
	tenantSlug,
}: {
	repo: OverviewRepository;
	isSelected: boolean;
	onSelect: (id: string) => void;
	tenantSlug: string;
}) {
	const [menuOpen, setMenuOpen] = useState(false);
	const menuRef = useRef<HTMLDivElement>(null);

	// Close dropdown when clicking outside
	useEffect(() => {
		if (!menuOpen) return;
		const handler = (e: MouseEvent) => {
			if (
				menuRef.current &&
				!menuRef.current.contains(e.target as Node)
			) {
				setMenuOpen(false);
			}
		};
		document.addEventListener("mousedown", handler);
		return () => document.removeEventListener("mousedown", handler);
	}, [menuOpen]);

	return (
		<div className="relative">
			<button
				type="button"
				onClick={() => onSelect(repo._id)}
				className={`card card-sm text-left w-full ${
					isSelected
						? "border-[rgba(158,255,100,0.4)] bg-[rgba(158,255,100,0.06)]"
						: ""
				}`}
			>
				<div className="repo-header">
					<span className="repo-name">{repo.fullName}</span>
					<StatusPill
						label={repo.latestSnapshot ? "SBOM active" : "no SBOM"}
						tone={repo.latestSnapshot ? "success" : "neutral"}
					/>
				</div>
				{repo.latestSnapshot && (
					<div className="flex flex-wrap gap-1.5 mt-1">
						<StatusPill
							label={`${repo.latestSnapshot.previewComponents.length} components`}
							tone="neutral"
						/>
						{repo.latestSnapshot.vulnerablePreview.length > 0 && (
							<StatusPill
								label={`${repo.latestSnapshot.vulnerablePreview.length} vulnerable`}
								tone="danger"
							/>
						)}
						{repo.latestSnapshot.comparison && (
							<StatusPill
								label={`${repo.latestSnapshot.comparison.addedPreview.length} added`}
								tone="info"
							/>
						)}
					</div>
				)}
				<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
					{formatTimestamp(repo.latestSnapshot?.capturedAt)}
				</p>
			</button>

			{/* §3.14 — Per-repo dropdown menu */}
			<div ref={menuRef} className="absolute top-2 right-2 z-10">
				<button
					type="button"
					className="p-1 rounded-md hover:bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)] transition-colors"
					onClick={(e) => {
						e.stopPropagation();
						setMenuOpen((prev) => !prev);
					}}
					aria-label="Repository actions"
				>
					<MoreVertical size={14} />
				</button>

				{menuOpen && (
					<RepoDropdownMenu
						repositoryFullName={repo.fullName}
						tenantSlug={tenantSlug}
						onClose={() => setMenuOpen(false)}
					/>
				)}
			</div>
		</div>
	);
}

function RepoDropdownMenu({
	repositoryFullName,
	tenantSlug,
	onClose,
}: {
	repositoryFullName: string;
	tenantSlug: string;
	onClose: () => void;
}) {
	const disconnect = useMutation(api.repositories.disconnect);
	const reconnect = useMutation(api.repositories.reconnect);
	const [loading, setLoading] = useState<
		"idle" | "disconnecting" | "reconnecting"
	>("idle");
	const [msg, setMsg] = useState<string | null>(null);

	const handleDisconnect = async () => {
		setLoading("disconnecting");
		setMsg(null);
		try {
			await disconnect({ tenantSlug, repositoryFullName });
			setMsg("Disconnected");
		} catch (err) {
			setMsg(
				err instanceof Error ? err.message : "Disconnect failed",
			);
		} finally {
			setLoading("idle");
			setTimeout(() => {
				setMsg(null);
				onClose();
			}, 1500);
		}
	};

	const handleReconnect = async () => {
		setLoading("reconnecting");
		setMsg(null);
		try {
			await reconnect({ tenantSlug, repositoryFullName });
			setMsg("Reconnected");
		} catch (err) {
			setMsg(
				err instanceof Error ? err.message : "Reconnect failed",
			);
		} finally {
			setLoading("idle");
			setTimeout(() => {
				setMsg(null);
				onClose();
			}, 1500);
		}
	};

	return (
		<div className="absolute right-0 top-7 w-44 rounded-lg border border-[var(--line)] bg-[var(--surface)] shadow-lg py-1 z-20">
			<button
				type="button"
				className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-[var(--sea-ink)] hover:bg-[var(--surface-hover,rgba(255,255,255,0.06))] transition-colors disabled:opacity-50"
				onClick={handleDisconnect}
				disabled={loading !== "idle"}
			>
				{loading === "disconnecting" ? (
					<RefreshCw size={12} className="animate-spin" />
				) : (
					<Unplug size={12} />
				)}
				{loading === "disconnecting" ? "Disconnecting…" : "Disconnect"}
			</button>

			<button
				type="button"
				className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-[var(--sea-ink)] hover:bg-[var(--surface-hover,rgba(255,255,255,0.06))] transition-colors disabled:opacity-50"
				onClick={handleReconnect}
				disabled={loading !== "idle"}
			>
				{loading === "reconnecting" ? (
					<RefreshCw size={12} className="animate-spin" />
				) : (
					<RefreshCw size={12} />
				)}
				{loading === "reconnecting" ? "Reconnecting…" : "Reconnect"}
			</button>

			{msg && (
				<div className="px-3 py-1 text-xs text-[var(--sea-ink-soft)]">
					{msg}
				</div>
			)}
		</div>
	);
}

export type { OverviewRepository };
