import { ChevronRight, GitPullRequest, Wrench, Zap } from "lucide-react";
import type { FindingGroup } from "../lib/findings";
import { isExploitable } from "../lib/findings";
import { absoluteTime, humanize, relativeTime, repoShortName } from "../lib/format";
import SeverityBadge from "./ui/SeverityBadge";

/**
 * One finding (or a group of identical findings) as a dense list row.
 * Signals that change what you do next — exploitability, a known fix,
 * an open PR — are shown as badges; everything else is quiet metadata.
 */
export default function FindingListRow({
	group,
	onOpen,
	selected = false,
	leading,
	showRepo = true,
}: {
	group: FindingGroup;
	onOpen: () => void;
	selected?: boolean;
	leading?: React.ReactNode;
	showRepo?: boolean;
}) {
	const f = group.lead;
	const count = group.items.length;
	const exploitable = group.items.some(isExploitable);
	const prOpen = group.items.some((i) => i.status === "pr_opened" || i.prUrl);
	const oldest = Math.min(...group.items.map((i) => i.createdAt));

	return (
		<div className={`list-row group !gap-0 !p-0 ${selected ? "is-selected" : ""}`}>
			{leading && <div className="flex shrink-0 items-center pl-4">{leading}</div>}
			<button
				type="button"
				onClick={onOpen}
				className="flex min-w-0 flex-1 items-center gap-3 bg-transparent px-4 py-2.5 text-left"
			>
				<span className="w-[84px] shrink-0">
					<SeverityBadge severity={f.severity} />
				</span>
				<span className="min-w-0 flex-1">
					<span className="flex items-center gap-2">
						<span className="truncate text-[0.84rem] font-medium text-[var(--text)]">{f.title}</span>
						{count > 1 && (
							<span className="badge shrink-0 !h-[18px] tabular" title={`${count} occurrences`}>
								×{count}
							</span>
						)}
					</span>
					<span className="mt-0.5 flex items-center gap-1.5 truncate text-xs text-[var(--text-3)]">
						{showRepo && (
							<>
								<span className="truncate">{repoShortName(f.repositoryFullName || f.repositoryName)}</span>
								<span aria-hidden>·</span>
							</>
						)}
						<span className="truncate">{humanize(f.source)}</span>
						{f.affectedPackages.length > 0 && (
							<>
								<span aria-hidden>·</span>
								<span className="truncate font-mono text-[0.7rem]">{f.affectedPackages[0]}</span>
							</>
						)}
					</span>
				</span>
				<span className="hidden shrink-0 items-center gap-1.5 sm:flex">
					{exploitable && (
						<span className="badge" data-tone="danger" title="Exploitability confirmed in sandbox">
							<Zap size={11} />
							Exploitable
						</span>
					)}
					{f.fixVersion && (
						<span className="badge" data-tone="success" title={`Upgrade to ${f.fixVersion}`}>
							<Wrench size={11} />
							Fix {f.fixVersion}
						</span>
					)}
					{prOpen && (
						<span className="badge" data-tone="info">
							<GitPullRequest size={11} />
							PR open
						</span>
					)}
				</span>
				<span
					className="w-16 shrink-0 text-right text-xs text-[var(--text-3)] tabular"
					title={`First seen ${absoluteTime(oldest)}`}
				>
					{relativeTime(oldest)}
				</span>
				<ChevronRight
					size={14}
					className="shrink-0 text-[var(--text-3)] opacity-0 transition-opacity group-hover:opacity-100"
				/>
			</button>
		</div>
	);
}
