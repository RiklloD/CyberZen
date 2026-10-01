import { useEffect, useState } from "react";
import { repoShortName } from "../../lib/format";
import { useTenantSlug } from "../../lib/workspace";

type RepoLike = { _id: string; fullName: string };

const KEY = "cyberzen.selectedRepo";

/**
 * Selected repository shared across per-repo pages (supply chain, CI/CD,
 * remediation, attack paths) so switching pages keeps your context.
 * Persisted per workspace; falls back to the first repository.
 */
export function useSelectedRepo<T extends RepoLike>(repositories: T[]) {
	const tenantSlug = useTenantSlug();
	const storageKey = `${KEY}.${tenantSlug}`;
	const [selectedId, setSelectedId] = useState<string | null>(null);

	useEffect(() => {
		try {
			setSelectedId(localStorage.getItem(storageKey));
		} catch {
			/* ignore */
		}
	}, [storageKey]);

	const select = (id: string) => {
		setSelectedId(id);
		try {
			localStorage.setItem(storageKey, id);
		} catch {
			/* ignore */
		}
	};

	const active = repositories.find((r) => r._id === selectedId) ?? repositories[0];
	return [active, select] as const;
}

/** Segmented control for a few repos, a select for many. */
export default function RepoPicker<T extends RepoLike>({
	repositories,
	active,
	onSelect,
}: {
	repositories: T[];
	active: T | undefined;
	onSelect: (id: string) => void;
}) {
	if (repositories.length <= 1) return null;

	if (repositories.length > 4) {
		return (
			<select
				className="input !w-auto"
				aria-label="Repository"
				value={active?._id ?? ""}
				onChange={(e) => onSelect(e.target.value)}
			>
				{repositories.map((r) => (
					<option key={r._id} value={r._id}>
						{repoShortName(r.fullName)}
					</option>
				))}
			</select>
		);
	}

	return (
		<div className="segmented" role="group" aria-label="Repository">
			{repositories.map((r) => (
				<button
					key={r._id}
					type="button"
					aria-pressed={active?._id === r._id}
					onClick={() => onSelect(r._id)}
					title={r.fullName}
				>
					{repoShortName(r.fullName)}
				</button>
			))}
		</div>
	);
}
