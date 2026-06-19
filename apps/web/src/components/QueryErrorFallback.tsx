import { AlertTriangle, RotateCcw } from "lucide-react";
import type { ReactNode } from "react";

type Props = {
	error?: Error | unknown;
	reset?: () => void;
	info?: { componentStack: string };
	title?: string;
	className?: string;
};

function errorMessage(error: Error | unknown): string {
	if (error instanceof Error) return error.message;
	if (typeof error === "string") return error;
	return "An unexpected error occurred.";
}

/**
 * Inline error card for failed Convex queries.
 * Compatible with TanStack Router's errorComponent interface (accepts error + reset props).
 * Use as `errorComponent: QueryErrorFallback` on routes that are primarily data-driven,
 * or render it directly inside a component when you can detect the error state.
 */
export default function QueryErrorFallback({
	error,
	reset,
	title = "Failed to load data",
	className }: Props): ReactNode {
	const msg = error !== undefined ? errorMessage(error) : null;

	return (
		<div className={className ?? "page-body-padded"}>
			<div className="panel flex flex-col items-center gap-4 px-8 py-10 text-center">
				<div className="flex h-12 w-12 items-center justify-center rounded-full bg-orange-100 text-orange-500">
					<AlertTriangle size={22} />
				</div>
				<div>
					<h2 className="text-base font-semibold text-[var(--sea-ink)]">
						{title}
					</h2>
					<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
						The request to the server failed. Check your connection and try again.
					</p>
				</div>
				{msg && (
					<pre className="w-full max-w-lg overflow-x-auto rounded-md bg-orange-50 p-3 text-left text-xs text-orange-700">
						{msg}
					</pre>
				)}
				{reset && (
					<button
						type="button"
						className="secondary-button flex items-center gap-2"
						onClick={reset}
					>
						<RotateCcw size={14} />
						Retry
					</button>
				)}
			</div>
		</div>
	);
}
