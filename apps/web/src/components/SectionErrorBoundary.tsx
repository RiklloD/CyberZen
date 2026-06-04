import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

type Props = {
	children: ReactNode;
	title?: string;
};

type State = {
	hasError: boolean;
	error: Error | null;
};

/**
 * Section-level error boundary.
 * Wraps individual panels/sections so one failing panel doesn't break the entire route.
 * Shows a compact inline error state within the panel area.
 */
export default class SectionErrorBoundary extends Component<Props, State> {
	constructor(props: Props) {
		super(props);
		this.state = { hasError: false, error: null };
	}

	static getDerivedStateFromError(error: Error): State {
		return { hasError: true, error };
	}

	componentDidCatch(error: Error, info: ErrorInfo) {
		console.error(
			`[SectionErrorBoundary${this.props.title ? ` (${this.props.title})` : ""}]`,
			error,
			info.componentStack,
		);
	}

	handleRetry = () => {
		this.setState({ hasError: false, error: null });
	};

	render() {
		if (this.state.hasError) {
			return (
				<div className="panel">
					<div className="flex flex-col items-center gap-3 px-6 py-8 text-center">
						<div className="flex h-10 w-10 items-center justify-center rounded-full bg-orange-100 text-orange-500">
							<AlertTriangle size={20} />
						</div>
						<div>
							{this.props.title && (
								<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
									{this.props.title}
								</h3>
							)}
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
								Failed to load this section.{" "}
								<button
									type="button"
									className="text-[var(--signal)] hover:underline"
									onClick={this.handleRetry}
								>
									Retry
								</button>
							</p>
						</div>
						{this.state.error && import.meta.env.DEV && (
							<pre className="w-full max-w-lg overflow-x-auto rounded-md bg-orange-50 p-2 text-left text-[0.65rem] text-orange-700">
								{this.state.error.message}
							</pre>
						)}
					</div>
				</div>
			);
		}

		return this.props.children;
	}
}
