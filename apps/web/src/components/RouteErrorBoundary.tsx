import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

type Props = {
	children?: ReactNode;
	error?: Error | unknown;
	info?: { componentStack: string };
	reset?: () => void;
};

type State = {
	hasError: boolean;
	error: Error | null;
};

class ErrorBoundaryImpl extends Component<Props, State> {
	constructor(props: Props) {
		super(props);
		this.state = { hasError: false, error: null };
	}

	static getDerivedStateFromError(error: Error): State {
		return { hasError: true, error };
	}

	componentDidCatch(error: Error, info: ErrorInfo) {
		console.error("[RouteErrorBoundary]", error, info.componentStack);
	}

	handleRetry = () => {
		this.setState({ hasError: false, error: null });
		this.props.reset?.();
	};

	handleReload = () => {
		window.location.reload();
	};

	render() {
		const propError =
			this.props.error instanceof Error
				? this.props.error
				: this.props.error
					? new Error(String(this.props.error))
					: null;
		const displayError = this.state.error ?? propError;
		const hasError = this.state.hasError || propError !== null;

		if (hasError) {
			return (
				<div className="flex min-h-[60vh] items-center justify-center p-8">
					<div className="flex max-w-md flex-col items-center gap-4 text-center">
						<div className="flex h-14 w-14 items-center justify-center rounded-full bg-red-100 text-red-500">
							<AlertTriangle size={28} />
						</div>
						<h2 className="text-lg font-semibold text-[var(--sea-ink)]">
							Something went wrong
						</h2>
						<p className="text-sm text-[var(--sea-ink-soft)]">
							An unexpected error occurred while rendering this page.
						</p>
						{displayError && (
							<pre className="w-full overflow-x-auto rounded-md bg-red-50 p-3 text-left text-xs text-red-700">
								{displayError.message}
							</pre>
						)}
						<div className="flex gap-3">
							<button
								type="button"
								className="secondary-button"
								onClick={this.handleRetry}
							>
								<RotateCcw size={14} />
								Try Again
							</button>
							<button
								type="button"
								className="signal-button"
								onClick={this.handleReload}
							>
								Reload Page
							</button>
						</div>
					</div>
				</div>
			);
		}

		return this.props.children;
	}
}

export default function RouteErrorBoundary(props: {
	children?: ReactNode;
	error?: Error | unknown;
	info?: { componentStack: string };
	reset?: () => void;
}) {
	return <ErrorBoundaryImpl {...props} />;
}
