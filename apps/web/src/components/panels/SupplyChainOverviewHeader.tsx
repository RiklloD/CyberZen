import { Link2 } from "lucide-react";

export default function SupplyChainOverviewHeader() {
	return (
		<div className="page-header">
			<div className="flex items-center gap-3">
				<Link2 size={20} className="text-[var(--signal)]" />
				<div>
					<h1 className="page-title">Supply Chain</h1>
					<p className="page-subtitle">
						Supply chain posture, prompt injection risk, and dependency health
					</p>
				</div>
			</div>
		</div>
	);
}
