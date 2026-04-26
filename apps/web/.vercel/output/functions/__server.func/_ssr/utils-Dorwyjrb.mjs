function formatTimestamp(timestamp) {
  if (!timestamp) return "Not yet";
  return new Intl.DateTimeFormat("en-CH", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(timestamp);
}
function severityTone(severity) {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  return "info";
}
function workflowTone(status) {
  if (status === "completed") return "success";
  if (status === "failed") return "danger";
  if (status === "running") return "info";
  return "warning";
}
function disclosureTone(status) {
  if (status === "matched") return "danger";
  if (status === "version_unknown" || status === "no_snapshot") return "warning";
  if (status === "version_unaffected") return "success";
  return "info";
}
function syncTone(status) {
  if (status === "failed") return "danger";
  if (status === "skipped") return "warning";
  return "success";
}
function validationTone(status) {
  if (status === "validated") return "success";
  if (status === "likely_exploitable") return "warning";
  if (status === "unexploitable") return "info";
  return workflowTone(status ?? "queued");
}
function blastTierTone(riskTier) {
  if (riskTier === "critical") return "danger";
  if (riskTier === "high") return "warning";
  if (riskTier === "medium") return "neutral";
  return "success";
}
function attackSurfaceTone(score) {
  if (score >= 70) return "success";
  if (score >= 40) return "warning";
  if (score > 0) return "danger";
  return "neutral";
}
function driftLevelTone(level) {
  if (level === "non_compliant") return "danger";
  if (level === "at_risk" || level === "drifting") return "warning";
  return "success";
}
function frameworkScoreTone(score) {
  if (score >= 80) return "success";
  if (score >= 60) return "warning";
  return "danger";
}
function slaComplianceTone(rate) {
  if (rate >= 0.9) return "success";
  if (rate >= 0.7) return "warning";
  return "danger";
}
function priorityTierTone(tier) {
  if (tier === "p0") return "danger";
  if (tier === "p1") return "warning";
  if (tier === "p2") return "info";
  return "neutral";
}
function trendTone(trend) {
  if (trend === "improving") return "success";
  if (trend === "degrading") return "warning";
  return "neutral";
}
function supplyChainRiskTone(riskLevel) {
  if (riskLevel === "critical" || riskLevel === "high") return "danger";
  if (riskLevel === "medium") return "warning";
  return "success";
}
function injectionRiskTone(riskLevel) {
  if (riskLevel === "confirmed_injection" || riskLevel === "likely_injection")
    return "danger";
  if (riskLevel === "suspicious") return "warning";
  return "success";
}
function honeypotScoreTone(score) {
  if (score >= 85) return "danger";
  if (score >= 70) return "warning";
  return "neutral";
}
function learningTrendTone(trend) {
  if (trend === "improving") return "success";
  if (trend === "degrading") return "danger";
  return "neutral";
}
function maturityTone(score) {
  if (score >= 70) return "success";
  if (score >= 35) return "warning";
  return "neutral";
}
function multiplierTone(m) {
  if (m >= 1.5) return "danger";
  return "neutral";
}
function repositoryHealthTone(score) {
  if (score >= 80) return "success";
  if (score >= 60) return "warning";
  return "danger";
}
export {
  attackSurfaceTone as a,
  blastTierTone as b,
  slaComplianceTone as c,
  multiplierTone as d,
  severityTone as e,
  formatTimestamp as f,
  driftLevelTone as g,
  honeypotScoreTone as h,
  injectionRiskTone as i,
  frameworkScoreTone as j,
  disclosureTone as k,
  learningTrendTone as l,
  maturityTone as m,
  syncTone as n,
  priorityTierTone as p,
  repositoryHealthTone as r,
  supplyChainRiskTone as s,
  trendTone as t,
  validationTone as v,
  workflowTone as w
};
