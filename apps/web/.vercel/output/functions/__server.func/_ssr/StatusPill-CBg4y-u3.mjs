import { j as jsxRuntimeExports } from "../_libs/react.mjs";
const toneStyles = {
  neutral: "border-[rgba(130,122,110,0.22)] bg-[rgba(130,122,110,0.07)] text-[var(--sea-ink-soft)]",
  success: "border-[rgba(5,150,105,0.26)] bg-[rgba(5,150,105,0.08)] text-[var(--success)]",
  warning: "border-[rgba(217,119,6,0.28)] bg-[rgba(217,119,6,0.09)] text-[var(--warning)]",
  danger: "border-[rgba(220,38,38,0.26)] bg-[rgba(220,38,38,0.09)] text-[var(--danger)]",
  info: "border-[rgba(30,157,154,0.26)] bg-[rgba(30,157,154,0.08)] text-[var(--teal)]"
};
function StatusPill({
  label,
  tone = "neutral"
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      className: `inline-flex items-center rounded-full border px-2 py-0.5 text-[0.65rem] font-semibold tracking-[0.12em] uppercase leading-none ${toneStyles[tone]}`,
      children: label
    }
  );
}
export {
  StatusPill as S
};
