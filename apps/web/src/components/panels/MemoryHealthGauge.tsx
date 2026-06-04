export default function MemoryHealthGauge({
  score,
  size = 100,
}: {
  score: number; // 0-100
  size?: number;
}) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDasharray = circumference;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  // Color based on score
  const getColor = (score: number) => {
    if (score >= 80) return "var(--sea-green)";
    if (score >= 60) return "var(--sea-yellow)";
    if (score >= 40) return "var(--sea-orange)";
    return "var(--sea-red)";
  };

  const color = getColor(score);

  return (
    <div className="flex items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="transform -rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="rgba(130,122,110,0.1)"
            strokeWidth="8"
            fill="none"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth="8"
            fill="none"
            strokeDasharray={strokeDasharray}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        {/* Score text */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <div className="text-2xl font-mono font-bold" style={{ color }}>
              {score}
            </div>
            <div className="text-xs text-[var(--sea-ink-soft)] -mt-1">
              health
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}