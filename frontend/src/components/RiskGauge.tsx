'use client';

import { getRiskColor, getRiskLabel } from '@/lib/utils';

interface RiskGaugeProps {
  score: number;
  size?: number;
}

export default function RiskGauge({ score, size = 180 }: RiskGaugeProps) {
  const color = getRiskColor(score);
  const label = getRiskLabel(score);
  const radius = (size - 20) / 2;
  const circumference = Math.PI * radius; // semicircle
  const progress = (score / 100) * circumference;
  const center = size / 2;

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size / 2 + 20} viewBox={`0 0 ${size} ${size / 2 + 20}`}>
        {/* Background arc */}
        <path
          d={`M 10 ${size / 2 + 10} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2 + 10}`}
          fill="none"
          stroke="#1e293b"
          strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d={`M 10 ${size / 2 + 10} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2 + 10}`}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={`${circumference - progress}`}
          className="transition-all duration-1000 ease-out"
          style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
        />
        {/* Score text */}
        <text
          x={center}
          y={size / 2 - 5}
          textAnchor="middle"
          className="fill-white text-3xl font-bold"
          fontSize="32"
          fontWeight="700"
        >
          {score}
        </text>
        <text
          x={center}
          y={size / 2 + 15}
          textAnchor="middle"
          className="fill-gray-400 text-xs"
          fontSize="12"
        >
          / 100
        </text>
      </svg>
      <span
        className="text-sm font-semibold"
        style={{ color }}
      >
        {label}
      </span>
    </div>
  );
}
