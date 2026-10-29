import { cn } from '@/lib/utils';
import type { Severity } from '@/types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

const severityConfig: Record<Severity, { bg: string; text: string; label: string }> = {
  CRITICAL: {
    bg: 'bg-red-500/15 border border-red-500/30',
    text: 'text-red-400',
    label: 'Critical',
  },
  HIGH: {
    bg: 'bg-orange-500/15 border border-orange-500/30',
    text: 'text-orange-400',
    label: 'High',
  },
  MODERATE: {
    bg: 'bg-amber-500/15 border border-amber-500/30',
    text: 'text-amber-400',
    label: 'Moderate',
  },
  LOW: {
    bg: 'bg-emerald-500/15 border border-emerald-500/30',
    text: 'text-emerald-400',
    label: 'Low',
  },
};

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const config = severityConfig[severity] || severityConfig.LOW;

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full font-semibold',
        config.bg,
        config.text,
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
      )}
    >
      {config.label}
    </span>
  );
}
