'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import type { Finding } from '@/types';

interface FindingsCardProps {
  finding: Finding;
  index: number;
}

export default function FindingsCard({ finding, index }: FindingsCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card border-navy-600/20 hover:border-navy-600/40 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start justify-between gap-4 text-left"
      >
        <div className="flex items-start gap-3 min-w-0">
          <span className="flex-shrink-0 w-6 h-6 rounded-full bg-navy-700 flex items-center justify-center text-xs text-gray-400 font-mono mt-0.5">
            {index + 1}
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="text-sm font-semibold text-white">{finding.title}</h4>
              <SeverityBadge severity={finding.severity} />
            </div>
            <p className="text-xs text-gray-500 mt-1 truncate">
              {finding.rule_id}
            </p>
          </div>
        </div>
        <span className="text-gray-500 flex-shrink-0 mt-1">
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </span>
      </button>

      {expanded && (
        <div className="mt-4 ml-9 space-y-3 text-sm">
          <div>
            <h5 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
              Explanation
            </h5>
            <p className="text-gray-300 leading-relaxed">{finding.explanation}</p>
          </div>

          <div>
            <h5 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
              Evidence
            </h5>
            <code className="block bg-navy-900 border border-navy-700/50 rounded-lg px-3 py-2 text-xs text-cyan-light font-mono break-all">
              {finding.evidence}
            </code>
          </div>

          <div>
            <h5 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
              Remediation
            </h5>
            <p className="text-gray-300 leading-relaxed">{finding.remediation}</p>
          </div>

          <div className="flex items-center gap-4 text-xs text-gray-500">
            <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
            <span>Weight: {finding.weight.toFixed(1)}</span>
          </div>
        </div>
      )}
    </div>
  );
}
