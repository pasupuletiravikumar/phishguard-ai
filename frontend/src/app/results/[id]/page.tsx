'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  Shield,
  ArrowLeft,
  FileDown,
  Globe,
  Mail,
  MessageSquare,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Cpu,
  Layers,
  Calendar,
  Lock,
  ExternalLink,
} from 'lucide-react';
import { getScanDetails, exportReport } from '@/lib/api';
import type { ScanResult } from '@/types';
import RiskGauge from '@/components/RiskGauge';
import SeverityBadge from '@/components/SeverityBadge';
import FindingsCard from '@/components/FindingsCard';
import LoadingSpinner from '@/components/LoadingSpinner';
import { formatDate } from '@/lib/utils';

export default function ResultDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    getScanDetails(scanId)
      .then((data) => setResult(data))
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Scan not found.');
      })
      .finally(() => setLoading(false));
  }, [scanId]);

  const handleExport = async (format: 'json' | 'html') => {
    if (!result) return;
    try {
      const blob = await exportReport(result.scan_id, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishguard-report-${result.scan_id}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch {
      alert('Failed to export report');
    }
  };

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto px-4 py-24 text-center">
        <LoadingSpinner text="Loading comprehensive forensic report..." />
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-20 text-center">
        <AlertTriangle className="h-12 w-12 text-red-400 mx-auto mb-3" />
        <h2 className="text-xl font-bold text-white">Scan Record Not Found</h2>
        <p className="text-sm text-gray-400 mt-1 mb-6">
          The requested scan report could not be located in the database.
        </p>
        <Link href="/history" className="btn-secondary text-xs">
          Back to History
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Navigation Top */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link
          href="/history"
          className="inline-flex items-center gap-2 text-xs text-gray-400 hover:text-cyan transition-colors"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Scan History
        </Link>
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleExport('json')}
            className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5"
          >
            <FileDown className="h-3.5 w-3.5" /> Export JSON
          </button>
          <button
            onClick={() => handleExport('html')}
            className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5"
          >
            <FileDown className="h-3.5 w-3.5" /> Export HTML
          </button>
        </div>
      </div>

      {/* Main Verdict Card */}
      <div className="card border-l-4 border-l-cyan">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-3">
              <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-navy-900 text-cyan border border-cyan/20">
                {result.scan_type} Vector
              </span>
              <SeverityBadge severity={result.severity} size="md" />
              <span className="text-xs font-mono text-gray-500">
                ID: {result.scan_id}
              </span>
            </div>
            <h1 className="text-2xl font-extrabold text-white">
              Forensic Threat Assessment
            </h1>
            <p className="text-sm text-gray-300 leading-relaxed">
              {result.summary}
            </p>
            <div className="flex flex-wrap items-center gap-4 text-xs text-gray-400 pt-2">
              <span className="flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" /> {formatDate(result.timestamp)}
              </span>
              <span className="flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-cyan" /> {result.analysis_mode}
              </span>
            </div>
          </div>

          <div className="flex flex-col items-center bg-navy-900/60 p-4 rounded-xl border border-navy-700/50">
            <RiskGauge score={result.risk_score} size={160} />
          </div>
        </div>

        {/* Input content inspection */}
        <div className="mt-6 pt-4 border-t border-navy-700/50">
          <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-1.5">
            Analyzed Input Artifact
          </span>
          <div className="bg-navy-950 p-3 rounded-lg border border-navy-800 text-xs font-mono text-gray-200 break-all select-all">
            {result.input_preview}
          </div>
        </div>
      </div>

      {/* URL Specific Decomposition */}
      {result.url_details && (
        <div className="card">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan" /> Structural RFC Decomposition
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Scheme</span>
              <span className="text-white font-bold">{result.url_details.scheme}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Registered Domain</span>
              <span className="text-cyan-light font-bold">
                {result.url_details.registered_domain || 'None'}
              </span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Subdomain Count</span>
              <span className="text-white">{result.url_details.subdomains.length}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Query Parameters</span>
              <span className="text-white">{result.url_details.query_param_count}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg col-span-2">
              <span className="text-gray-500 block">Hostname</span>
              <span className="text-white break-all">{result.url_details.hostname}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg col-span-2">
              <span className="text-gray-500 block">Path</span>
              <span className="text-white break-all">{result.url_details.path || '/'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Email Specific Decomposition */}
      {result.email_details && (
        <div className="card">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <Mail className="h-4 w-4 text-cyan" /> Email Forensics & Header Verification
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Sender Header</span>
              <span className="text-white">{result.email_details.sender || 'Not Specified'}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Reply-To Header</span>
              <span className="text-white">{result.email_details.reply_to || 'None'}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Extracted Embedded URLs</span>
              <span className="text-cyan-light">{result.email_details.extracted_urls.length} link(s) found</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Social Engineering Triggers</span>
              <span className="text-amber-400">
                {[
                  result.email_details.urgency_detected && 'Urgency',
                  result.email_details.credential_harvest_detected && 'Credential Harvest',
                  result.email_details.financial_fraud_detected && 'Financial Fraud',
                ].filter(Boolean).join(', ') || 'None Detected'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Machine Learning Model Diagnostics */}
      {result.ml_result && (
        <div className="card">
          <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan" /> Machine Learning Model Inference
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs mb-4">
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Model Architecture</span>
              <span className="text-white font-mono">{result.ml_result.model_name}</span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Classifier Output</span>
              <span className={`font-bold font-mono ${
                result.ml_result.prediction === 'PHISHING' ? 'text-red-400' : 'text-emerald-400'
              }`}>
                {result.ml_result.prediction || 'N/A'}
              </span>
            </div>
            <div className="p-3 bg-navy-900 rounded-lg">
              <span className="text-gray-500 block">Phishing Probability</span>
              <span className="text-white font-mono">
                {result.ml_result.phishing_probability !== null
                  ? `${(result.ml_result.phishing_probability * 100).toFixed(1)}%`
                  : 'N/A'}
              </span>
            </div>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed bg-navy-900/50 p-3 rounded-lg border border-navy-800">
            <strong>Model Diagnostic Note:</strong> {result.ml_result.notes}
          </p>
        </div>
      )}

      {/* Contributing Findings */}
      <div>
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-cyan" /> Contributing Findings & Heuristic Triggers ({result.findings.length})
        </h2>
        {result.findings.length === 0 ? (
          <div className="card p-6 text-center text-gray-400">
            <CheckCircle className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
            <p className="font-semibold text-white">Clean Threat Profile</p>
            <p className="text-xs text-gray-500">No malicious indicators triggered during rule evaluation.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {result.findings.map((finding, idx) => (
              <FindingsCard key={idx} finding={finding} index={idx} />
            ))}
          </div>
        )}
      </div>

      {/* Transparency: Checks Completed vs Not Performed */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <CheckCircle className="h-4 w-4" /> Checks Completed
          </h3>
          <ul className="space-y-1.5 text-xs text-gray-300">
            {result.checks_completed.map((check, i) => (
              <li key={i} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                {check}
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <HelpCircle className="h-4 w-4" /> Checks Not Performed / Out of Scope
          </h3>
          <ul className="space-y-1.5 text-xs text-gray-500">
            {result.checks_not_performed.map((check, i) => (
              <li key={i} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-gray-600" />
                {check}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Limitations & Legal Disclaimer */}
      <div className="card bg-navy-900/40 border-navy-700/50">
        <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" /> Operational Limitations & Disclaimers
        </h3>
        <ul className="space-y-1 text-xs text-gray-400 list-disc list-inside">
          {result.limitations.map((lim, i) => (
            <li key={i}>{lim}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
