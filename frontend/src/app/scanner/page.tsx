'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Globe,
  Mail,
  MessageSquare,
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  FileDown,
  Sparkles,
  ExternalLink,
  ChevronRight,
  Info,
  RefreshCw,
  Cpu,
  Layers,
} from 'lucide-react';
import RiskGauge from '@/components/RiskGauge';
import SeverityBadge from '@/components/SeverityBadge';
import FindingsCard from '@/components/FindingsCard';
import LoadingSpinner from '@/components/LoadingSpinner';
import {
  scanUrl,
  scanEmail,
  scanMessage,
  getDemoSamples,
  exportReport,
} from '@/lib/api';
import type { ScanResult, DemoSample } from '@/types';
import { formatDate } from '@/lib/utils';

export default function ScannerPage() {
  const [activeTab, setActiveTab] = useState<'url' | 'email' | 'message'>('url');

  // URL state
  const [urlInput, setUrlInput] = useState('');
  const [enableMl, setEnableMl] = useState(true);
  const [enableThreatIntel, setEnableThreatIntel] = useState(true);

  // Email state
  const [emailContent, setEmailContent] = useState('');
  const [emailSender, setEmailSender] = useState('');
  const [emailDisplayName, setEmailDisplayName] = useState('');
  const [emailReplyTo, setEmailReplyTo] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [showAdvancedEmail, setShowAdvancedEmail] = useState(false);

  // Message state
  const [messageContent, setMessageContent] = useState('');
  const [sourceHint, setSourceHint] = useState('sms');

  // Shared state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [demoSamples, setDemoSamples] = useState<DemoSample[]>([]);

  useEffect(() => {
    getDemoSamples()
      .then((samples) => setDemoSamples(samples))
      .catch(() => {});
  }, []);

  const handleUrlScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await scanUrl(urlInput.trim(), enableMl, enableThreatIntel);
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please check the backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleEmailScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailContent.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await scanEmail({
        content: emailContent.trim(),
        sender: emailSender.trim() || undefined,
        display_name: emailDisplayName.trim() || undefined,
        reply_to: emailReplyTo.trim() || undefined,
        subject: emailSubject.trim() || undefined,
      });
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please check the backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleMessageScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!messageContent.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await scanMessage(messageContent.trim(), sourceHint);
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please check the backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (sample: DemoSample) => {
    setResult(null);
    setError(null);
    if (sample.type === 'url' && sample.input.url) {
      setActiveTab('url');
      setUrlInput(sample.input.url);
    } else if (sample.type === 'email') {
      setActiveTab('email');
      setEmailContent(sample.input.content || '');
      setEmailSender(sample.input.sender || '');
      setEmailDisplayName(sample.input.display_name || '');
      setEmailSubject(sample.input.subject || '');
    } else if (sample.type === 'message') {
      setActiveTab('message');
      setMessageContent(sample.input.message || '');
      setSourceHint(sample.input.source_hint || 'sms');
    }
  };

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
    } catch (err) {
      alert('Failed to download report');
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Title */}
      <div className="mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan/10 border border-cyan/20 text-cyan text-xs font-semibold uppercase tracking-wider mb-2">
          <Shield className="h-3.5 w-3.5" /> Threat Detection Console
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">Security Scanner</h1>
        <p className="text-gray-400 mt-1">
          Perform multi-vector phishing analysis on suspicious URLs, emails, and SMS/chat messages.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-navy-700/60 mb-6 gap-2">
        <button
          onClick={() => { setActiveTab('url'); setResult(null); setError(null); }}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'url'
              ? 'border-cyan text-cyan bg-navy-900/50'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-navy-600'
          }`}
        >
          <Globe className="h-4 w-4" /> URL Analysis
        </button>
        <button
          onClick={() => { setActiveTab('email'); setResult(null); setError(null); }}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'email'
              ? 'border-cyan text-cyan bg-navy-900/50'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-navy-600'
          }`}
        >
          <Mail className="h-4 w-4" /> Email Analysis
        </button>
        <button
          onClick={() => { setActiveTab('message'); setResult(null); setError(null); }}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'message'
              ? 'border-cyan text-cyan bg-navy-900/50'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-navy-600'
          }`}
        >
          <MessageSquare className="h-4 w-4" /> SMS / Message
        </button>
      </div>

      {/* Demo Samples Quick Load */}
      {demoSamples.length > 0 && !result && (
        <div className="mb-6 p-4 rounded-xl bg-navy-900/60 border border-navy-700/40">
          <div className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2.5">
            <Sparkles className="h-3.5 w-3.5 text-cyan" /> Load Test Scenario:
          </div>
          <div className="flex flex-wrap gap-2">
            {demoSamples.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => loadSample(sample)}
                className="px-3 py-1.5 rounded-lg text-xs bg-navy-800 hover:bg-navy-700 border border-navy-700 hover:border-cyan/40 text-gray-300 transition-all text-left flex items-center gap-1.5"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-cyan" />
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input Forms */}
      <div className="card mb-8">
        {activeTab === 'url' && (
          <form onSubmit={handleUrlScan} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                Target URL to Inspect
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="e.g. http://192.168.1.1/login or https://secure-paypal-verify.com/login"
                  className="input-field pl-11"
                  required
                />
                <Globe className="h-5 w-5 text-gray-500 absolute left-3.5 top-3.5" />
              </div>
              <p className="text-xs text-gray-500 mt-1.5">
                Note: Safe inspection only. URLs are lexically parsed; no outbound connections or payload downloads occur.
              </p>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-navy-700/50">
              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableMl}
                    onChange={(e) => setEnableMl(e.target.checked)}
                    className="rounded bg-navy-900 border-navy-600 text-cyan focus:ring-cyan h-4 w-4"
                  />
                  <span>ML Feature Classification</span>
                </label>
                <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableThreatIntel}
                    onChange={(e) => setEnableThreatIntel(e.target.checked)}
                    className="rounded bg-navy-900 border-navy-600 text-cyan focus:ring-cyan h-4 w-4"
                  />
                  <span>Threat Intelligence Lookup</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={loading || !urlInput.trim()}
                className="btn-primary py-2.5 px-6 text-sm"
              >
                {loading ? <LoadingSpinner text="Analyzing..." /> : (
                  <>
                    <Search className="h-4 w-4" /> Run Deep URL Scan
                  </>
                )}
              </button>
            </div>
          </form>
        )}

        {activeTab === 'email' && (
          <form onSubmit={handleEmailScan} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                Email Content / Body <span className="text-red-400">*</span>
              </label>
              <textarea
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="Paste the suspicious email body text here..."
                rows={6}
                className="textarea-field w-full font-mono text-xs"
                required
              />
            </div>

            <button
              type="button"
              onClick={() => setShowAdvancedEmail(!showAdvancedEmail)}
              className="text-xs text-cyan flex items-center gap-1 hover:underline font-medium"
            >
              {showAdvancedEmail ? 'Hide Headers / Metadata' : '+ Add Sender Metadata (Subject, Sender, Reply-To)'}
            </button>

            {showAdvancedEmail && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 rounded-lg bg-navy-900/60 border border-navy-700/40">
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">Subject</label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    placeholder="e.g. Urgent: Your account is locked"
                    className="input-field py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">Display Name</label>
                  <input
                    type="text"
                    value={emailDisplayName}
                    onChange={(e) => setEmailDisplayName(e.target.value)}
                    placeholder="e.g. PayPal Security Team"
                    className="input-field py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">Sender Address (From)</label>
                  <input
                    type="text"
                    value={emailSender}
                    onChange={(e) => setEmailSender(e.target.value)}
                    placeholder="e.g. security@paypa1-update.com"
                    className="input-field py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">Reply-To Address</label>
                  <input
                    type="text"
                    value={emailReplyTo}
                    onChange={(e) => setEmailReplyTo(e.target.value)}
                    placeholder="e.g. hacker123@gmail.com"
                    className="input-field py-2 text-xs"
                  />
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-navy-700/50">
              <button
                type="submit"
                disabled={loading || !emailContent.trim()}
                className="btn-primary py-2.5 px-6 text-sm"
              >
                {loading ? <LoadingSpinner text="Analyzing..." /> : (
                  <>
                    <Search className="h-4 w-4" /> Analyze Email Content
                  </>
                )}
              </button>
            </div>
          </form>
        )}

        {activeTab === 'message' && (
          <form onSubmit={handleMessageScan} className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-sm font-medium text-gray-300">
                  SMS / Chat Message
                </label>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-400">Platform:</span>
                  <select
                    value={sourceHint}
                    onChange={(e) => setSourceHint(e.target.value)}
                    className="bg-navy-900 border border-navy-700 text-gray-200 text-xs rounded px-2 py-1"
                  >
                    <option value="sms">SMS / Text</option>
                    <option value="whatsapp">WhatsApp</option>
                    <option value="telegram">Telegram</option>
                    <option value="chat">Internal Chat</option>
                  </select>
                </div>
              </div>
              <textarea
                value={messageContent}
                onChange={(e) => setMessageContent(e.target.value)}
                placeholder="e.g. USPS: Your package could not be delivered due to missing house number. Please update here: http://bit.ly/usps-track-93"
                rows={4}
                className="textarea-field w-full text-xs font-mono"
                required
              />
            </div>

            <div className="flex justify-end pt-2 border-t border-navy-700/50">
              <button
                type="submit"
                disabled={loading || !messageContent.trim()}
                className="btn-primary py-2.5 px-6 text-sm"
              >
                {loading ? <LoadingSpinner text="Analyzing..." /> : (
                  <>
                    <Search className="h-4 w-4" /> Analyze Message
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-start gap-3 mb-8">
          <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-red-200">Analysis Error</div>
            <p className="mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div className="space-y-8 animate-in fade-in duration-300">
          {/* Header Banner */}
          <div className="card border-l-4 border-l-cyan">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-bold text-white">Analysis Verdict</h2>
                  <SeverityBadge severity={result.severity} size="md" />
                  <span className="text-xs bg-navy-700 text-gray-300 px-2.5 py-1 rounded-md font-mono">
                    ID: {result.scan_id.slice(0, 8)}
                  </span>
                </div>
                <p className="text-sm text-gray-300 mt-2">{result.summary}</p>
                <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500 mt-3">
                  <span>Type: <strong className="text-gray-300 capitalize">{result.scan_type}</strong></span>
                  <span>Scanned: <strong className="text-gray-300">{formatDate(result.timestamp)}</strong></span>
                  <span>Engine: <strong className="text-cyan">{result.analysis_mode}</strong></span>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex items-center gap-2 self-end md:self-auto">
                <button
                  onClick={() => handleExport('json')}
                  className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5"
                  title="Export JSON report"
                >
                  <FileDown className="h-3.5 w-3.5" /> Export JSON
                </button>
                <button
                  onClick={() => handleExport('html')}
                  className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5"
                  title="Export printable HTML report"
                >
                  <FileDown className="h-3.5 w-3.5" /> Export HTML
                </button>
                <Link
                  href={`/results/${result.scan_id}`}
                  className="btn-primary py-2 px-3 text-xs flex items-center gap-1.5"
                >
                  Full Report <ChevronRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          </div>

          {/* Risk Overview Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Risk Gauge */}
            <div className="card flex flex-col items-center justify-center p-6 text-center">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Overall Risk Score
              </span>
              <RiskGauge score={result.risk_score} size={200} />
              <p className="text-xs text-gray-400 mt-3 max-w-xs">
                Derived via probabilistic independent risk union across all detected heuristic indicators.
              </p>
            </div>

            {/* Findings Summary */}
            <div className="card p-6 flex flex-col justify-between">
              <div>
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Findings Breakdown
                </span>
                <div className="grid grid-cols-2 gap-3 mt-4">
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <span className="text-xs text-red-400 block font-medium">Critical</span>
                    <span className="text-2xl font-bold text-red-300">
                      {result.risk_breakdown.rule_counts_by_severity.CRITICAL || 0}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                    <span className="text-xs text-orange-400 block font-medium">High</span>
                    <span className="text-2xl font-bold text-orange-300">
                      {result.risk_breakdown.rule_counts_by_severity.HIGH || 0}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <span className="text-xs text-amber-400 block font-medium">Moderate</span>
                    <span className="text-2xl font-bold text-amber-300">
                      {result.risk_breakdown.rule_counts_by_severity.MODERATE || 0}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                    <span className="text-xs text-emerald-400 block font-medium">Low</span>
                    <span className="text-2xl font-bold text-emerald-300">
                      {result.risk_breakdown.rule_counts_by_severity.LOW || 0}
                    </span>
                  </div>
                </div>
              </div>
              <div className="text-xs text-gray-500 mt-4 pt-3 border-t border-navy-700/50">
                Total Indicators Evaluated: {result.findings.length}
              </div>
            </div>

            {/* Machine Learning / Intel Status */}
            <div className="card p-6 flex flex-col justify-between">
              <div>
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Cpu className="h-3.5 w-3.5 text-cyan" /> ML Classifier Verdict
                </span>
                {result.ml_result ? (
                  <div className="mt-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-400">Classification:</span>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                        result.ml_result.prediction === 'PHISHING'
                          ? 'bg-red-500/20 text-red-400'
                          : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {result.ml_result.prediction}
                      </span>
                    </div>
                    {result.ml_result.phishing_probability !== null && (
                      <div>
                        <div className="flex justify-between text-xs text-gray-400 mb-1">
                          <span>Phishing Probability:</span>
                          <span className="text-white font-mono">
                            {(result.ml_result.phishing_probability * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div className="w-full bg-navy-900 rounded-full h-2">
                          <div
                            className="bg-cyan h-2 rounded-full transition-all duration-500"
                            style={{ width: `${result.ml_result.phishing_probability * 100}%` }}
                          />
                        </div>
                      </div>
                    )}
                    <p className="text-xs text-gray-400 leading-relaxed italic">
                      {result.ml_result.notes}
                    </p>
                  </div>
                ) : (
                  <div className="text-xs text-gray-500 mt-4">
                    Machine learning model not engaged or applicable for this scan vector.
                  </div>
                )}
              </div>

              {result.threat_intel && result.threat_intel.length > 0 && (
                <div className="text-xs pt-3 border-t border-navy-700/50 mt-4">
                  <span className="text-gray-400">Threat Intel Feeds:</span>
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {result.threat_intel.map((ti, i) => (
                      <span
                        key={i}
                        className={`px-2 py-0.5 rounded text-[11px] font-mono ${
                          ti.status === 'MALICIOUS'
                            ? 'bg-red-500/20 text-red-400'
                            : 'bg-navy-700 text-gray-300'
                        }`}
                      >
                        {ti.provider}: {ti.status}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Key Findings List */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-cyan" />
                Detected Security Indicators ({result.findings.length})
              </h3>
            </div>

            {result.findings.length === 0 ? (
              <div className="card p-8 text-center text-gray-400">
                <CheckCircle className="h-10 w-10 text-emerald-400 mx-auto mb-2" />
                <p className="font-semibold text-white">No Suspicious Indicators Detected</p>
                <p className="text-xs text-gray-500 mt-1">
                  The submitted content did not trigger any established phishing heuristics.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {result.findings.map((f, idx) => (
                  <FindingsCard key={idx} finding={f} index={idx} />
                ))}
              </div>
            )}
          </div>

          {/* Technical Details Inspection */}
          {result.url_details && (
            <div className="card">
              <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyan" /> URL Structural Decomposition
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                <div className="p-3 bg-navy-900 rounded-lg">
                  <span className="text-gray-500 block">Registered Domain</span>
                  <span className="text-cyan-light font-bold text-sm">
                    {result.url_details.registered_domain || 'N/A'}
                  </span>
                </div>
                <div className="p-3 bg-navy-900 rounded-lg">
                  <span className="text-gray-500 block">Hostname</span>
                  <span className="text-white break-all">{result.url_details.hostname}</span>
                </div>
                <div className="p-3 bg-navy-900 rounded-lg">
                  <span className="text-gray-500 block">Entropy (Shannon)</span>
                  <span className="text-white">{result.url_details.shannon_entropy.toFixed(2)}</span>
                </div>
                <div className="p-3 bg-navy-900 rounded-lg">
                  <span className="text-gray-500 block">Direct IP Host?</span>
                  <span className={result.url_details.is_ip_address ? 'text-red-400 font-bold' : 'text-gray-400'}>
                    {result.url_details.is_ip_address ? 'YES' : 'NO'}
                  </span>
                </div>
                <div className="p-3 bg-navy-900 rounded-lg">
                  <span className="text-gray-500 block">Known URL Shortener?</span>
                  <span className={result.url_details.is_shortener ? 'text-amber-400 font-bold' : 'text-gray-400'}>
                    {result.url_details.is_shortener ? 'YES' : 'NO'}
                  </span>
                </div>
                <div className="p-3 bg-navy-900 rounded-lg">
                  <span className="text-gray-500 block">Punycode / Homograph?</span>
                  <span className={result.url_details.is_punycode ? 'text-red-400 font-bold' : 'text-gray-400'}>
                    {result.url_details.is_punycode ? 'YES' : 'NO'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Recommendations & Defensive Actions */}
          {result.recommendations.length > 0 && (
            <div className="card bg-navy-900/60 border border-cyan/20">
              <h3 className="text-base font-bold text-white mb-3 flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan" /> Recommended Security Actions
              </h3>
              <ul className="space-y-2">
                {result.recommendations.map((action, i) => (
                  <li key={i} className="text-xs text-gray-300 flex items-start gap-2.5">
                    <CheckCircle className="h-4 w-4 text-cyan shrink-0 mt-0.5" />
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Reset Scan button */}
          <div className="flex justify-center pt-4">
            <button
              onClick={() => {
                setResult(null);
                setUrlInput('');
                setEmailContent('');
                setMessageContent('');
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }}
              className="btn-secondary text-sm flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" /> Start New Scan
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
