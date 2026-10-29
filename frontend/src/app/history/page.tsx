'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  History,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  Shield,
  RefreshCw,
  FileText,
  AlertTriangle,
} from 'lucide-react';
import { getScanHistory, deleteScan } from '@/lib/api';
import type { ScanHistorySummary } from '@/types';
import SeverityBadge from '@/components/SeverityBadge';
import LoadingSpinner from '@/components/LoadingSpinner';
import EmptyState from '@/components/EmptyState';
import { formatDate, truncateText } from '@/lib/utils';

export default function HistoryPage() {
  const [history, setHistory] = useState<ScanHistorySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await getScanHistory();
      setHistory(data);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleDelete = async (scanId: string) => {
    if (!confirm('Are you sure you want to delete this scan record?')) return;
    setDeletingId(scanId);
    try {
      await deleteScan(scanId);
      setHistory((prev) => prev.filter((item) => item.scan_id !== scanId));
    } catch (err) {
      alert('Failed to delete scan record.');
    } finally {
      setDeletingId(null);
    }
  };

  // Filter logic
  const filteredHistory = history.filter((item) => {
    const matchesSearch =
      item.input_preview.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.scan_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.summary.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesType = typeFilter === 'all' || item.scan_type.toLowerCase() === typeFilter.toLowerCase();
    const matchesSeverity = severityFilter === 'all' || item.severity === severityFilter;

    return matchesSearch && matchesType && matchesSeverity;
  });

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan/10 border border-cyan/20 text-cyan text-xs font-semibold uppercase tracking-wider mb-2">
            <History className="h-3.5 w-3.5" /> Audit Log
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">Scan History</h1>
          <p className="text-gray-400 mt-1">
            Historical threat assessments, risk scores, and forensic artifacts.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          disabled={loading}
          className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5 self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="card p-4 mb-6">
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
          <div className="relative w-full md:w-80">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search input, ID, summary..."
              className="input-field py-2 pl-9 text-xs"
            />
            <Search className="h-4 w-4 text-gray-500 absolute left-3 top-2.5" />
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Filter className="h-3.5 w-3.5" /> Filter:
            </div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-navy-900 border border-navy-700 text-gray-200 text-xs rounded-lg px-2.5 py-2"
            >
              <option value="all">All Vectors</option>
              <option value="url">URL Scans</option>
              <option value="email">Email Scans</option>
              <option value="message">SMS / Chat</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-navy-900 border border-navy-700 text-gray-200 text-xs rounded-lg px-2.5 py-2"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MODERATE">Moderate</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* History Table */}
      {loading ? (
        <LoadingSpinner text="Retrieving historical logs..." />
      ) : filteredHistory.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No Matching Scan Records"
          description="Try adjusting your filter criteria or execute new scans through the scanner interface."
          action={
            <Link href="/scanner" className="btn-primary text-xs">
              Open Scanner
            </Link>
          }
        />
      ) : (
        <div className="card overflow-hidden p-0 border-navy-700/50">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-navy-900 text-gray-400 uppercase font-mono border-b border-navy-700/50">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Vector</th>
                  <th className="py-3 px-4">Input Preview</th>
                  <th className="py-3 px-4 text-center">Score</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4 text-center">Findings</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-700/40">
                {filteredHistory.map((item) => (
                  <tr key={item.scan_id} className="hover:bg-navy-700/20 transition-colors">
                    <td className="py-3.5 px-4 text-gray-400 whitespace-nowrap">
                      {formatDate(item.timestamp)}
                    </td>
                    <td className="py-3.5 px-4 font-semibold capitalize text-cyan-light">
                      {item.scan_type}
                    </td>
                    <td className="py-3.5 px-4 max-w-xs font-mono text-gray-300 truncate" title={item.input_preview}>
                      {truncateText(item.input_preview, 45)}
                    </td>
                    <td className="py-3.5 px-4 text-center font-bold text-white">
                      {item.risk_score}
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td className="py-3.5 px-4 text-center text-gray-400">
                      {item.finding_count}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          href={`/results/${item.scan_id}`}
                          className="p-1.5 rounded hover:bg-navy-700 text-gray-400 hover:text-cyan transition-colors"
                          title="View Full Report"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </Link>
                        <button
                          onClick={() => handleDelete(item.scan_id)}
                          disabled={deletingId === item.scan_id}
                          className="p-1.5 rounded hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors"
                          title="Delete Record"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="p-3 bg-navy-900/60 border-t border-navy-700/50 text-right text-xs text-gray-500">
            Showing {filteredHistory.length} of {history.length} scans
          </div>
        </div>
      )}
    </div>
  );
}
