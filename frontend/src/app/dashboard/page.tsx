'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  RefreshCw,
  Search,
  TrendingUp,
  FileText,
  BarChart2,
  PieChart as PieChartIcon,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';
import { getDashboardStats, seedDemoData, resetDemoData } from '@/lib/api';
import type { DashboardStats } from '@/types';
import LoadingSpinner from '@/components/LoadingSpinner';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MODERATE: '#f59e0b',
  LOW: '#10b981',
};

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const data = await getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard statistics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleSeed = async () => {
    setSeeding(true);
    setMessage(null);
    try {
      const res = await seedDemoData();
      setMessage(res.message);
      await fetchStats();
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : 'Failed to seed sample scans.');
    } finally {
      setSeeding(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Are you sure you want to clear scan history?')) return;
    setSeeding(true);
    setMessage(null);
    try {
      const res = await resetDemoData();
      setMessage(res.message);
      await fetchStats();
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : 'Failed to reset scan data.');
    } finally {
      setSeeding(false);
    }
  };

  if (loading && !stats) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-20 text-center">
        <LoadingSpinner text="Loading threat intelligence metrics..." />
      </div>
    );
  }

  // Format data for Recharts
  const severityPieData = stats
    ? Object.entries(stats.severity_distribution || {}).map(([key, value]) => ({
        name: key,
        value,
        color: SEVERITY_COLORS[key] || '#94a3b8',
      }))
    : [];

  const typeBarData = stats
    ? Object.entries(stats.scans_by_type || {}).map(([key, value]) => ({
        name: key.toUpperCase(),
        count: value,
      }))
    : [];

  const trendData = stats?.recent_trend || [];

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan/10 border border-cyan/20 text-cyan text-xs font-semibold uppercase tracking-wider mb-2">
            <Activity className="h-3.5 w-3.5" /> SOC Overview & Telemetry
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">Security Analytics</h1>
          <p className="text-gray-400 mt-1">
            Aggregated threat intelligence, scan distributions, and heuristic detection telemetry.
          </p>
        </div>

        {/* Database Quick Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={fetchStats}
            disabled={loading}
            className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5"
            title="Refresh statistics"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <button
            onClick={handleSeed}
            disabled={seeding}
            className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5 border-cyan/30 text-cyan"
            title="Seed demo telemetry records"
          >
            <Database className="h-3.5 w-3.5" /> {seeding ? 'Processing...' : 'Seed Sample Data'}
          </button>
          <button
            onClick={handleReset}
            disabled={seeding}
            className="btn-danger py-2 px-3 text-xs flex items-center gap-1.5"
            title="Purge scan history"
          >
            Purge History
          </button>
        </div>
      </div>

      {message && (
        <div className="p-3 mb-6 rounded-lg bg-navy-800 border border-cyan/30 text-cyan-light text-xs flex items-center gap-2">
          <CheckCircle className="h-4 w-4 text-cyan" />
          <span>{message}</span>
        </div>
      )}

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="card p-5 border-l-4 border-l-cyan">
          <span className="text-xs text-gray-400 font-medium">Total Scans Executed</span>
          <div className="text-3xl font-bold text-white mt-1">
            {stats?.total_scans || 0}
          </div>
          <span className="text-[11px] text-gray-500 mt-2 block">All vectors combined</span>
        </div>

        <div className="card p-5 border-l-4 border-l-red-500">
          <span className="text-xs text-red-400 font-medium">Critical Threats</span>
          <div className="text-3xl font-bold text-red-300 mt-1">
            {stats?.critical_risk_count || 0}
          </div>
          <span className="text-[11px] text-gray-500 mt-2 block">Risk score &gt;= 75</span>
        </div>

        <div className="card p-5 border-l-4 border-l-orange-500">
          <span className="text-xs text-orange-400 font-medium">High / Moderate Risk</span>
          <div className="text-3xl font-bold text-orange-300 mt-1">
            {(stats?.high_risk_count || 0) + (stats?.moderate_risk_count || 0)}
          </div>
          <span className="text-[11px] text-gray-500 mt-2 block">Suspicious indicators detected</span>
        </div>

        <div className="card p-5 border-l-4 border-l-emerald-500">
          <span className="text-xs text-emerald-400 font-medium">Low / Benign</span>
          <div className="text-3xl font-bold text-emerald-300 mt-1">
            {stats?.low_risk_count || 0}
          </div>
          <span className="text-[11px] text-gray-500 mt-2 block">Clean or minimal findings</span>
        </div>
      </div>

      {stats && stats.total_scans > 0 ? (
        <>
          {/* Charts Row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Severity Distribution Pie */}
            <div className="card p-6">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <PieChartIcon className="h-4 w-4 text-cyan" /> Severity Classification Ratio
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityPieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      innerRadius={45}
                      paddingAngle={4}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {severityPieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                      itemStyle={{ color: '#f8fafc', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Scans by Type Bar Chart */}
            <div className="card p-6">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <BarChart2 className="h-4 w-4 text-cyan" /> Scans By Attack Surface
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={typeBarData}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                      itemStyle={{ color: '#f8fafc', fontSize: '12px' }}
                    />
                    <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Top Triggered Heuristic Rules */}
          <div className="card p-6 mb-8">
            <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-cyan" /> Most Frequently Triggered Detection Rules
            </h3>
            {stats.top_triggered_rules && stats.top_triggered_rules.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy-900 text-gray-400 uppercase font-mono">
                    <tr>
                      <th className="py-2.5 px-4 rounded-l">Rule Identifier</th>
                      <th className="py-2.5 px-4">Severity Weight</th>
                      <th className="py-2.5 px-4 text-right rounded-r">Trigger Count</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-700/50">
                    {stats.top_triggered_rules.map((rule, idx) => (
                      <tr key={idx} className="hover:bg-navy-700/30">
                        <td className="py-3 px-4 font-mono text-cyan-light font-medium">
                          {rule.rule_id}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            rule.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            rule.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                            rule.severity === 'MODERATE' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {rule.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right font-bold text-white">
                          {rule.count}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-xs text-gray-500 italic">No heuristic rules triggered yet.</p>
            )}
          </div>
        </>
      ) : (
        <div className="card p-12 text-center">
          <Database className="h-12 w-12 text-gray-600 mx-auto mb-3" />
          <h3 className="text-lg font-bold text-white">No Telemetry Recorded Yet</h3>
          <p className="text-xs text-gray-400 max-w-sm mx-auto mt-1 mb-6">
            Execute scans using the scanner console, or click below to populate the dashboard with realistic demonstration data.
          </p>
          <div className="flex justify-center gap-3">
            <button
              onClick={handleSeed}
              disabled={seeding}
              className="btn-primary text-xs flex items-center gap-2"
            >
              <Database className="h-4 w-4" /> Seed Sample Scans
            </button>
            <Link href="/scanner" className="btn-secondary text-xs flex items-center gap-2">
              <Search className="h-4 w-4" /> Open Scanner
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
