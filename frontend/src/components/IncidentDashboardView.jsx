import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  CheckCircle2, 
  Clock, 
  Server, 
  Layers, 
  Lock, 
  ExternalLink,
  ChevronRight,
  TrendingUp,
  FileText
} from 'lucide-react';

export const IncidentDashboardView = ({ onSelectIncident }) => {
  const incidentHistory = [
    {
      id: "GHOST-8821B",
      title: "CWE-89: SQL Injection in Session Auth Handler",
      target: "auth_service.py",
      severity: "CRITICAL",
      cvss: 9.4,
      status: "PATCHED",
      agent: "Prometheus",
      time: "24m ago",
      secretsRedacted: 3,
      scenarioKey: "1_sql_injection"
    },
    {
      id: "GHOST-9042F",
      title: "CWE-502: Remote Code Execution via Python Pickle Deserialization",
      target: "cache_manager.py",
      severity: "CRITICAL",
      cvss: 9.8,
      status: "TRIAGED",
      agent: "Cerberus",
      time: "1h 12m ago",
      secretsRedacted: 1,
      scenarioKey: "2_rce_pickle"
    },
    {
      id: "GHOST-6119C",
      title: "CWE-918: SSRF & AWS IAM Metadata Exfiltration",
      target: "webhook_service.py",
      severity: "HIGH",
      cvss: 8.6,
      status: "PATCHED",
      agent: "Prometheus",
      time: "3h 45m ago",
      secretsRedacted: 2,
      scenarioKey: "3_ssrf_metadata"
    },
    {
      id: "GHOST-4320A",
      title: "CWE-798: Plaintext Hardcoded Master Encryption Key",
      target: "db_config.env",
      severity: "HIGH",
      cvss: 8.2,
      status: "REMEDIATED",
      agent: "Argus",
      time: "6h ago",
      secretsRedacted: 4,
      scenarioKey: "1_sql_injection"
    }
  ];

  const systemMetrics = [
    { label: "Active Air-Gapped Clusters", val: "14 Nodes", change: "+2 nodes", up: true },
    { label: "Total Telemetry Ingested", val: "1.42 GB", change: "28k lines/min", up: true },
    { label: "Zero-Trust Tokens Redacted", val: "318 Secrets", change: "100% masked", up: true },
    { label: "Avg Gemma Triage Latency", val: "1.84 sec", change: "-0.3s edge speed", up: true },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {systemMetrics.map((m, idx) => (
          <div key={idx} className="p-5 rounded-2xl bg-[#0c0d24] border border-[#1f2248] shadow-lg flex flex-col justify-between">
            <span className="text-xs text-slate-400 font-mono">{m.label}</span>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="text-2xl font-extrabold text-white font-sans">{m.val}</span>
              <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-500/30">
                {m.change}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Main Incident Feed Table */}
      <div className="p-6 rounded-2xl bg-[#0c0d24] border border-[#1f2248] shadow-xl">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              Real-Time Security Incident Feed
            </h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Autonomous multi-agent triage history triaged locally via Google Gemma
            </p>
          </div>
          <span className="text-xs font-mono px-3 py-1 rounded-full bg-emerald-950 border border-emerald-500/40 text-emerald-300 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            Telemetry Stream Active
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[11px] uppercase tracking-wider text-slate-500 border-b border-[#1f2248] bg-[#08091a]">
              <tr>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Threat Description</th>
                <th className="py-3 px-4">Target File</th>
                <th className="py-3 px-4">CVSS Severity</th>
                <th className="py-3 px-4">Leading Agent</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#16183a]">
              {incidentHistory.map((inc) => (
                <tr key={inc.id} className="hover:bg-[#121330] transition-colors group">
                  <td className="py-3.5 px-4 font-bold text-cyan-400">{inc.id}</td>
                  <td className="py-3.5 px-4 text-slate-200 font-sans font-medium">{inc.title}</td>
                  <td className="py-3.5 px-4 text-purple-300">{inc.target}</td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded font-bold ${
                      inc.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-500/40' : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                    }`}>
                      {inc.cvss} ({inc.severity})
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-300">{inc.agent}</td>
                  <td className="py-3.5 px-4">
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      {inc.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => onSelectIncident(inc.scenarioKey)}
                      className="px-2.5 py-1 rounded bg-purple-600/30 hover:bg-purple-600 text-purple-200 hover:text-white border border-purple-500/40 text-[11px] transition-all"
                    >
                      Inspect &gt;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
