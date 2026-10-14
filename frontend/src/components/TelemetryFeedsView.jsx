import React, { useState } from 'react';
import { 
  Activity, 
  Terminal, 
  Search, 
  Filter, 
  Download, 
  ShieldCheck, 
  AlertTriangle,
  Play,
  RotateCcw
} from 'lucide-react';

export const TelemetryFeedsView = ({ onInjectToPipeline }) => {
  const [filterType, setFilterType] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const sampleTelemetryStreams = [
    {
      timestamp: "2026-10-14 02:40:55.104",
      source: "HTTP-Worker-12",
      level: "INFO",
      message: "Incoming POST /api/v1/auth/login from 192.168.1.105 (client_agent: curl/8.4)",
      redacted: false,
      color: "text-slate-400"
    },
    {
      timestamp: "2026-10-14 02:40:55.105",
      source: "auth_service",
      level: "DEBUG",
      message: 'Evaluating user credential payload: username="admin\' OR \'1\'=\'1"',
      redacted: false,
      color: "text-amber-400"
    },
    {
      timestamp: "2026-10-14 02:40:55.120",
      source: "db_session_manager",
      level: "ERROR",
      message: "DB Execution Syntax Warning near ''1'='1'' in raw query buffer",
      redacted: false,
      color: "text-rose-400 font-bold"
    },
    {
      timestamp: "2026-10-14 02:41:09.112",
      source: "auth_service",
      level: "CRITICAL",
      message: "CRITICAL: Master session returned user_id=1 (root_admin) without password validation!",
      redacted: false,
      color: "text-red-400 font-bold"
    },
    {
      timestamp: "2026-10-14 02:41:09.115",
      source: "auth_service",
      level: "WARN",
      message: "Active API key logged: api_key='[REDACTED_SECRET_KEY]'",
      redacted: true,
      color: "text-cyan-400"
    },
    {
      timestamp: "2026-10-14 02:41:09.430",
      source: "HTTP-Worker-12",
      level: "FATAL",
      message: "Session hijacking detected! Token issued: [REDACTED_JWT_TOKEN]",
      redacted: true,
      color: "text-red-500 font-bold"
    },
    {
      timestamp: "2026-10-14 04:12:01.050",
      source: "cache_engine",
      level: "WARNING",
      message: "Deserializing untrusted binary payload from client stream... (pickle.loads)",
      redacted: false,
      color: "text-amber-400"
    },
    {
      timestamp: "2026-10-14 04:12:01.099",
      source: "kernel_audit",
      level: "CRITICAL",
      message: "Spawned unauthorized child subprocess /bin/sh (PID: 49201)",
      redacted: false,
      color: "text-red-400 font-bold"
    }
  ];

  const filtered = sampleTelemetryStreams.filter(item => {
    const matchesFilter = filterType === "ALL" || item.level === filterType;
    const matchesSearch = item.message.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          item.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-[#0c0d24] border border-[#1f2248] shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Live Air-Gapped Telemetry Stream
          </h3>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            High-speed local syslog ingestion with real-time zero-trust token masking
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search syslog buffers..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#08091a] border border-[#1f2248] rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 w-56"
            />
          </div>

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-[#08091a] border border-[#1f2248] rounded-xl px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Levels</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="ERROR">Errors</option>
            <option value="WARNING">Warnings</option>
          </select>
        </div>
      </div>

      {/* Terminal Telemetry Log Output */}
      <div className="p-6 rounded-2xl bg-[#060714] border border-[#1f2248] shadow-2xl font-mono text-xs">
        <div className="flex items-center justify-between border-b border-[#16183a] pb-3 mb-4 text-slate-400 text-[11px]">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/80"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></span>
            <span className="ml-2 text-slate-300">syslog.production.stream (Air-Gapped Listener)</span>
          </div>
          <span>Buffer: {filtered.length} entries</span>
        </div>

        <div className="space-y-2 max-h-[420px] overflow-y-auto pr-2">
          {filtered.map((log, idx) => (
            <div key={idx} className="flex items-start gap-3 py-1 px-2 rounded hover:bg-[#0f112e] transition-colors">
              <span className="text-slate-500 select-none text-[11px]">{log.timestamp}</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                log.level === 'CRITICAL' || log.level === 'FATAL' 
                  ? 'bg-red-950 text-red-300 border border-red-500/40' 
                  : log.level === 'ERROR'
                  ? 'bg-rose-950 text-rose-300'
                  : 'bg-slate-800 text-slate-400'
              }`}>
                {log.level}
              </span>
              <span className="text-purple-400 font-semibold">[{log.source}]</span>
              <span className={`flex-1 ${log.color}`}>{log.message}</span>
              {log.redacted && (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-950 border border-cyan-500/40 text-cyan-300">
                  MASKED
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Quick Action Button */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-purple-950/40 to-[#0c0d24] border border-purple-500/30 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span className="text-xs text-slate-300 font-sans">
            Want to triage these raw telemetry frames with Gemma Agent Argus right now?
          </span>
        </div>

        <button
          onClick={onInjectToPipeline}
          className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#080816] font-mono text-xs font-bold transition-all flex items-center gap-1.5 shadow-[0_0_15px_rgba(0,240,255,0.3)]"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>PIPE LOGS TO GEMMA TRIAGE</span>
        </button>
      </div>
    </div>
  );
};
