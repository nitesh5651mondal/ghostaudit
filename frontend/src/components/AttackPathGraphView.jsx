import React, { useState } from 'react';
import { 
  GitBranch, 
  ShieldAlert, 
  ArrowRight, 
  Terminal, 
  Server, 
  Database, 
  Globe, 
  Lock, 
  Unlock,
  CheckCircle,
  AlertOctagon
} from 'lucide-react';

export const AttackPathGraphView = ({ onSelectScenario }) => {
  const [selectedNode, setSelectedNode] = useState("app_login");

  const nodes = [
    {
      id: "external_attacker",
      title: "Untrusted Client",
      ip: "192.168.1.105 (Redacted)",
      type: "source",
      icon: Globe,
      status: "Adversary Injection Point",
      color: "border-red-500/50 bg-red-950/20 text-red-400"
    },
    {
      id: "waf_proxy",
      title: "API Gateway / Nginx",
      ip: "Port 443 / SSL Ingress",
      type: "gateway",
      icon: Server,
      status: "Bypassed via Encoded String",
      color: "border-amber-500/50 bg-amber-950/20 text-amber-400"
    },
    {
      id: "app_login",
      title: "Auth Service (verify_session)",
      ip: "auth_service.py:84",
      type: "vulnerability",
      icon: Terminal,
      status: "CWE-89 String Interpolation",
      color: "border-purple-500 bg-purple-950/50 text-purple-300 ring-2 ring-purple-500"
    },
    {
      id: "production_db",
      title: "Core Postgres/SQLite DB",
      ip: "users table / root_admin",
      type: "target",
      icon: Database,
      status: "Unauthorized Session Exfiltration",
      color: "border-cyan-500/50 bg-cyan-950/20 text-cyan-400"
    }
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header description */}
      <div className="p-6 rounded-2xl bg-[#0c0d24] border border-[#1f2248] shadow-xl">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-cyan-400" />
              Autonomous Attack Path & Kill-Chain Vector
            </h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Visualizing how adversaries bridge network perimeters to trigger the vulnerability identified by Argus and Cerberus
            </p>
          </div>
          <span className="text-xs font-mono px-3 py-1 rounded bg-purple-950 border border-purple-500/40 text-purple-300">
            Kill-Chain Phase: Exploitation
          </span>
        </div>
      </div>

      {/* Interactive Kill Chain Flow */}
      <div className="p-8 rounded-2xl bg-[#0a0b1f] border border-[#1f2248] shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-900/10 rounded-full blur-3xl pointer-events-none" />

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 relative z-10">
          {nodes.map((node, idx) => {
            const Icon = node.icon;
            const isSelected = selectedNode === node.id;
            return (
              <div
                key={node.id}
                onClick={() => setSelectedNode(node.id)}
                className={`p-5 rounded-2xl border transition-all cursor-pointer relative ${node.color} ${
                  isSelected ? 'shadow-[0_0_25px_rgba(121,40,202,0.4)] scale-105' : 'hover:border-slate-500'
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 rounded-xl bg-[#080816] border border-white/10">
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/40 border border-white/10">
                    HOP 0{idx + 1}
                  </span>
                </div>

                <h4 className="text-sm font-bold text-white font-sans">{node.title}</h4>
                <p className="text-xs font-mono text-slate-400 mt-1">{node.ip}</p>

                <div className="mt-4 pt-3 border-t border-white/10 text-[11px] font-mono flex items-center gap-1.5">
                  <AlertOctagon className="w-3.5 h-3.5" />
                  <span>{node.status}</span>
                </div>

                {idx < nodes.length - 1 && (
                  <div className="hidden md:flex absolute -right-4 top-1/2 -translate-y-1/2 z-20 w-8 h-8 rounded-full bg-[#12132e] border border-[#1f2248] items-center justify-center text-slate-400">
                    <ArrowRight className="w-4 h-4" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Node Forensics Inspector */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-[#0c0d24] border border-[#1f2248] shadow-xl">
          <h4 className="text-sm font-bold uppercase tracking-wider text-purple-300 font-mono mb-3">
            Adversary Breach Signature Analysis
          </h4>
          <p className="text-xs text-slate-300 leading-relaxed font-sans mb-4">
            The attacker leverages an unparameterized endpoint to bypass WAF signatures. Once inside <code>verify_session()</code>, raw string formatting interpolates user inputs directly into the database query buffer.
          </p>

          <div className="p-3.5 rounded-xl bg-[#08091a] border border-red-500/30 text-xs font-mono text-red-300 space-y-1">
            <div className="font-bold">// Malicious Payload Fingerprint</div>
            <div>POST /api/v1/auth/login</div>
            <div className="text-slate-300">Payload: username="admin' OR '1'='1"</div>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-[#0c0d24] border border-[#1f2248] shadow-xl flex flex-col justify-between">
          <div>
            <h4 className="text-sm font-bold uppercase tracking-wider text-cyan-300 font-mono mb-3">
              Gemma Prometheus Neutralization Strategy
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed font-sans mb-4">
              Agent Prometheus synthesizes a surgical patch to truncate this exact attack hop. By substituting string interpolation with parameterized binding <code>cursor.execute(query, (user_input,))</code>, the exploit vector collapses entirely.
            </p>
          </div>

          <button
            onClick={() => onSelectScenario("1_sql_injection")}
            className="w-full py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold transition-all flex items-center justify-center gap-2"
          >
            <span>LOAD THIS ATTACK HOP INTO LIVE FORENSIC AUDITOR</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
