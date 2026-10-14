import React from 'react';
import { Eye, ShieldAlert, Wrench, CheckCircle2, AlertTriangle, Terminal, Code2 } from 'lucide-react';

export const AgentFlow = ({ activeStep, report, isProcessing }) => {
  const steps = [
    {
      id: 1,
      name: 'Pre-Inference Sanitizer',
      subtitle: 'Zero-Trust Redaction Engine',
      icon: Terminal,
      color: 'cyan',
      description: 'Scans & scrubs AWS keys, JWTs, and RFC-1918 IPs locally before LLM prompt assembly.'
    },
    {
      id: 2,
      name: 'Agent Argus',
      subtitle: 'The All-Seeing Log Observer',
      icon: Eye,
      color: 'purple',
      description: 'Isolates crash signatures, microsecond timestamps, stack traces, and malicious payloads.'
    },
    {
      id: 3,
      name: 'Agent Cerberus',
      subtitle: 'The Security & Code Gatekeeper',
      icon: ShieldAlert,
      color: 'pink',
      description: 'Audits source code around culprit site, classifies CWEs, and scores CVSS v3.1 severity.'
    },
    {
      id: 4,
      name: 'Agent Prometheus',
      subtitle: 'The Healer & Patch Synthesizer',
      icon: Wrench,
      color: 'emerald',
      description: 'Autonomously synthesizes unified git diff patches and defense-in-depth hardening.'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {steps.map((step, idx) => {
        const Icon = step.icon;
        const isActive = activeStep === step.id;
        const isDone = activeStep > step.id || (report && !isProcessing);

        let borderGlow = "border-[#1f2248] bg-[#0c0d22]";
        let badgeColor = "bg-slate-800 text-slate-400";

        if (isActive) {
          borderGlow = "border-cyan-500 bg-[#0f1430] shadow-[0_0_20px_rgba(0,240,255,0.2)]";
          badgeColor = "bg-cyan-950 text-cyan-300 border border-cyan-500/50";
        } else if (isDone) {
          borderGlow = "border-purple-500/50 bg-[#0d0f28]";
          badgeColor = "bg-purple-950 text-purple-300 border border-purple-500/40";
        }

        return (
          <div
            key={step.id}
            className={`relative p-5 rounded-xl border transition-all duration-300 flex flex-col justify-between ${borderGlow}`}
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-lg ${isActive ? 'bg-cyan-500/20 text-cyan-400 animate-pulse' : isDone ? 'bg-purple-500/20 text-purple-400' : 'bg-slate-800 text-slate-500'}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full ${badgeColor}`}>
                    STEP 0{step.id}
                  </span>
                </div>
                {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
              </div>

              <h4 className="text-sm font-bold text-white font-sans">{step.name}</h4>
              <p className="text-[11px] text-purple-300/80 font-mono mb-2">{step.subtitle}</p>
              <p className="text-xs text-slate-400 leading-relaxed">{step.description}</p>
            </div>

            {/* Micro status footer */}
            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-500">Status:</span>
              <span className={isActive ? 'text-cyan-400 font-bold' : isDone ? 'text-emerald-400' : 'text-slate-600'}>
                {isActive ? 'ANALYZING...' : isDone ? 'COMPLETED' : 'STANDBY'}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
