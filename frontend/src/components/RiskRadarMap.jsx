import React, { useMemo } from 'react';

/**
 * Animated Risk Proximity Radar Map
 * Directly inspired by the CyberX security operations radial visualization.
 * Features:
 * - Counter-rotating orbital rings for continuous dynamic movement
 * - Orbiting nodes with pulsing sizes, glowing blurs, and shifting radial paths
 * - Real-time updates matching the latest executed scenario & CVSS score
 */
export const RiskRadarMap = ({ 
  criticalCount = 157, 
  severity = "CRITICAL", 
  cvss = 9.4, 
  latestIncident = "CWE-89: SQL Injection",
  isAuditing = false 
}) => {
  // Generate multi-orbit node structure with individual orbital velocities & phases
  const rings = useMemo(() => {
    const ringCount = 8;
    const generated = [];

    const colors = [
      '#00F0FF', // Cyan (low exposure)
      '#7928CA', // Deep Purple (triaged)
      '#A855F7', // Violet
      '#3B82F6', // Blue
      '#EC4899', // Pink (exploitable)
      '#EF4444', // Red (critical breach)
      '#94A3B8', // White/Slate
    ];

    for (let r = 1; r <= ringCount; r++) {
      const radius = 62 + r * 28;
      const nodesInRing = 10 + r * 5;
      const nodes = [];

      for (let i = 0; i < nodesInRing; i++) {
        const angle = (i / nodesInRing) * 2 * Math.PI;
        // Prioritize red and pink nodes if CVSS is critical
        const color = cvss >= 9.0 && (i % 4 === 0) 
          ? '#EF4444' 
          : colors[(i + r * 3) % colors.length];

        const baseSize = (i % 3 === 0) ? 5 : (i % 2 === 0 ? 4 : 3);
        const opacity = 0.45 + ((i * 17) % 55) / 100;

        nodes.push({
          angle,
          radius,
          x: 300 + Math.cos(angle) * radius,
          y: 300 + Math.sin(angle) * radius,
          color,
          size: baseSize,
          opacity,
          pulseDelay: (i % 5) * 0.4
        });
      }

      // Alternate clockwise and counter-clockwise orbital rotation speeds
      const animationSpeed = (r % 2 === 0) ? `${18 + r * 4}s` : `${24 + r * 3}s`;
      const reverse = r % 2 === 1;

      generated.push({ 
        radius, 
        nodes, 
        animationSpeed, 
        reverse, 
        ringIdx: r 
      });
    }
    return generated;
  }, [cvss]);

  return (
    <div className="relative w-full h-[550px] flex items-center justify-center overflow-hidden rounded-2xl bg-gradient-to-b from-[#0c0d24] via-[#090a1a] to-[#060714] border border-[#1f2248] shadow-2xl">
      {/* Background radial glow that reacts to severity */}
      <div className={`absolute w-[460px] h-[460px] rounded-full blur-3xl pointer-events-none transition-all duration-1000 ${
        cvss >= 9.0 ? 'bg-red-950/25' : 'bg-purple-900/20'
      }`} />
      <div className="absolute w-[260px] h-[260px] rounded-full bg-cyan-900/15 blur-2xl pointer-events-none" />

      {/* SVG Canvas for Rings & Animated Nodes */}
      <svg className="w-[600px] h-[600px] absolute" viewBox="0 0 600 600">
        <defs>
          <radialGradient id="radarCenterGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#7928CA" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#080816" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="sweepGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#7928CA" stopOpacity="0" />
            <stop offset="80%" stopColor="#00F0FF" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#00F0FF" stopOpacity="0.9" />
          </linearGradient>
        </defs>

        {/* Concentric stationary track rings */}
        {rings.map((ring, idx) => (
          <circle
            key={`ring-track-${idx}`}
            cx="300"
            cy="300"
            r={ring.radius}
            fill="none"
            stroke="rgba(107, 70, 193, 0.16)"
            strokeWidth="1"
            strokeDasharray={idx % 2 === 0 ? "3, 5" : "none"}
          />
        ))}

        {/* Outer radial ticks */}
        {Array.from({ length: 64 }).map((_, i) => {
          const angle = (i / 64) * 2 * Math.PI;
          const x1 = 300 + Math.cos(angle) * 290;
          const y1 = 300 + Math.sin(angle) * 290;
          const x2 = 300 + Math.cos(angle) * 296;
          const y2 = 300 + Math.sin(angle) * 296;
          return (
            <line
              key={`tick-${i}`}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke="rgba(148, 163, 184, 0.18)"
              strokeWidth="1.5"
            />
          );
        })}

        {/* High-speed rotating radar sweep beam */}
        <g className="origin-center animate-spin-slow">
          <line
            x1="300"
            y1="300"
            x2="590"
            y2="300"
            stroke="url(#sweepGrad)"
            strokeWidth="2.5"
          />
          {/* Faint radar sweep sector shadow */}
          <polygon
            points="300,300 590,300 580,260"
            fill="rgba(0, 240, 255, 0.04)"
          />
        </g>

        {/* Counter-Rotating Orbital Rings with Animated Moving Nodes */}
        {rings.map((ring, rIdx) => (
          <g
            key={`orbit-group-${rIdx}`}
            className="origin-center"
            style={{
              transformOrigin: '300px 300px',
              animation: `${ring.reverse ? 'spin-reverse' : 'spin'} ${ring.animationSpeed} linear infinite`
            }}
          >
            {ring.nodes.map((node, nIdx) => (
              <g key={`node-g-${nIdx}`}>
                {/* Node outer pulsing halo for critical threats */}
                {(node.color === '#EF4444' || node.color === '#EC4899') && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={node.size + 3}
                    fill={node.color}
                    opacity="0.25"
                    className="animate-ping"
                    style={{ animationDuration: '3s', animationDelay: `${node.pulseDelay}s` }}
                  />
                )}
                {/* Core particle */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.size}
                  fill={node.color}
                  opacity={node.opacity}
                  className="radar-node cursor-pointer transition-transform hover:scale-150"
                >
                  <title>{`Cluster Node: ${node.color} (CVSS Risk Orbit: ${cvss})`}</title>
                </circle>
              </g>
            ))}
          </g>
        ))}
      </svg>

      {/* Central Metric HUD that updates dynamically */}
      <div className={`relative z-10 flex flex-col items-center justify-center text-center p-6 rounded-full w-52 h-52 bg-[#0a0b1f]/95 border transition-all duration-500 backdrop-blur-md shadow-2xl ${
        isAuditing 
          ? 'border-cyan-400 shadow-[0_0_35px_rgba(0,240,255,0.4)]' 
          : cvss >= 9.0 
          ? 'border-red-500/50 shadow-[0_0_30px_rgba(239,68,68,0.3)]' 
          : 'border-purple-500/40'
      }`}>
        <span className="text-5xl font-extrabold tracking-tight text-white font-sans drop-shadow-md">
          {criticalCount}
        </span>
        <span className="text-xs uppercase tracking-widest text-slate-400 font-medium mt-1">
          Critical Assets
        </span>

        {/* Dynamic Badge with live CVSS & Severity */}
        <div className={`mt-2 flex items-center gap-1.5 px-3 py-0.5 rounded-full text-[10px] font-bold border transition-colors ${
          cvss >= 9.0 
            ? 'bg-red-950/80 border-red-500/60 text-red-300' 
            : cvss >= 7.0 
            ? 'bg-amber-950/80 border-amber-500/60 text-amber-300' 
            : 'bg-cyan-950/80 border-cyan-500/60 text-cyan-300'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full ${
            cvss >= 9.0 ? 'bg-red-500 animate-ping' : 'bg-cyan-400'
          }`} />
          <span>{severity} // CVSS {cvss}</span>
        </div>

        {/* Pulsing indicator when triaging */}
        {isAuditing && (
          <span className="text-[9px] text-cyan-400 font-mono mt-1 animate-pulse">
            AUDITING LIVE ORBITS...
          </span>
        )}
      </div>

      {/* Top Left Header with Latest Tested Incident */}
      <div className="absolute top-4 left-6 flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <h3 className="text-lg font-semibold text-white tracking-wide">Risk Proximity Map</h3>
          <span className="text-xs px-2 py-0.5 rounded bg-purple-950/70 border border-purple-600/40 text-purple-300 font-mono">
            Live Vector
          </span>
        </div>
        <div className="text-[11px] font-mono text-cyan-400 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
          <span>Active Target: {latestIncident}</span>
        </div>
      </div>

      {/* Bottom Legend */}
      <div className="absolute bottom-4 right-6 flex items-center gap-4 text-xs text-slate-400 font-mono">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-cyan-400"></span> Low Exposure
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-purple-500"></span> Med Triage
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-pink-500"></span> Exploitable
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-red-500"></span> Critical (CVSS &gt; 9)
        </span>
      </div>

      {/* CSS Keyframe for counter-clockwise rotation */}
      <style>{`
        @keyframes spin-reverse {
          from {
            transform: rotate(360deg);
          }
          to {
            transform: rotate(0deg);
          }
        }
      `}</style>
    </div>
  );
};
