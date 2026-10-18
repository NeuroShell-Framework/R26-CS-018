import React from 'react';

export default function Presets({ onSelectPreset }) {
  const presets = [
    {
      id: 'nmap-stealth',
      title: '1. Nmap Stealth Scan',
      intent: 'NETWORK_SCAN',
      targetType: 'IP',
      targetValue: '192.168.1.1',
      primaryTool: 'nmap',
      ports: '80, 443',
      modifiers: ['stealth'],
      confidence: 0.95,
      description: 'TCP SYN stealth scan against local RFC-1918 gateway'
    },
    {
      id: 'nikto-ssl',
      title: '2. Nikto HTTPS Audit',
      intent: 'VULNERABILITY_AUDIT',
      targetType: 'IP',
      targetValue: '10.0.0.8',
      primaryTool: 'nikto',
      ports: '443',
      modifiers: ['ssl'],
      confidence: 0.95,
      description: 'Web vulnerability audit over SSL/TLS port 443'
    },
    {
      id: 'gobuster-dir',
      title: '3. Gobuster Directory Bruteforce',
      intent: 'DIRECTORY_BRUTEFORCE',
      targetType: 'IP',
      targetValue: '10.0.0.5',
      primaryTool: 'gobuster',
      ports: '80',
      modifiers: ['quick'],
      confidence: 0.95,
      description: 'Fast web path discovery using common wordlist'
    },
    {
      id: 'public-ip-safety',
      title: '4. Public IP Safety Test (8.8.8.8)',
      intent: 'NETWORK_SCAN',
      targetType: 'IP',
      targetValue: '8.8.8.8',
      primaryTool: 'nmap',
      ports: '80',
      modifiers: ['stealth'],
      confidence: 0.95,
      isSafetyTest: true,
      description: 'Triggers backend SafetyFilter RFC-1918 scope rejection'
    }
  ];

  return (
    <div className="glass-panel presets-bar">
      <div className="section-title">
        ⚡ Demo Quick Presets (Populates Form)
      </div>
      <div className="presets-list">
        {presets.map((p) => (
          <button
            key={p.id}
            className={`preset-btn ${p.isSafetyTest ? 'safety' : ''}`}
            onClick={() => onSelectPreset(p)}
            title={p.description}
          >
            <span>{p.isSafetyTest ? '🛡️' : '🚀'}</span>
            <div>
              <div style={{ fontWeight: 700 }}>{p.title}</div>
              <div style={{ fontSize: '11px', opacity: 0.7 }}>{p.targetValue} • {p.primaryTool}</div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
