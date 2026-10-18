import React from 'react';

export default function Header({ apiKey, onOpenKeyModal }) {
  return (
    <header className="app-header">
      <div className="header-brand">
        <div className="brand-icon">⚡</div>
        <div className="header-title-area">
          <h1>NEUROSHELL</h1>
          <p>Component 02 — Dynamic Planner & RAG Engine</p>
        </div>
      </div>

      <div className="header-right">
        <div className="boundary-pill">
          <span>🔒</span> Planning & Validation Only | Command Execution Belongs to Component 03
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="key-config-btn" onClick={onOpenKeyModal}>
            <span>🔑</span> API Key: <code style={{ color: 'var(--accent-cyan)' }}>{apiKey ? `${apiKey.substring(0, 8)}...` : 'Default'}</code>
          </button>
        </div>
      </div>
    </header>
  );
}
