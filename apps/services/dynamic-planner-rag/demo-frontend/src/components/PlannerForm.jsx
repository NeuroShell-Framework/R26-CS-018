import React from 'react';

const ALL_MODIFIERS = ['stealth', 'aggressive', 'quick', 'ssl', 'full', 'all-ports'];

export default function PlannerForm({
  formData,
  setFormData,
  onSubmit,
  loading
}) {
  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const toggleModifier = (mod) => {
    setFormData(prev => {
      const current = prev.modifiers || [];
      const updated = current.includes(mod)
        ? current.filter(m => m !== mod)
        : [...current, mod];
      return { ...prev, modifiers: updated };
    });
  };

  const generateUuid = () => {
    const uuid = 'demo-' + Math.random().toString(36).substring(2, 9);
    handleChange('sessionId', uuid);
  };

  return (
    <form className="glass-panel form-panel" onSubmit={onSubmit}>
      <div className="section-title">
        ⚙️ Planner Input Specification
      </div>

      <div className="form-group">
        <label>Intent Code</label>
        <select
          className="form-control"
          value={formData.intent}
          onChange={(e) => handleChange('intent', e.target.value)}
        >
          <option value="NETWORK_SCAN">NETWORK_SCAN</option>
          <option value="SERVICE_ENUMERATION">SERVICE_ENUMERATION</option>
          <option value="VULNERABILITY_AUDIT">VULNERABILITY_AUDIT</option>
          <option value="DIRECTORY_BRUTEFORCE">DIRECTORY_BRUTEFORCE</option>
        </select>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>Target Type</label>
          <select
            className="form-control"
            value={formData.targetType}
            onChange={(e) => handleChange('targetType', e.target.value)}
          >
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain Name</option>
            <option value="URL">URL</option>
          </select>
        </div>

        <div className="form-group">
          <label>Target Value</label>
          <input
            type="text"
            className="form-control"
            value={formData.targetValue}
            onChange={(e) => handleChange('targetValue', e.target.value)}
            placeholder="e.g. 192.168.1.1 or 8.8.8.8"
            required
          />
        </div>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>Primary Tool</label>
          <select
            className="form-control"
            value={formData.primaryTool}
            onChange={(e) => handleChange('primaryTool', e.target.value)}
          >
            <option value="nmap">Nmap</option>
            <option value="nikto">Nikto</option>
            <option value="gobuster">Gobuster</option>
          </select>
        </div>

        <div className="form-group">
          <label>Ports (Comma separated)</label>
          <input
            type="text"
            className="form-control"
            value={formData.ports}
            onChange={(e) => handleChange('ports', e.target.value)}
            placeholder="e.g. 80, 443"
          />
        </div>
      </div>

      <div className="form-group">
        <label>Intent Confidence ({formData.confidence})</label>
        <input
          type="range"
          min="0.5"
          max="1.0"
          step="0.05"
          className="form-control"
          style={{ padding: 0 }}
          value={formData.confidence}
          onChange={(e) => handleChange('confidence', parseFloat(e.target.value))}
        />
      </div>

      <div className="form-group">
        <label>Selectable Intent Modifiers</label>
        <div className="chips-container">
          {ALL_MODIFIERS.map(mod => {
            const isActive = formData.modifiers?.includes(mod);
            return (
              <button
                type="button"
                key={mod}
                className={`chip-btn ${isActive ? 'active' : ''}`}
                onClick={() => toggleModifier(mod)}
              >
                {isActive ? '✓ ' : '+ '}{mod}
              </button>
            );
          })}
        </div>
      </div>

      <div className="form-group">
        <label>Session Identifier (Redis Key)</label>
        <div style={{ display: 'flex', gap: '8px' }}>
          <input
            type="text"
            className="form-control"
            style={{ flex: 1 }}
            value={formData.sessionId}
            onChange={(e) => handleChange('sessionId', e.target.value)}
            placeholder="session-id"
            required
          />
          <button
            type="button"
            className="chip-btn"
            style={{ background: 'rgba(59, 130, 246, 0.2)', color: 'var(--accent-sky)' }}
            onClick={generateUuid}
          >
            🎲 New ID
          </button>
        </div>
      </div>

      <button
        type="submit"
        className="btn-generate"
        disabled={loading}
      >
        {loading ? 'Synthesizing Plan...' : '⚡ Generate Command Plan'}
      </button>
    </form>
  );
}
