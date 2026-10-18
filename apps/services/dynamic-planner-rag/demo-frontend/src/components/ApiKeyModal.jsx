import React, { useState } from 'react';

export default function ApiKeyModal({ isOpen, currentKey, onSave, onClose }) {
  const [keyInput, setKeyInput] = useState(currentKey);

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave(keyInput.trim());
    onClose();
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h3>🔑 Configure C2 API Authentication Key</h3>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Enter the API Key configured in your backend <code>.env</code> file (default: <code>neuroshell-secret-key</code>). This key is used to authenticate requests to <code>/plan</code> and <code>/metrics</code>.
        </p>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="form-group">
            <label>API Key (x-api-key header)</label>
            <input
              type="text"
              className="form-control"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              placeholder="e.g. neuroshell-secret-key"
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '6px' }}>
            <button
              type="button"
              className="chip-btn"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="key-config-btn"
              style={{ background: 'var(--accent-blue)', color: '#fff' }}
            >
              Save Key
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
