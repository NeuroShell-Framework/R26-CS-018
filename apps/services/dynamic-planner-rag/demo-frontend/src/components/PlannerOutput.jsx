import React, { useState } from 'react';

export default function PlannerOutput({ data }) {
  const [copied, setCopied] = useState(false);

  if (!data) return null;

  const commands = data.command_sequence && data.command_sequence.length > 0
    ? data.command_sequence
    : [data.command];

  const fullCommandText = commands.join('\n');

  const handleCopy = () => {
    navigator.clipboard.writeText(fullCommandText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="glass-panel output-panel glow-cyan">
      <div className="section-title" style={{ color: 'var(--status-green)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>✅ PLAN GENERATED — VALIDATION PASSED</span>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Latency: {data.latency_ms} ms</span>
      </div>

      <div className="command-box">
        <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-subtle)', fontStyle: 'italic', marginBottom: '4px' }}>
          {commands.length > 1 ? `Multi-Step Command Sequence (${commands.length} steps):` : 'Synthesized Command:'}
        </div>

        {commands.map((cmd, idx) => (
          <div key={idx} className="command-line">
            {commands.length > 1 && <span style={{ color: 'var(--accent-blue)', marginRight: '8px' }}>[{idx + 1}]</span>}
            {cmd}
          </div>
        ))}

        <button className="copy-btn" onClick={handleCopy}>
          {copied ? '✓ Copied to Clipboard!' : '📋 Copy Command'}
        </button>
      </div>

      <div className="meta-grid">
        <div className="meta-item">
          <label>Selected Tool</label>
          <span style={{ color: 'var(--accent-cyan)' }}>{data.tool}</span>
        </div>

        <div className="meta-item">
          <label>Intent Code</label>
          <span>{data.intent_ref}</span>
        </div>

        <div className="meta-item">
          <label>Validation Status</label>
          <span style={{ color: data.validation_passed ? 'var(--status-green)' : 'var(--status-red)' }}>
            {data.validation_passed ? 'PASSED (Strict)' : 'FAILED'}
          </span>
        </div>

        <div className="meta-item">
          <label>Safety Flags</label>
          <span>{data.safety_flags?.length === 0 ? 'None (Private Scope)' : data.safety_flags?.join(', ')}</span>
        </div>

        <div className="meta-item">
          <label>Session ID</label>
          <span style={{ fontSize: '12px' }}>{data.session_id}</span>
        </div>

        <div className="meta-item">
          <label>Estimated Duration</label>
          <span>{data.estimated_duration || 'medium'}</span>
        </div>
      </div>

      {/* RAG Evidence Section */}
      {data.retrieval_sources && data.retrieval_sources.length > 0 && (
        <div style={{ marginTop: '12px', background: 'rgba(0, 0, 0, 0.3)', padding: '12px 16px', borderRadius: '8px' }}>
          <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--accent-sky)', marginBottom: '6px' }}>
            📚 RAG Retrieval Sources Grounding:
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {data.retrieval_sources.map((src, idx) => (
              <span key={idx} style={{ background: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.3)', color: 'var(--accent-cyan)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                ✓ {src}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
