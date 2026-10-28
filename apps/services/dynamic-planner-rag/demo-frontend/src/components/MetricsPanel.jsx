import React, { useState } from 'react';
import { fetchMetrics } from '../services/api';

export default function MetricsPanel({ apiKey }) {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadMetrics = async () => {
    setLoading(true);
    setError(null);
    const data = await fetchMetrics(apiKey);
    if (data.error) {
      setError(data.error);
    } else {
      setMetrics(data);
    }
    setLoading(false);
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      <div className="section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>📊 C2 Aggregated Metrics Observer (GET /metrics)</span>
        <button
          className="copy-btn"
          onClick={loadMetrics}
          disabled={loading}
          style={{ fontSize: '11px', padding: '4px 10px' }}
        >
          {loading ? 'Refreshing...' : '🔄 Refresh Metrics'}
        </button>
      </div>

      {error && (
        <div style={{ fontSize: '12px', color: 'var(--status-red)', marginTop: '8px' }}>
          Failed to fetch metrics: {error} (Check API Key)
        </div>
      )}

      {metrics && !error && (
        <div className="meta-grid" style={{ marginTop: '12px' }}>
          <div className="meta-item">
            <label>Total Requests</label>
            <span style={{ color: 'var(--accent-cyan)' }}>{metrics.total || 0}</span>
          </div>

          <div className="meta-item">
            <label>Successful Plans</label>
            <span style={{ color: 'var(--status-green)' }}>{metrics.successful || 0}</span>
          </div>

          <div className="meta-item">
            <label>Failed / Blocked</label>
            <span style={{ color: 'var(--status-red)' }}>{metrics.failed || 0}</span>
          </div>

          <div className="meta-item">
            <label>Average Latency</label>
            <span>{metrics.avg_latency_ms ? `${metrics.avg_latency_ms} ms` : 'N/A'}</span>
          </div>
        </div>
      )}

      {!metrics && !error && !loading && (
        <div style={{ fontSize: '12px', color: 'var(--text-subtle)', fontStyle: 'italic', marginTop: '6px' }}>
          Click "Refresh Metrics" to query the backend <code>/metrics</code> endpoint.
        </div>
      )}
    </div>
  );
}
