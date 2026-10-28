import React, { useEffect, useState } from 'react';
import { fetchHealth } from '../services/api';

export default function StatusPanel() {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadHealth = async () => {
    const data = await fetchHealth();
    setHealthData(data);
    setLoading(false);
  };

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const isOnline = healthData && healthData.status === 'ok';
  const redisOk = healthData && healthData.redis === 'ok';
  const port = healthData?.port || 8002;
  const kbChunks = healthData?.kb_chunks !== undefined ? healthData.kb_chunks : 0;

  return (
    <div className="status-grid">
      <div className="glass-panel status-card">
        <div className={`status-icon-wrapper ${isOnline ? 'online' : 'error'}`}>
          {isOnline ? '🟢' : '🔴'}
        </div>
        <div className="status-info">
          <h4>C2 API Server</h4>
          <p>{loading ? 'Checking...' : isOnline ? `ONLINE (Port ${port})` : 'OFFLINE'}</p>
        </div>
      </div>

      <div className="glass-panel status-card">
        <div className={`status-icon-wrapper ${redisOk ? 'online' : 'error'}`}>
          {redisOk ? '⚡' : '⚠️'}
        </div>
        <div className="status-info">
          <h4>Redis Session Store</h4>
          <p>{loading ? 'Checking...' : redisOk ? 'REDIS CONNECTED' : 'IN-MEMORY FALLBACK'}</p>
        </div>
      </div>

      <div className="glass-panel status-card">
        <div className="status-icon-wrapper online">
          📚
        </div>
        <div className="status-info">
          <h4>Knowledge Base</h4>
          <p>{loading ? 'Checking...' : `${kbChunks} Vector Chunks`}</p>
        </div>
      </div>

      <div className="glass-panel status-card">
        <div className="status-icon-wrapper online">
          🧠
        </div>
        <div className="status-info">
          <h4>Synthesis Model</h4>
          <p>neuroshell-c2-gemma2-final</p>
        </div>
      </div>
    </div>
  );
}
