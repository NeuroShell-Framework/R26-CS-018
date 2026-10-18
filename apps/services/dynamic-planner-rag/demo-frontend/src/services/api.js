// Vite dev proxy routes /api to http://127.0.0.1:8002 to prevent browser CORS blocking
const PROXY_BASE_URL = '/api';
const DIRECT_BASE_URL = 'http://127.0.0.1:8002';

async function safeFetch(path, options = {}) {
  try {
    const res = await fetch(`${PROXY_BASE_URL}${path}`, options);
    // If response is valid (including HTTP 400, 401, 422 which are expected API error payloads)
    if (res.status < 500 || res.ok) {
      return res;
    }
  } catch (err) {
    // Proxy fetch failed; fallback to direct URL
  }

  // Direct fetch fallback
  return await fetch(`${DIRECT_BASE_URL}${path}`, options);
}

export async function fetchHealth() {
  try {
    const res = await safeFetch('/health');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return { status: 'error', error: err.message };
  }
}

export async function fetchAvailableTools() {
  try {
    const res = await safeFetch('/tools/available');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return { tools: [], error: err.message };
  }
}

export async function fetchMetrics(apiKey) {
  try {
    const res = await safeFetch('/metrics', {
      headers: {
        'x-api-key': apiKey || 'neuroshell-secret-key'
      }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return { error: err.message };
  }
}

export async function generatePlan(payload, apiKey) {
  try {
    const res = await safeFetch('/plan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey || 'neuroshell-secret-key'
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (!res.ok) {
      return {
        success: false,
        status: res.status,
        errorData: data
      };
    }

    return {
      success: true,
      data
    };
  } catch (err) {
    return {
      success: false,
      status: 500,
      errorData: { detail: err.message || 'Network error connecting to C2 backend' }
    };
  }
}
