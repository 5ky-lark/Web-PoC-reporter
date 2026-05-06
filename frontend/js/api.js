/**
 * API client — REST + WebSocket. Talks to FastAPI via Vite's /api proxy.
 */

const BASE = '';

async function req(path, opts = {}) {
  const resp = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: `HTTP ${resp.status}` }));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  const ctype = resp.headers.get('content-type') || '';
  if (ctype.includes('application/json')) return resp.json();
  return resp.text();
}

/* ---------- meta ---------- */
export const getProfiles = () => req('/api/profiles');
export const getHealth   = () => req('/api/health');

/* ---------- engagements ---------- */
export const listEngagements   = () => req('/api/engagements');
export const getEngagement     = (id) => req(`/api/engagements/${id}`);
export const createEngagement  = (body) => req('/api/engagements', {
  method: 'POST', body: JSON.stringify(body),
});
export const setEngagementStatus = (id, status) => req(`/api/engagements/${id}/status`, {
  method: 'PATCH', body: JSON.stringify({ status }),
});

/* ---------- scans ---------- */
export const startScan = ({ targetUrl, modules, profile = 'standard', engagementId = null }) =>
  req('/api/scan', {
    method: 'POST',
    body: JSON.stringify({
      target_url: targetUrl,
      modules,
      profile,
      engagement_id: engagementId,
    }),
  });

export const getScan       = (id) => req(`/api/scan/${id}`);
export const listScans     = (engagementId = null) =>
  req(`/api/scans${engagementId ? `?engagement_id=${engagementId}` : ''}`);
export const cancelScan    = (id) => req(`/api/scan/${id}/cancel`, { method: 'POST' });
export const getScanAudit  = (id) => req(`/api/scan/${id}/audit`);
export const getScanDiff   = (older, newer) => req(`/api/scan/diff/${older}/${newer}`);

/* ---------- findings ---------- */
export const getFinding   = (id) => req(`/api/finding/${id}`);
export const patchFinding = (id, body) => req(`/api/finding/${id}`, {
  method: 'PATCH', body: JSON.stringify(body),
});
export const listNotes    = (id) => req(`/api/finding/${id}/notes`);
export const addNote      = (id, body, author = null) =>
  req(`/api/finding/${id}/notes`, {
    method: 'POST', body: JSON.stringify({ body, author }),
  });

/* ---------- exports ---------- */
export async function exportScan(scanId, format) {
  const resp = await fetch(`${BASE}/api/scan/${scanId}/export/${format}`);
  if (!resp.ok) throw new Error(`Export ${format} failed: HTTP ${resp.status}`);

  const ctype = resp.headers.get('content-type') || '';
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);

  if (format === 'pdf' && ctype.includes('text/html')) {
    // WeasyPrint not installed — open the HTML and let the browser print
    const w = window.open(url, '_blank');
    if (w) w.onload = () => setTimeout(() => w.print(), 600);
    return;
  }

  const ext = (
    format === 'pdf' ? 'pdf' :
    format === 'sarif' ? 'sarif' :
    format === 'csv' ? 'csv' :
    format === 'md' || format === 'markdown' ? 'md' :
    format === 'json' ? 'json' :
    format === 'html' ? 'html' : 'txt'
  );

  const a = document.createElement('a');
  a.href = url;
  a.download = `cybersyc-${scanId.slice(0, 8)}.${ext}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 400);
}

/* ---------- websocket ---------- */
export function connectWebSocket(scanId, onMessage, onClose) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${window.location.host}/ws/scan/${scanId}`;
  const ws = new WebSocket(url);
  ws.onmessage = (ev) => {
    try { onMessage(JSON.parse(ev.data)); }
    catch (e) { console.error('ws parse', e); }
  };
  ws.onclose = () => onClose && onClose();
  ws.onerror = (e) => console.error('ws error', e);
  return ws;
}
