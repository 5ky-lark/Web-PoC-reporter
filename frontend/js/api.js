/**
 * API client — REST + WebSocket. Talks to FastAPI via Vite's /api proxy.
 */

const IS_LOCAL = ['localhost', '127.0.0.1'].includes(window.location.hostname);
// Vercel service routePrefix="/api" + backend endpoints under "/api/*" => "/api/api/*" in prod.
const BASE = IS_LOCAL ? '' : '/api';

async function req(path, opts = {}) {
  const method = opts.method || 'GET';
  console.info('[api] request', { method, path });
  const resp = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: `HTTP ${resp.status}` }));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  const ctype = resp.headers.get('content-type') || '';
  console.info('[api] response', { method, path, status: resp.status, contentType: ctype });
  if (ctype.includes('application/json')) return resp.json();
  return resp.text();
}

/* ---------- meta ---------- */
export const getProfiles = () => req('/api/profiles');
export const getHealth   = () => req('/api/health');

/* ---------- scans ---------- */
export const startScan = ({ targetUrl, modules, profile = 'standard' }) =>
  req('/api/scan', {
    method: 'POST',
    body: JSON.stringify({
      target_url: targetUrl,
      modules,
      profile,
    }),
  });

export const getScan       = (id) => req(`/api/scan/${id}`);
export const listScans     = () => req('/api/scans');
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
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const body = await resp.json();
      if (body && body.detail) detail = body.detail;
    } catch {}
    throw new Error(`Export ${format} failed: ${detail}`);
  }

  const ctype = resp.headers.get('content-type') || '';
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);

  if (format === 'pdf' && ctype.includes('text/html')) {
    // WeasyPrint not installed — open the HTML and let the browser print
    console.info('[export] pdf fallback -> html print mode', { scanId });
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
