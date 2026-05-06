/**
 * Entry point — bootstrap, routing, recent-scans rail.
 */

import * as api from './api.js';
import * as engagement from './engagement.js';
import * as scanner from './scanner.js';
import * as triage from './triage.js';
import { el, relativeAge, hostOf, toast } from './utils.js';

const VIEWS = ['engagements', 'run', 'triage'];

// ---------- routing ----------

function parseHash() {
  const raw = (window.location.hash || '').slice(1);
  const [path, qs = ''] = raw.split('?');
  const params = new URLSearchParams(qs);
  return { path: path || 'engagements', params };
}

function switchView(name) {
  if (!VIEWS.includes(name)) name = 'engagements';
  for (const v of VIEWS) {
    document.getElementById('view-' + v).classList.toggle('active', v === name);
  }
  document.querySelectorAll('.rail-link').forEach(link => {
    link.classList.toggle('active', link.dataset.view === name);
  });
}

async function handleRoute() {
  const { path, params } = parseHash();
  switchView(path);

  if (path === 'run') {
    // from engagements card → preselect engagement
    const eid = params.get('engagement');
    if (eid) scanner.preselectEngagement(eid);
    scanner.reset();
  } else if (path === 'triage') {
    const sid = params.get('scan');
    if (sid) await triage.loadScan(sid);
  }
}

// ---------- rail: recent scans ----------

async function refreshRecentScans() {
  const wrap = document.getElementById('rail-scans');
  if (!wrap) return;
  let scans = [];
  try { scans = (await api.listScans()).slice(0, 6); } catch {}
  wrap.innerHTML = '';
  if (scans.length === 0) {
    wrap.appendChild(el('div', {
      style: 'padding: 4px 12px; font-size: 11px; color: var(--text-faint);',
    }, 'no scans yet'));
    return;
  }
  for (const s of scans) {
    const link = el('a', {
      className: 'rail-link',
      href: `#triage?scan=${s.id}`,
      style: 'padding: 5px 10px; margin: 0 8px;',
    });
    const sum = s.summary || {};
    const total = (sum.critical || 0) + (sum.high || 0) + (sum.medium || 0) + (sum.low || 0);
    const status = s.status || 'pending';

    const dot = el('span', {
      style: `display:inline-block;width:5px;height:5px;border-radius:50%;background:${
        status === 'completed' ? 'var(--accent)' :
        status === 'running' ? 'var(--sev-medium)' :
        status === 'cancelled' ? 'var(--text-faint)' :
        status === 'error' ? 'var(--alert)' :
        'var(--text-faint)'
      };flex-shrink:0;`,
    });
    link.appendChild(dot);
    const txt = el('span', {
      style: 'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;',
    }, hostOf(s.target_url));
    link.appendChild(txt);
    if (total > 0) {
      link.appendChild(el('span', {
        style: 'font: 500 10px var(--font-mono); color: var(--text-faint); flex-shrink:0;',
      }, String(total)));
    }
    wrap.appendChild(link);
  }
}

// ---------- bootstrap ----------

async function bootstrap() {
  // Health probe (toast if backend down)
  try { await api.getHealth(); }
  catch { toast('Backend unreachable on /api/health', 'error'); }

  await engagement.refresh();
  engagement.init();

  scanner.setOnScanComplete(async (scanId) => {
    window.location.hash = `#triage?scan=${scanId}`;
    await refreshRecentScans();
  });
  await scanner.init(engagement.getCached);

  triage.init();

  // Rail link clicks
  document.querySelectorAll('.rail-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const view = link.dataset.view;
      if (view) {
        e.preventDefault();
        window.location.hash = '#' + view;
      }
    });
  });

  window.addEventListener('hashchange', handleRoute);
  await handleRoute();

  refreshRecentScans();
  setInterval(refreshRecentScans, 8000);
}

document.addEventListener('DOMContentLoaded', bootstrap);
