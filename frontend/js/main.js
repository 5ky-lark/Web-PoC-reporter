import * as api from './api.js';
import * as scanner from './scanner.js';
import * as triage from './triage.js';
import { el, hostOf, toast } from './utils.js';

const VIEWS = ['run', 'triage'];

function parseHash() {
  const raw = (window.location.hash || '').slice(1);
  const [path, qs = ''] = raw.split('?');
  return { path: path || 'run', params: new URLSearchParams(qs) };
}

function switchView(name) {
  if (!VIEWS.includes(name)) name = 'run';
  for (const v of VIEWS) {
    document.getElementById('view-' + v).classList.toggle('active', v === name);
  }
  document.querySelectorAll('.rail-link').forEach(link => {
    link.classList.toggle('active', link.dataset.view === name);
  });
}

async function handleRoute() {
  const { path, params } = parseHash();
  console.info('[router] route change', { path, params: Object.fromEntries(params.entries()) });
  switchView(path);
  if (path === 'triage') {
    const sid = params.get('scan');
    if (sid) await triage.loadScan(sid);
  }
}

async function refreshRecentScans() {
  const wrap = document.getElementById('rail-scans');
  if (!wrap) return;
  let scans = [];
  try { scans = (await api.listScans()).slice(0, 6); } catch {}
  wrap.innerHTML = '';
  if (scans.length === 0) {
    wrap.appendChild(el('div', { style: 'padding: 4px 12px; font-size: 11px; color: var(--text-faint);' }, 'no scans yet'));
    return;
  }
  for (const s of scans) {
    const link = el('a', {
      className: 'rail-link',
      href: `#triage?scan=${s.id}`,
      style: 'padding: 5px 10px; margin: 0 8px;'
    });
    const sum = s.summary || {};
    const total = (sum.critical || 0) + (sum.high || 0) + (sum.medium || 0) + (sum.low || 0);
    const status = s.status || 'pending';
    const dot = el('span', {
      style: `display:inline-block;width:5px;height:5px;border-radius:50%;background:${
        status === 'completed' ? 'var(--accent)' : status === 'running' ? 'var(--sev-medium)' : status === 'error' ? 'var(--alert)' : 'var(--text-faint)'
      };flex-shrink:0;`
    });
    link.appendChild(dot);
    link.appendChild(el('span', {
      style: 'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;'
    }, hostOf(s.target_url)));
    if (s.profile) {
      link.appendChild(el('span', {
        style: 'font: 500 9.5px var(--font-mono); color: var(--text-faint); text-transform: uppercase; margin-left:6px;',
      }, s.profile));
    }
    if (total > 0) link.appendChild(el('span', { style: 'font: 500 10px var(--font-mono); color: var(--text-faint);' }, String(total)));
    link.title = `${hostOf(s.target_url)} · ${s.profile || 'standard'} · ${new Date(s.started_at).toLocaleString()}`;
    wrap.appendChild(link);
  }
  console.info('[history] refreshed recent scans', { count: scans.length });
}

async function bootstrap() {
  try {
    const h = await api.getHealth();
    console.info('[boot] health', h);
  } catch {
    toast('Backend unreachable on /api/health', 'error');
  }

  scanner.setOnScanComplete(async (scanId) => {
    console.info('[scan] complete, routing to triage', { scanId });
    window.location.hash = `#triage?scan=${scanId}`;
    await refreshRecentScans();
  });
  await scanner.init();
  triage.init();

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
  window.addEventListener('keydown', (e) => {
    const activeTag = document.activeElement?.tagName?.toLowerCase();
    const typing = activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select';
    if (typing) return;
    // "/" => focus triage search quickly
    if (e.key === '/') {
      e.preventDefault();
      const search = document.getElementById('search-input');
      if (search) search.focus();
      return;
    }
    // g r / g t quick navigation
    if (e.key.toLowerCase() === 'g') {
      window.__cybersyc_g_pressed_at = Date.now();
      return;
    }
    const gRecent = Date.now() - (window.__cybersyc_g_pressed_at || 0) < 1200;
    if (gRecent && e.key.toLowerCase() === 'r') {
      e.preventDefault();
      window.location.hash = '#run';
      return;
    }
    if (gRecent && e.key.toLowerCase() === 't') {
      e.preventDefault();
      window.location.hash = '#triage';
      return;
    }
  });
  await handleRoute();
  refreshRecentScans();
  setInterval(refreshRecentScans, 8000);
}

document.addEventListener('DOMContentLoaded', bootstrap);

