import * as api from './api.js';
import {
  el, escapeHtml, toast, MODULE_NAMES, SEVERITY_GLYPH, hostOf,
} from './utils.js';

let profiles = {};
let allModules = [];
let selectedProfile = 'standard';
let modulesByProfile = {};
let activeWS = null;
let activeScanId = null;
let runFindings = [];
let runSummary = {};
let onScanComplete = null;
const DRAFT_KEY = 'cybersyc.runDraft.v1';

export function setOnScanComplete(fn) { onScanComplete = fn; }

export async function init() {
  try {
    const data = await api.getProfiles();
    profiles = data.profiles;
    allModules = data.modules;
    modulesByProfile = Object.fromEntries(
      Object.entries(profiles).map(([k, v]) => [k, new Set(v.modules)])
    );
  } catch (e) {
    toast('Failed to load profiles: ' + e.message, 'error');
    profiles = {
      recon: { modules: ['headers', 'ssl', 'tech'], description: '' },
      standard: { modules: allModules, description: '' },
      deep: { modules: allModules, description: '' },
    };
  }

  renderProfiles();
  renderModuleList();
  restoreDraft();

  document.getElementById('btn-start-scan').addEventListener('click', startScan);
  document.getElementById('btn-kill').addEventListener('click', killScan);
  document.getElementById('run-target').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startScan();
  });
  document.getElementById('run-target').addEventListener('input', persistDraft);
  document.getElementById('auth-confirm').addEventListener('change', persistDraft);
  document.getElementById('module-grid').addEventListener('change', persistDraft);
  console.info('[run] initialized scanner view');
}

function renderProfiles() {
  const row = document.getElementById('profile-row');
  row.innerHTML = '';
  const order = ['recon', 'standard', 'deep'];
  for (const name of order) {
    const p = profiles[name];
    if (!p) continue;
    const card = el('button', {
      type: 'button',
      className: 'profile-card' + (name === selectedProfile ? ' selected' : ''),
      'data-profile': name,
      onclick: () => selectProfile(name),
    });
    const head = el('div', { className: 'name' },
      el('span', { className: 'glyph' }, name[0].toUpperCase()),
      name.charAt(0).toUpperCase() + name.slice(1),
    );
    card.appendChild(head);
    card.appendChild(el('div', { className: 'desc' }, p.description));
    card.appendChild(el('div', { className: 'count' }, `${p.modules.length} modules`));
    row.appendChild(card);
  }
}

function selectProfile(name) {
  selectedProfile = name;
  document.querySelectorAll('.profile-card').forEach(c => {
    c.classList.toggle('selected', c.dataset.profile === name);
  });
  const set = modulesByProfile[name] || new Set();
  document.querySelectorAll('.module-row input[type=checkbox]').forEach(cb => {
    cb.checked = set.has(cb.dataset.module);
  });
  persistDraft();
  console.info('[run] profile selected', { profile: name, modules: set.size });
}

function renderModuleList() {
  const grid = document.getElementById('module-grid');
  if (!grid) return;
  grid.innerHTML = '';
  const set = modulesByProfile[selectedProfile] || new Set(allModules);
  for (const m of allModules) {
    const row = el('label', { className: 'module-row' });
    const cb = el('input', { type: 'checkbox', 'data-module': m });
    if (set.has(m)) cb.checked = true;
    row.appendChild(cb);
    row.appendChild(el('div', {}, MODULE_NAMES[m] || m));
    row.appendChild(el('span', { className: 'module-desc' }, m));
    grid.appendChild(row);
  }
}

function getSelectedModules() {
  return Array.from(document.querySelectorAll('.module-row input:checked'))
    .map(cb => cb.dataset.module);
}

function showError(msg) {
  const box = document.getElementById('run-error');
  box.textContent = msg;
  box.classList.remove('hidden');
}

function clearError() {
  document.getElementById('run-error').classList.add('hidden');
}

async function startScan() {
  clearError();
  const url = document.getElementById('run-target').value.trim();
  const auth = document.getElementById('auth-confirm').checked;
  const modules = getSelectedModules();

  if (!url) return showError('Target URL is required.');
  if (!auth) return showError('Confirm authorization before scanning.');
  if (modules.length === 0) return showError('Select at least one module.');

  const btn = document.getElementById('btn-start-scan');
  btn.disabled = true;
  btn.innerHTML = '<span>Starting…</span>';

  try {
    console.info('[scan] start requested', { url, profile: selectedProfile, modulesCount: modules.length });
    const r = await api.startScan({ targetUrl: url, modules, profile: selectedProfile });
    activeScanId = r.scan_id;
    runFindings = [];
    runSummary = {};
    showProgress(r.target_url, modules);
    activeWS = api.connectWebSocket(activeScanId, onWsMessage, onWsClose);
    persistDraft();
  } catch (e) {
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Start scan';
    showError(e.message);
  }
}

function showProgress(targetUrl, modules) {
  document.getElementById('run-screen-config').classList.add('hidden');
  document.getElementById('run-screen-progress').classList.remove('hidden');
  document.getElementById('run-crumb').textContent = `scanning ${hostOf(targetUrl)}`;
  document.getElementById('progress-target').textContent = targetUrl;
  document.getElementById('progress-percent').textContent = '0%';
  document.getElementById('progress-bar-fill').style.width = '0%';
  document.getElementById('progress-counts').textContent = `0 / ${modules.length} complete`;

  const grid = document.getElementById('module-status');
  grid.innerHTML = '';
  for (const m of modules) {
    const row = el('div', { className: 'mod-status', 'data-module': m, 'data-status': 'pending' });
    row.appendChild(el('span', { className: 'glyph' }, '·'));
    row.appendChild(el('span', { className: 'label' }, MODULE_NAMES[m] || m));
    row.appendChild(el('span', { className: 'count' }, ''));
    grid.appendChild(row);
  }

  document.getElementById('live-feed').innerHTML = '';
  document.getElementById('live-feed-count').textContent = '0';
}

function onWsMessage(data) {
  console.info('[ws] message', data);
  if (data.type === 'scan_complete' || data.type === 'scan_cancelled') {
    runSummary = data.summary || {};
    document.getElementById('progress-percent').textContent = '100%';
    document.getElementById('progress-bar-fill').style.width = '100%';
    document.getElementById('progress-title').textContent =
      data.type === 'scan_cancelled' ? 'Scan cancelled' : 'Scan complete';
    setTimeout(() => { if (onScanComplete) onScanComplete(activeScanId); }, 700);
    return;
  }
  if (data.type === 'error') {
    toast(data.message || 'Scan error', 'error');
    return;
  }

  const { module, status, progress, findings } = data;
  document.getElementById('progress-percent').textContent = `${Math.round(progress)}%`;
  document.getElementById('progress-bar-fill').style.width = `${progress}%`;

  const row = document.querySelector(`.mod-status[data-module="${module}"]`);
  if (row) {
    row.dataset.status = status;
    const glyph = row.querySelector('.glyph');
    if (status === 'running') glyph.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-3.5-7.1"/></svg>';
    else if (status === 'complete') glyph.textContent = '✓';
    else if (status === 'error') glyph.textContent = '!';
    else if (status === 'cancelled') glyph.textContent = '×';
    else glyph.textContent = '·';
    if (findings && findings.length > 0) row.querySelector('.count').textContent = `${findings.length}`;
  }

  const total = document.querySelectorAll('.mod-status').length;
  const done = document.querySelectorAll('.mod-status[data-status="complete"], .mod-status[data-status="error"], .mod-status[data-status="cancelled"]').length;
  document.getElementById('progress-counts').textContent = `${done} / ${total} complete`;

  if (findings && findings.length > 0) {
    runFindings.push(...findings);
    const feed = document.getElementById('live-feed');
    for (const f of findings) {
      const item = el('div', { className: 'feed-item' });
      const sev = (f.severity || 'info').toLowerCase();
      item.appendChild(el('span', { className: `sev sev-${sev}` }, SEVERITY_GLYPH[sev] || '·'));
      item.appendChild(el('span', { className: 'id' }, f.tracking_id || `cys-${(f.id || '').slice(0, 6)}`));
      item.appendChild(el('span', { className: 'title' }, escapeHtml(f.title || '(untitled)')));
      item.appendChild(el('span', { className: 'module' }, MODULE_NAMES[f.module] || f.module));
      feed.insertBefore(item, feed.firstChild);
    }
    document.getElementById('live-feed-count').textContent = String(runFindings.length);
    feed.scrollTop = 0;
  }
}

function onWsClose() {
  console.info('[ws] closed');
  const btn = document.getElementById('btn-start-scan');
  btn.disabled = false;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Start scan';
}

async function killScan() {
  if (!activeScanId) return;
  try {
    await api.cancelScan(activeScanId);
    console.info('[scan] cancel requested', { scanId: activeScanId });
    toast('Cancel signal sent', 'ok');
  } catch (e) {
    toast('Cancel failed: ' + e.message, 'error');
  }
}

export function reset() {
  document.getElementById('run-screen-progress').classList.add('hidden');
  document.getElementById('run-screen-config').classList.remove('hidden');
  document.getElementById('run-crumb').textContent = 'new scan';
  document.getElementById('run-target').value = '';
  document.getElementById('auth-confirm').checked = false;
  const btn = document.getElementById('btn-start-scan');
  btn.disabled = false;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Start scan';
  if (activeWS) { try { activeWS.close(); } catch {} activeWS = null; }
  activeScanId = null;
  sessionStorage.removeItem(DRAFT_KEY);
  console.info('[run] reset state');
}

export function getActiveScanId() { return activeScanId; }

function persistDraft() {
  const payload = {
    target: document.getElementById('run-target').value,
    auth: document.getElementById('auth-confirm').checked,
    profile: selectedProfile,
    modules: getSelectedModules(),
  };
  sessionStorage.setItem(DRAFT_KEY, JSON.stringify(payload));
}

function restoreDraft() {
  const raw = sessionStorage.getItem(DRAFT_KEY);
  if (!raw) return;
  try {
    const draft = JSON.parse(raw);
    if (draft.target) document.getElementById('run-target').value = draft.target;
    if (typeof draft.auth === 'boolean') document.getElementById('auth-confirm').checked = draft.auth;
    if (draft.profile && profiles[draft.profile]) {
      selectedProfile = draft.profile;
      renderProfiles();
    }
    if (Array.isArray(draft.modules) && draft.modules.length > 0) {
      const selected = new Set(draft.modules);
      document.querySelectorAll('.module-row input[type=checkbox]').forEach(cb => {
        cb.checked = selected.has(cb.dataset.module);
      });
    }
    console.info('[run] restored draft state');
  } catch {
    sessionStorage.removeItem(DRAFT_KEY);
  }
}

