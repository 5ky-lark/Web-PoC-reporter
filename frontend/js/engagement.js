/**
 * Engagements view + new-engagement modal.
 */

import * as api from './api.js';
import { el, escapeHtml, toast, relativeAge, hostOf } from './utils.js';

let engagements = [];

export async function refresh() {
  try {
    engagements = await api.listEngagements();
  } catch (e) {
    toast('Failed to load engagements: ' + e.message, 'error');
    engagements = [];
  }
  renderList();
  return engagements;
}

export function getCached() { return engagements; }

function renderList() {
  const body = document.getElementById('engagements-body');
  if (!body) return;
  body.innerHTML = '';

  if (engagements.length === 0) {
    body.appendChild(emptyState());
    return;
  }

  for (const e of engagements) {
    body.appendChild(card(e));
  }
}

function emptyState() {
  const wrap = el('div', { className: 'empty' });
  wrap.appendChild(el('div', { className: 'empty-glyph' }, 'C'));
  wrap.appendChild(el('h3', {}, 'No engagements yet'));
  wrap.appendChild(el('p', {}, 'An engagement gates scan scope, records the tester, hashes the LoA, and rolls forward across scans for diffs. Create one before your first scan.'));
  wrap.appendChild(el('button', {
    className: 'btn btn-primary',
    onclick: () => openModal(),
  }, '+ New engagement'));
  return wrap;
}

function card(e) {
  const summary = computeSummary(e);
  const c = el('article', {
    className: 'engagement-card',
    onclick: () => goToEngagement(e),
  });
  const left = el('div');
  left.appendChild(el('h4', {}, e.client_name || 'Untitled engagement'));
  const meta = el('div', { className: 'engagement-meta' });
  meta.appendChild(el('span', { className: 'engagement-status ' + (e.status || 'active') },
    (e.status || 'active').toUpperCase()));
  meta.appendChild(el('span', {}, `${(e.in_scope_targets || []).length} target(s)`));
  meta.appendChild(el('span', {}, `${e.scan_count || 0} scan(s)`));
  if (e.latest_scan) {
    meta.appendChild(el('span', {}, `last ${relativeAge(e.latest_scan.started_at)}`));
  }
  left.appendChild(meta);

  const right = el('div', { className: 'engagement-summary' });
  for (const [sev, count] of Object.entries(summary)) {
    if (count === 0 && sev !== 'critical' && sev !== 'high') continue;
    const stat = el('div', { className: 'stat' });
    stat.appendChild(el('span', {
      className: 'stat-val',
      style: `color: var(--sev-${sev});`,
    }, String(count)));
    stat.appendChild(el('span', { className: 'stat-label' }, sev));
    right.appendChild(stat);
  }

  c.appendChild(left);
  c.appendChild(right);
  return c;
}

function computeSummary(e) {
  // Aggregate across scans by reading the latest_scan.summary
  const s = (e.latest_scan && e.latest_scan.summary) || {};
  return {
    critical: s.critical || 0,
    high: s.high || 0,
    medium: s.medium || 0,
    low: s.low || 0,
  };
}

function goToEngagement(e) {
  // For now, jump to Run with that engagement preselected.
  window.location.hash = `#run?engagement=${e.id}`;
}

/* ---------- modal ---------- */

export function openModal() {
  const m = document.getElementById('engagement-modal');
  m.classList.remove('hidden');
  document.getElementById('eng-client').focus();
}

function closeModal() {
  const m = document.getElementById('engagement-modal');
  m.classList.add('hidden');
  document.getElementById('modal-error').classList.add('hidden');
  // Clear inputs (user can cancel and retry)
  for (const id of ['eng-client', 'eng-contract', 'eng-tester', 'eng-tester-email',
    'eng-scope', 'eng-out-scope', 'eng-window-start', 'eng-window-end',
    'eng-emergency', 'eng-roe', 'eng-loa']) {
    const e = document.getElementById(id);
    if (e) e.value = '';
  }
}

async function createFromModal() {
  const error = document.getElementById('modal-error');
  error.classList.add('hidden');

  const get = (id) => (document.getElementById(id).value || '').trim();
  const lines = (id) => get(id).split('\n').map(s => s.trim()).filter(Boolean);

  const client = get('eng-client');
  const tester = get('eng-tester');
  const inScope = lines('eng-scope');

  if (!client || !tester) {
    error.textContent = 'Client name and tester name are required.';
    error.classList.remove('hidden');
    return;
  }
  if (inScope.length === 0) {
    error.textContent = 'Add at least one in-scope host.';
    error.classList.remove('hidden');
    return;
  }

  const body = {
    client_name: client,
    contract_id: get('eng-contract') || null,
    in_scope_targets: inScope,
    out_of_scope: lines('eng-out-scope'),
    rules_of_engagement: get('eng-roe') || null,
    emergency_contact: get('eng-emergency') || null,
    tester_name: tester,
    tester_email: get('eng-tester-email') || null,
    loa_text: get('eng-loa') || null,
    window_start: get('eng-window-start') || null,
    window_end: get('eng-window-end') || null,
  };

  try {
    await api.createEngagement(body);
    closeModal();
    await refresh();
    toast('Engagement created', 'ok');
  } catch (e) {
    error.textContent = e.message;
    error.classList.remove('hidden');
  }
}

export function init() {
  document.getElementById('btn-new-engagement').addEventListener('click', openModal);
  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-cancel').addEventListener('click', closeModal);
  document.getElementById('modal-create').addEventListener('click', createFromModal);
  document.getElementById('engagement-modal').addEventListener('click', (e) => {
    if (e.target.id === 'engagement-modal') closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' &&
        !document.getElementById('engagement-modal').classList.contains('hidden')) {
      closeModal();
    }
  });
}
