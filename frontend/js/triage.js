/**
 * Triage view — findings table + detail drawer.
 * Search / severity-filter / status-filter / sort / group, status workflow,
 * raw PoC display with copy buttons, notes, audit history.
 */

import * as api from './api.js';
import {
  el, escapeHtml, toast, copyText, debounce,
  SEVERITY_GLYPH, SEVERITY_ORDER, STATUS_LABELS, MODULE_NAMES,
  CONFIDENCE_LABELS, hostOf, relativeAge, fmtCvss, severityRank,
  effectiveSeverity,
} from './utils.js';

let scanState = null;       // current scan dict
let findingsState = [];     // findings array
let engagementState = null; // engagement (if attached)
let auditState = [];        // audit log entries (lazy-loaded)

let selectedSeverities = new Set(['critical', 'high', 'medium', 'low', 'info']);
let selectedStatuses  = new Set(['new', 'triaging', 'confirmed', 'accepted_risk', 'fixed', 'wont_fix', 'false_positive']);
let searchQuery = '';
let groupBy = 'severity';
let sortBy = 'severity';
let activeFinding = null;
let activeTab = 'evidence';

// ---------- entry point ----------

export async function loadScan(scanId) {
  try {
    scanState = await api.getScan(scanId);
  } catch (e) {
    toast('Failed to load scan: ' + e.message, 'error');
    return;
  }
  findingsState = scanState.findings || [];
  engagementState = null;
  if (scanState.engagement_id) {
    try {
      engagementState = await api.getEngagement(scanState.engagement_id);
    } catch {}
  }
  auditState = [];

  // Update command bar
  document.getElementById('triage-target').textContent = scanState.target_url;
  renderTriageActions();
  renderToolbar();
  renderSummary();
  renderTable();
  clearDrawer();
}

// ---------- toolbar ----------

function renderTriageActions() {
  const wrap = document.getElementById('triage-actions');
  if (!wrap) return;
  wrap.innerHTML = '';

  const make = (label, fmt, cls = 'btn-ghost') =>
    el('button', {
      className: `btn btn-sm ${cls}`,
      onclick: async () => {
        try { await api.exportScan(scanState.id, fmt); }
        catch (e) { toast(e.message, 'error'); }
      },
    }, label);

  wrap.appendChild(make('SARIF', 'sarif'));
  wrap.appendChild(make('JSON', 'json'));
  wrap.appendChild(make('Markdown', 'md'));
  wrap.appendChild(make('CSV', 'csv'));
  wrap.appendChild(make('PDF', 'pdf', 'btn'));
}

function renderToolbar() {
  const tb = document.getElementById('triage-toolbar');
  // Severity pills are added once; ensure not duplicated
  if (!tb.querySelector('[data-sev-pill]')) {
    const sevs = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of sevs) {
      const pill = el('button', {
        className: 'pill active',
        'data-sev': sev,
        'data-sev-pill': '',
        onclick: () => toggleSev(sev),
      });
      pill.appendChild(el('span', { className: 'glyph' }, SEVERITY_GLYPH[sev]));
      pill.appendChild(document.createTextNode(' ' + sev));
      pill.appendChild(el('span', { className: 'count', 'data-sev-count': sev }, '0'));
      tb.appendChild(pill);
    }
  }

  // Wire search and selects (idempotent)
  const search = document.getElementById('search-input');
  if (!search.dataset.bound) {
    search.dataset.bound = '1';
    search.addEventListener('input', debounce((e) => {
      searchQuery = e.target.value.toLowerCase();
      renderTable();
    }, 100));
  }
  const groupSel = document.getElementById('group-by');
  if (!groupSel.dataset.bound) {
    groupSel.dataset.bound = '1';
    groupSel.addEventListener('change', (e) => {
      groupBy = e.target.value; renderTable();
    });
  }
  const sortSel = document.getElementById('sort-by');
  if (!sortSel.dataset.bound) {
    sortSel.dataset.bound = '1';
    sortSel.addEventListener('change', (e) => {
      sortBy = e.target.value; renderTable();
    });
  }
}

function toggleSev(sev) {
  if (selectedSeverities.has(sev)) selectedSeverities.delete(sev);
  else selectedSeverities.add(sev);
  document.querySelector(`[data-sev-pill][data-sev="${sev}"]`)
    .classList.toggle('active', selectedSeverities.has(sev));
  renderTable();
}

function renderSummary() {
  const sum = scanState.summary || {};
  // Severity counts on the pills
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const elc = document.querySelector(`[data-sev-count="${sev}"]`);
    if (elc) elc.textContent = String(sum[sev] || 0);
  }

  const wrap = document.getElementById('triage-summary');
  wrap.innerHTML = '';

  const total = findingsState.length;
  wrap.appendChild(textGroup(`${total}`, 'total'));
  wrap.appendChild(el('span', { className: 'delim' }, '·'));

  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const n = sum[sev] || 0;
    const grp = el('span', { className: 'grp' });
    grp.appendChild(el('span', {
      className: 'glyph',
      style: `color: var(--sev-${sev});`,
    }, SEVERITY_GLYPH[sev]));
    grp.appendChild(el('span', {}, String(n)));
    wrap.appendChild(grp);
  }

  if (engagementState) {
    wrap.appendChild(el('span', { className: 'delim' }, '·'));
    wrap.appendChild(textGroup(engagementState.client_name, 'client'));
  }

  if (scanState.profile) {
    wrap.appendChild(el('span', { className: 'delim' }, '·'));
    wrap.appendChild(textGroup(scanState.profile, 'profile'));
  }
}

function textGroup(value, label) {
  const grp = el('span', { className: 'grp' });
  grp.appendChild(el('span', { style: 'color: var(--text);' }, String(value)));
  grp.appendChild(el('span', { className: 'glyph' }, label));
  return grp;
}

// ---------- table ----------

function renderTable() {
  const wrap = document.getElementById('findings-table');
  wrap.innerHTML = '';

  let visible = findingsState.filter(f => {
    const sev = effectiveSeverity(f);
    if (!selectedSeverities.has(sev)) return false;
    if (!selectedStatuses.has(f.status || 'new')) return false;
    if (searchQuery) {
      const hay = [
        f.title, f.module, f.cwe_id, f.tracking_id, f.target_url,
        f.evidence, f.evidence_request, f.evidence_response,
        f.description,
      ].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  });

  visible = sortFindings(visible);

  if (visible.length === 0) {
    wrap.appendChild(el('div', {
      className: 'drawer-empty',
      style: 'height: 200px;',
    }, findingsState.length === 0
      ? 'this scan produced no findings'
      : 'no findings match the current filters'));
    return;
  }

  // Group
  const groups = groupFindings(visible);
  for (const [groupLabel, rows] of groups) {
    if (groupBy !== 'none') {
      wrap.appendChild(el('div', { className: 'group-head' },
        `${groupLabel} · ${rows.length}`));
    }
    for (const f of rows) wrap.appendChild(rowFor(f));
  }
}

function rowFor(f) {
  const sev = effectiveSeverity(f);
  const row = el('div', {
    className: 'findings-row' + (activeFinding && activeFinding.id === f.id ? ' selected' : ''),
    onclick: () => selectFinding(f),
  });
  row.appendChild(el('span', { className: `sev sev-${sev}` }, SEVERITY_GLYPH[sev] || '·'));
  row.appendChild(el('span', { className: 'id' }, f.tracking_id || `cys-${(f.id || '').slice(0, 6)}`));
  row.appendChild(el('span', { className: 'title' }, f.title || '(untitled)'));
  row.appendChild(el('span', { className: 'host' }, hostOf(f.target_url || scanState.target_url)));
  row.appendChild(el('span', { className: 'cvss' }, fmtCvss(f.cvss_score)));
  row.appendChild(el('span', {
    className: 'status-tag ' + (f.status || 'new'),
  }, STATUS_LABELS[f.status] || 'NEW'));
  row.appendChild(el('span', { className: 'age' }, relativeAge(f.discovered_at)));
  return row;
}

function sortFindings(arr) {
  const copy = arr.slice();
  if (sortBy === 'severity') {
    copy.sort((a, b) => severityRank(effectiveSeverity(a)) - severityRank(effectiveSeverity(b))
      || (b.cvss_score || 0) - (a.cvss_score || 0));
  } else if (sortBy === 'cvss') {
    copy.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
  } else if (sortBy === 'title') {
    copy.sort((a, b) => (a.title || '').localeCompare(b.title || ''));
  } else if (sortBy === 'age') {
    copy.sort((a, b) => (b.discovered_at || '').localeCompare(a.discovered_at || ''));
  }
  return copy;
}

function groupFindings(arr) {
  if (groupBy === 'none') return [['', arr]];
  const groups = new Map();
  const keyOf = (f) => {
    if (groupBy === 'severity') return effectiveSeverity(f);
    if (groupBy === 'module') return f.module || 'unknown';
    if (groupBy === 'status') return f.status || 'new';
    if (groupBy === 'host') return hostOf(f.target_url || scanState.target_url);
    if (groupBy === 'cwe') return f.cwe_id || 'no-cwe';
    return '';
  };
  for (const f of arr) {
    const k = keyOf(f);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  // For severity, preserve the canonical order
  if (groupBy === 'severity') {
    const ordered = ['critical', 'high', 'medium', 'low', 'info']
      .filter(k => groups.has(k))
      .map(k => [k, groups.get(k)]);
    return ordered;
  }
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

// ---------- drawer ----------

function clearDrawer() {
  activeFinding = null;
  document.querySelectorAll('.findings-row').forEach(r => r.classList.remove('selected'));
  const drawer = document.getElementById('drawer');
  drawer.innerHTML = '';
  drawer.appendChild(el('div', {
    className: 'drawer-empty', id: 'drawer-empty',
  }, [
    'select a finding to inspect evidence,',
    el('br'),
    'reproducer, status, notes, history',
  ]));
}

async function selectFinding(f) {
  activeFinding = f;
  // mark row
  document.querySelectorAll('.findings-row').forEach(r => r.classList.remove('selected'));
  // (visual update on next render)
  renderDrawer(f);
  document.querySelectorAll('.findings-row').forEach(r => {
    if (r.querySelector('.id')?.textContent ===
        (f.tracking_id || `cys-${(f.id || '').slice(0, 6)}`)) r.classList.add('selected');
  });
}

function renderDrawer(f) {
  const drawer = document.getElementById('drawer');
  drawer.innerHTML = '';

  const sev = effectiveSeverity(f);
  const head = el('div', { className: 'drawer-head' });

  const top = el('div', { className: 'top' });
  top.appendChild(el('span', { className: `sev sev-${sev}` }, SEVERITY_GLYPH[sev] || '·'));
  top.appendChild(el('span', { className: 'id' }, f.tracking_id || `cys-${(f.id || '').slice(0, 6)}`));
  top.appendChild(el('span', { className: 'spacer', style: 'flex:1' }));
  top.appendChild(el('span', {
    className: 'mono', style: 'color: var(--text-muted); font-size: 12px;',
  }, `CVSS ${fmtCvss(f.cvss_score)}`));
  head.appendChild(top);

  head.appendChild(el('h2', {}, f.title || '(untitled)'));

  const meta = el('div', { className: 'meta' });
  meta.appendChild(el('span', {}, `module · ${MODULE_NAMES[f.module] || f.module}`));
  if (f.cwe_id) meta.appendChild(el('span', {}, `cwe · ${f.cwe_id}`));
  meta.appendChild(el('span', {}, `confidence · ${CONFIDENCE_LABELS[f.confidence] || f.confidence}`));
  if (f.target_url) meta.appendChild(el('span', {}, `path · ${hostOf(f.target_url)}`));
  head.appendChild(meta);

  drawer.appendChild(head);

  // Tabs
  const tabs = el('div', { className: 'drawer-tabs' });
  const tabNames = ['evidence', 'description', 'remediation', 'notes', 'history', 'workflow'];
  for (const name of tabNames) {
    const t = el('button', {
      className: 'drawer-tab' + (activeTab === name ? ' active' : ''),
      'data-tab': name,
      onclick: () => { activeTab = name; renderDrawer(f); },
    }, name);
    tabs.appendChild(t);
  }
  drawer.appendChild(tabs);

  // Body
  const body = el('div', { className: 'drawer-body' });
  drawer.appendChild(body);

  if (activeTab === 'evidence') renderEvidenceTab(body, f);
  else if (activeTab === 'description') renderDescriptionTab(body, f);
  else if (activeTab === 'remediation') renderRemediationTab(body, f);
  else if (activeTab === 'notes') renderNotesTab(body, f);
  else if (activeTab === 'history') renderHistoryTab(body, f);
  else if (activeTab === 'workflow') renderWorkflowTab(body, f);
}

function makeCodeBlock(content) {
  const pre = el('pre', { className: 'code' });
  pre.textContent = content;
  const btn = el('button', { className: 'code-copy' }, 'copy');
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    copyText(content, btn);
  });
  pre.appendChild(btn);
  return pre;
}

function renderEvidenceTab(body, f) {
  if (f.evidence_curl) {
    body.appendChild(el('h4', {}, 'reproducer (curl)'));
    body.appendChild(makeCodeBlock(f.evidence_curl));
  }
  if (f.evidence_request) {
    body.appendChild(el('h4', {}, 'request'));
    body.appendChild(makeCodeBlock(f.evidence_request));
  }
  if (f.evidence_response) {
    body.appendChild(el('h4', {}, 'response'));
    body.appendChild(makeCodeBlock(f.evidence_response));
  }
  if (f.evidence && !f.evidence_request) {
    body.appendChild(el('h4', {}, 'evidence'));
    body.appendChild(makeCodeBlock(f.evidence));
  }
  if (f.cvss_vector) {
    body.appendChild(el('h4', {}, 'cvss vector'));
    body.appendChild(makeCodeBlock(f.cvss_vector));
  }
  if (!f.evidence_curl && !f.evidence_request && !f.evidence) {
    body.appendChild(el('p', { className: 'faint' },
      'this finding has no captured HTTP evidence yet. heuristic-only scanners (e.g. ssl, ports) report on out-of-band channels.'));
  }
}

function renderDescriptionTab(body, f) {
  if (f.description) {
    body.appendChild(el('h4', {}, 'description'));
    body.appendChild(el('p', {}, f.description));
  }
  if (f.poc_steps && f.poc_steps.length > 0) {
    body.appendChild(el('h4', {}, 'proof of concept'));
    const ol = el('ol', { className: 'poc-steps' });
    for (const step of f.poc_steps) ol.appendChild(el('li', {}, step));
    body.appendChild(ol);
  }
  if (f.references && f.references.length > 0) {
    body.appendChild(el('h4', {}, 'references'));
    const refs = el('div', { className: 'refs' });
    for (const r of f.references) {
      refs.appendChild(el('a', { href: r, target: '_blank', rel: 'noopener' }, r));
    }
    body.appendChild(refs);
  }
}

function renderRemediationTab(body, f) {
  if (f.remediation) {
    body.appendChild(el('h4', {}, 'remediation'));
    body.appendChild(el('div', { className: 'remediation' }, f.remediation));
  } else {
    body.appendChild(el('p', { className: 'faint' }, 'no remediation guidance recorded.'));
  }
  if (f.severity_override) {
    body.appendChild(el('h4', {}, 'severity override'));
    body.appendChild(el('p', {},
      `Severity overridden to ${(f.severity_override || '').toUpperCase()}` +
      (f.severity_override_reason ? ` — ${f.severity_override_reason}` : '')));
  }
}

function renderWorkflowTab(body, f) {
  body.appendChild(el('h4', {}, 'status'));
  const statuses = [
    'new', 'triaging', 'confirmed',
    'false_positive', 'accepted_risk', 'fixed', 'wont_fix',
  ];
  const wf = el('div', { className: 'workflow' });
  for (const s of statuses) {
    const btn = el('button', {
      className: 'pill' + (f.status === s ? ' active' : ''),
      onclick: async () => {
        try {
          const updated = await api.patchFinding(f.id, { status: s });
          mergeUpdated(updated);
          renderTable();
          renderDrawer(activeFinding);
          toast('Status updated', 'ok');
        } catch (err) { toast(err.message, 'error'); }
      },
    }, STATUS_LABELS[s] || s);
    wf.appendChild(btn);
  }
  body.appendChild(wf);

  body.appendChild(el('h4', {}, 'severity override'));
  const overrideSel = el('select', {
    style: 'background: var(--bg); border: 1px solid var(--border); border-radius: var(--r-2); padding: 6px 10px; font: 500 12px var(--font-sans); color: var(--text); width: 100%;',
  });
  for (const s of ['', 'critical', 'high', 'medium', 'low', 'info']) {
    const opt = document.createElement('option');
    opt.value = s;
    opt.textContent = s ? s.toUpperCase() : '— (no override) —';
    if (f.severity_override === s || (!s && !f.severity_override)) opt.selected = true;
    overrideSel.appendChild(opt);
  }
  body.appendChild(overrideSel);

  const reason = el('textarea', {
    placeholder: 'Reason for override (recorded in audit log and report)',
    style: 'width: 100%; margin-top: 8px;',
  });
  reason.value = f.severity_override_reason || '';
  body.appendChild(reason);

  const saveBtn = el('button', {
    className: 'btn btn-primary btn-sm',
    style: 'margin-top: 8px;',
    onclick: async () => {
      try {
        const updated = await api.patchFinding(f.id, {
          severity_override: overrideSel.value || null,
          severity_override_reason: reason.value || '',
        });
        mergeUpdated(updated);
        renderTable();
        renderDrawer(activeFinding);
        toast('Override saved', 'ok');
      } catch (err) { toast(err.message, 'error'); }
    },
  }, 'Save override');
  body.appendChild(saveBtn);

  body.appendChild(el('h4', {}, 'confidence'));
  const confs = ['heuristic', 'reflected', 'executed', 'operator_confirmed'];
  const cf = el('div', { className: 'workflow' });
  for (const c of confs) {
    cf.appendChild(el('button', {
      className: 'pill' + (f.confidence === c ? ' active' : ''),
      onclick: async () => {
        try {
          const updated = await api.patchFinding(f.id, { confidence: c });
          mergeUpdated(updated);
          renderDrawer(activeFinding);
          toast('Confidence updated', 'ok');
        } catch (err) { toast(err.message, 'error'); }
      },
    }, CONFIDENCE_LABELS[c] || c));
  }
  body.appendChild(cf);
}

function renderNotesTab(body, f) {
  body.appendChild(el('h4', {}, 'notes'));
  const list = el('div', { className: 'notes-list' });
  body.appendChild(list);

  api.listNotes(f.id).then(notes => {
    list.innerHTML = '';
    if (notes.length === 0) {
      list.appendChild(el('p', { className: 'faint' }, 'no notes yet.'));
    }
    for (const n of notes) {
      const item = el('div', { className: 'note-item' });
      item.appendChild(el('div', { className: 'meta' },
        `${n.author || 'operator'} · ${relativeAge(n.created_at)}`));
      item.appendChild(el('div', { className: 'body' }, n.body));
      list.appendChild(item);
    }
  }).catch(e => {
    list.innerHTML = '';
    list.appendChild(el('p', { className: 'faint' }, 'failed to load notes: ' + e.message));
  });

  // form
  const form = el('div', { className: 'note-form' });
  const ta = el('textarea', {
    placeholder: 'add a note (markdown OK) — saved with timestamp + author',
    style: 'min-height: 70px;',
  });
  const author = el('div', { className: 'input' });
  const authorInput = el('input', { placeholder: 'your name (optional)' });
  author.appendChild(authorInput);
  form.appendChild(ta);
  form.appendChild(author);
  const submit = el('button', {
    className: 'btn btn-primary btn-sm',
    onclick: async () => {
      const text = ta.value.trim();
      if (!text) return;
      try {
        await api.addNote(f.id, text, authorInput.value.trim() || null);
        ta.value = '';
        renderDrawer(f);
        toast('Note added', 'ok');
      } catch (e) { toast(e.message, 'error'); }
    },
  }, 'Add note');
  form.appendChild(submit);
  body.appendChild(form);
}

function renderHistoryTab(body, f) {
  body.appendChild(el('h4', {}, 'audit log for this scan'));
  const list = el('div', { className: 'history' });
  body.appendChild(list);

  const populate = (events) => {
    list.innerHTML = '';
    const relevant = events.filter(ev =>
      !ev.finding_id || ev.finding_id === f.id
    );
    if (relevant.length === 0) {
      list.appendChild(el('p', { className: 'faint' }, 'no events recorded.'));
      return;
    }
    for (const ev of relevant) {
      const it = el('div', { className: 'history-item' });
      it.appendChild(el('span', { className: 'ev' }, ev.event_type));
      const detail = ev.details && Object.keys(ev.details).length > 0
        ? JSON.stringify(ev.details).slice(0, 80)
        : '';
      it.appendChild(el('span', { className: 'mono', style: 'color: var(--text-faint);' }, detail));
      it.appendChild(el('span', { className: 'ts' }, relativeAge(ev.created_at)));
      list.appendChild(it);
    }
  };

  if (auditState.length > 0) {
    populate(auditState);
  } else {
    api.getScanAudit(scanState.id)
      .then(events => { auditState = events; populate(events); })
      .catch(e => {
        list.innerHTML = '';
        list.appendChild(el('p', { className: 'faint' }, 'failed to load audit: ' + e.message));
      });
  }
}

function mergeUpdated(updated) {
  // splice the updated finding back into findingsState
  const idx = findingsState.findIndex(x => x.id === updated.id);
  if (idx >= 0) {
    findingsState[idx] = { ...findingsState[idx], ...updated };
    if (activeFinding && activeFinding.id === updated.id) {
      activeFinding = findingsState[idx];
    }
  }
}

export function init() {
  // wire drawer-empty placeholder once
  // most wiring is per-render
}
