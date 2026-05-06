/**
 * Shared helpers: severity, formatting, DOM, toasts.
 * Severity carries colour AND a single-letter glyph (CVD-safe).
 */

export const SEVERITY_GLYPH = {
  critical: 'C', high: 'H', medium: 'M', low: 'L', info: 'i',
};

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const STATUS_LABELS = {
  new: 'NEW',
  triaging: 'TRIAGING',
  confirmed: 'CONFIRMED',
  false_positive: 'FALSE-POS',
  accepted_risk: 'ACCEPTED',
  fixed: 'FIXED',
  wont_fix: 'WON\'T FIX',
};

export const MODULE_NAMES = {
  crawler: 'Crawler',
  headers: 'Headers',
  ssl: 'SSL/TLS',
  ports: 'Ports',
  tech: 'Tech',
  xss: 'XSS',
  sqli: 'SQLi',
  cmdi: 'CmdI',
  pathtraversal: 'Path Trav',
  cors: 'CORS',
  clickjack: 'Clickjack',
  session: 'Session',
  redirect: 'Redirect',
  ratelimit: 'Rate Limit',
  accesscontrol: 'Access',
  apisecurity: 'API',
  cve: 'CVE',
};

export const CONFIDENCE_LABELS = {
  heuristic: 'heuristic',
  reflected: 'reflected',
  executed: 'executed',
  operator_confirmed: 'confirmed',
};

export function escapeHtml(s) {
  if (s == null) return '';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

export function hostOf(url) {
  try { return new URL(url).hostname; } catch { return url || ''; }
}

export function shortId(s) { return (s || '').slice(0, 8); }

export function relativeAge(iso) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '';
  const diff = Date.now() - t;
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d`;
  const mo = Math.floor(d / 30);
  return `${mo}mo`;
}

export function debounce(fn, ms = 200) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'className') e.className = v;
    else if (k === 'innerHTML') e.innerHTML = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) {
    if (c == null || c === false) continue;
    if (typeof c === 'string') e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
  return e;
}

/* ---------- toast ---------- */

export function toast(message, kind = '') {
  const wrap = document.getElementById('toast-wrap');
  if (!wrap) return;
  const t = el('div', { className: `toast ${kind}` }, message);
  wrap.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transition = 'opacity 220ms';
    setTimeout(() => t.remove(), 240);
  }, 2400);
}

/* ---------- copy to clipboard ---------- */

export async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) {
      const old = btn.textContent;
      btn.textContent = 'copied';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = old;
        btn.classList.remove('copied');
      }, 1100);
    }
  } catch {
    toast('Copy blocked by browser', 'error');
  }
}

/* ---------- severity / status helpers ---------- */

export function effectiveSeverity(f) {
  return (f.severity_override || f.severity || 'info').toLowerCase();
}

export function severityRank(sev) {
  return SEVERITY_ORDER[sev] ?? 5;
}

export function fmtCvss(score) {
  const n = Number(score) || 0;
  return n.toFixed(1);
}
