/**
 * api/_shared.js — shared security helpers for the /api/search proxy.
 *
 * NOTE: files beginning with "_" are ignored by Vercel's function router
 * (vercel.json `functions.ignore`), so this module is importable but never
 * exposed as an HTTP endpoint of its own.
 */

/* ------------------------------ Logging -------------------------------- */
// Structured JSON log line (Vercel/Netlify ship these to their log drains,
// where you can build alerts on event names like `rate-limit` or `cap`).
// PRIVACY (§4): every value passes through redact() first, so full email
// addresses and anything that looks like an API key NEVER reach the logs.
// Emails are masked to "j***@university.edu" (local part hidden); keys are
// replaced with "[redacted]".
const EMAIL_RE = /([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})/g;
const KEY_RE   = /\b(?:sk|key|hunter|zx)[-_][A-Za-z0-9]{12,}\b/g;

function maskEmail(local, domain) {
  const head = String(local).slice(0, 1);
  return `${head}***@${domain}`;
}

function redact(v) {
  if (typeof v !== 'string') return v;
  return v.replace(EMAIL_RE, (_, l, d) => maskEmail(l, d))
          .replace(KEY_RE, '[redacted]');
}

function redactFields(fields) {
  const out = {};
  for (const k of Object.keys(fields || {})) out[k] = redact(fields[k]);
  return out;
}

function log(event, fields) {
  try {
    console.log(JSON.stringify({ ts: new Date().toISOString(), level: 'info', event, ...redactFields(fields) }));
  } catch (e) { /* logging must never throw */ }
}
function logWarn(event, fields) {
  try {
    console.warn(JSON.stringify({ ts: new Date().toISOString(), level: 'warn', event, ...redactFields(fields) }));
  } catch (e) { /* noop */ }
}

/* ------------------------- CORS allow-list ------------------------------ */
// Explicit production origins ONLY — no wildcard. Configure in the hosting
// dashboard:  ALLOWED_ORIGINS="https://letterdesk.app,https://www.letterdesk.app"
// Same-origin requests (no Origin header) and local development are always OK.
const DEV_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

function allowedOriginFor(originHeader) {
  if (!originHeader) return null;                       // same-origin / curl
  const list = String(process.env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (list.includes(originHeader)) return originHeader;
  if (!list.length && DEV_ORIGIN_RE.test(originHeader)) return originHeader; // dev only when unset
  return null;
}

function corsHeaders(originHeader) {
  const h = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin'
  };
  const allowed = allowedOriginFor(originHeader);
  if (allowed) h['Access-Control-Allow-Origin'] = allowed;
  return h;
}

/* --------------------------- Input validation ---------------------------- */
const LIMITS = {
  search: 200,        // author/name queries
  perPageMin: 1,
  perPageMax: 25,
  authorId: /^[A-Za-z0-9_-]{1,32}$/,   // OpenAlex id shape: A5086198262 / AX123…
  emailRe: /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/,
  promptMaxChars: 6000
};

function cleanText(raw, maxLen) {
  const s = String(raw == null ? '' : raw).trim();
  if (s.length > maxLen) return null;
  // Reject control chars and anything that looks like URL injection.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(s)) return null;
  if (/^(https?|ftp|file|gopher|data|javascript):/i.test(s)) return null;
  return s;
}

function cleanPerPage(raw, dflt = '5') {
  const n = parseInt(String(raw == null ? '' : raw), 10);
  if (!Number.isFinite(n) || String(raw).trim() === '') return dflt;
  return String(Math.min(LIMITS.perPageMax, Math.max(LIMITS.perPageMin, n)));
}

function cleanAuthorId(raw) {
  const s = String(raw == null ? '' : raw).trim();
  return LIMITS.authorId.test(s) ? s : null;
}

function cleanEmail(raw) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase();
  return LIMITS.emailRe.test(s) ? s : null;
}

/* ------------------------ Upstream fetch hardening ----------------------- */
// Every outbound call goes through here: fixed host allow-list + timeout so
// user input can never steer the request elsewhere (SSRF) or hang a worker.
const UPSTREAM_HOSTS = new Set([
  'api.openalex.org',
  'api.semanticscholar.org',
  'api.crossref.org',
  'hunter.io',
  'email-validation.api.abstractapi.com',
  'api.zerobounce.net',
  'dns.google',
  'api.groq.com'
]);

async function safeFetch(urlStr, init = {}, timeoutMs = 9000) {
  let u;
  try { u = new URL(urlStr); } catch (e) { throw new Error('bad-url'); }
  if (u.protocol !== 'https:' || !UPSTREAM_HOSTS.has(u.hostname)) {
    logWarn('ssrf-blocked', { url: `${u.protocol}//${u.hostname}` });
    throw new Error('blocked-host');
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(u.toString(), { redirect: 'error', ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

/* ----------------------------- Rate limiting ----------------------------- */
// Fixed-window counter kept in the function instance's memory. Serverless
// instances are short-lived, so this is a best-effort first line of defense;
// pair it with platform-level WAF rules for hard guarantees.
const WINDOW_MS = 60_000;
const bucketsIP = new Map();      // ip -> { count, resetAt }
const bucketsSession = new Map(); // session -> { count, resetAt }

function clientIp(req, event) {
  const fwd = (req && req.headers && req.headers.get && req.headers.get('x-forwarded-for')) ||
              (event && event.headers && (event.headers['x-forwarded-for'] || event.headers['X-Forwarded-For']));
  if (fwd) return String(fwd).split(',')[0].trim();
  return (event && event.context && event.context.clientContext && event.context.clientContext.ip) || 'unknown';
}

function clientSession(req, event) {
  const s = (req && req.headers && req.headers.get && req.headers.get('x-session-id')) ||
            (event && event.headers && (event.headers['x-session-id'] || event.headers['X-Session-Id']));
  if (s && /^[\w:-]{8,64}$/.test(String(s))) return String(s);
  return null;
}

function consume(map, key, cap) {
  const now = Date.now();
  const b = map.get(key);
  if (!b || b.resetAt <= now) {
    if (map.size > 50_000) map.clear(); // memory guard against table growth
    map.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  if (b.count >= cap) return false;
  b.count += 1;
  return true;
}

function checkRateLimit(req, event) {
  const ipCap = parseInt(process.env.RATE_LIMIT_PER_IP || '30', 10);
  const sessCap = parseInt(process.env.RATE_LIMIT_PER_SESSION || '60', 10); // per browser session, same 1-min window
  const ip = clientIp(req, event);
  if (!consume(bucketsIP, ip, ipCap)) {
    logWarn('rate-limit', { scope: 'ip', ip });
    return { retryAfter: WINDOW_MS, scope: 'ip' };
  }
  const sess = clientSession(req, event);
  if (sess && !consume(bucketsSession, sess, sessCap)) {
    logWarn('rate-limit', { scope: 'session', ip });
    return { retryAfter: WINDOW_MS, scope: 'session' };
  }
  return null;
}

/* ---------------------------- Spending controls -------------------------- */
// Global Groq quota caps. Token counts come back on every Groq response, so
// we can meter real usage across warm instances within a window. When any
// cap trips, the route returns 429 "groq-cap" and the client falls back to
// the local template engine — spend can never exceed one window's worth.
const groqUsage = { requests: 0, tokens: 0, windowStart: Date.now(), alerted: {} };

function groqWindowRollover() {
  const now = Date.now();
  if (now - groqWindowStartSafe() >= WINDOW_MS) {
    groqUsage.requests = 0;
    groqUsage.tokens = 0;
    groqUsage.windowStart = now;
    groqUsage.alerted = {};
  }
}
function groqWindowStartSafe() { return groqUsage.windowStart || Date.now(); }

function groqCapStatus() {
  groqWindowRollover();
  const reqCap = parseInt(process.env.GROQ_MAX_REQUESTS_PER_MIN || '10', 10);
  const tokCap = parseInt(process.env.GROQ_MAX_TOKENS_PER_HOUR || '60000', 10);
  if (groqUsage.requests >= reqCap) return 'requests';
  if (groqUsage.tokens >= tokCap) return 'tokens';
  return null;
}

function recordGroqUsage(tokens) {
  groqWindowRollover();
  groqUsage.requests += 1;
  groqUsage.tokens += Math.max(0, tokens | 0);
  const reqCap = parseInt(process.env.GROQ_MAX_REQUESTS_PER_MIN || '10', 10);
  const tokCap = parseInt(process.env.GROQ_MAX_TOKENS_PER_HOUR || '60000', 10);
  // Usage alerts at 80% and hard cap — wire these events into your log
  // provider's alerting (Vercel → Alerts, Netlify → log drain + PagerDuty,
  // or Groq console usage alerts as the upstream source of truth).
  [['req', groqUsage.requests / Math.max(1, reqCap)], ['tok', groqUsage.tokens / Math.max(1, tokCap)]].forEach(([k, frac]) => {
    if (frac >= 1 && !groqUsage.alerted[k + '-full']) {
      groqUsage.alerted[k + '-full'] = true;
      logWarn('groq-cap-reached', { kind: k, requests: groqUsage.requests, tokens: groqUsage.tokens });
    } else if (frac >= 0.8 && !groqUsage.alerted[k + '-80']) {
      groqUsage.alerted[k + '-80'] = true;
      logWarn('groq-usage-alert', { kind: k, percent: Math.round(frac * 100), requests: groqUsage.requests, tokens: groqUsage.tokens });
    }
  });
}

/* ------------------------------ Abuse monitor ---------------------------- */
// Tracks rejected requests per IP; repeated abuse gets flagged loudly so the
// log-based alert (and/or a WAF ban rule) picks it up.
const abuseCounters = new Map(); // ip -> { strikes, resetAt }
const ABUSE_WINDOW_MS = 15 * 60_000;
const ABUSE_STRIKE_BAN = 10;

function noteAbuse(ip, reason) {
  const now = Date.now();
  const a = abuseCounters.get(ip);
  if (!a || a.resetAt <= now) {
    if (abuseCounters.size > 20_000) abuseCounters.clear();
    abuseCounters.set(ip, { strikes: 1, resetAt: now + ABUSE_WINDOW_MS });
    return;
  }
  a.strikes += 1;
  if (a.strikes === ABUSE_STRIKE_BAN) {
    logWarn('abuse-pattern', { ip, strikes: a.strikes, lastReason: reason, action: 'flagged-for-ban' });
  }
}

module.exports = {
  log, logWarn, redact, maskEmail,
  corsHeaders,
  LIMITS, cleanText, cleanPerPage, cleanAuthorId, cleanEmail,
  safeFetch,
  checkRateLimit, clientIp, clientSession,
  groqCapStatus, recordGroqUsage,
  noteAbuse
};
