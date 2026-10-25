/**
 * api/_shared.js — shared security helpers for the /api/search proxy.
 *
 * SINGLE SOURCE OF TRUTH: scripts/build-search.js inlines this file verbatim
 * into api/search.js (the deployable, self-contained function file). Edit
 * HERE, then run `node scripts/build-search.js`. CI runs
 * `node scripts/build-search.js --check` so the two can never drift apart.
 *
 * NOTE: files beginning with "_" are ignored by Vercel's function router
 * (vercel.json `functions.exclude`), so this module is never exposed as an
 * HTTP endpoint of its own.
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

// Positive-integer only: rejects '', floats/garbage ('5.9'), NaN and Infinity,
// then clamps into [perPageMin, perPageMax]. Never throws on null/undefined.
function cleanPerPage(raw, dflt = '5') {
  const s = String(raw == null ? '' : raw).trim();
  if (!/^\d+$/.test(s)) return String(dflt);
  const n = Number(s);
  if (!Number.isSafeInteger(n)) return String(dflt);
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

const MAX_UPSTREAM_BODY_BYTES = 512 * 1024; // 512 KB cap on any upstream payload

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
    // Spread `init` FIRST so our hardening flags (redirect/signal) always
    // win — previously a caller-supplied `signal` could defeat the timeout.
    const res = await fetch(u.toString(), { ...init, redirect: 'error', signal: ctrl.signal });
    // Bound memory: reject oversized payloads before buffering them.
    const declaredLen = Number(res.headers.get('content-length'));
    if (Number.isFinite(declaredLen) && declaredLen > MAX_UPSTREAM_BODY_BYTES) {
      throw new Error('upstream-body-too-large');
    }
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/* ----------------------------- Rate limiting ----------------------------- */
// Fixed-window counter kept in the function instance's memory. Serverless
// instances are short-lived, so this is a best-effort first line of defense;
// pair it with platform-level WAF rules for hard guarantees.
const WINDOW_MS = 60_000;       // per-minute window (IP/session rate limits, Groq req cap)
const TOKEN_WINDOW_MS = 15 * 60_000; // rolling token/spend window (see note below)
const bucketsIP = new Map();      // ip -> { count, resetAt }
const bucketsSession = new Map(); // session -> { count, resetAt }

// Robust positive-integer env reader: NaN-safe, floor-bounded, defaults.
// A misconfigured env var (e.g. RATE_LIMIT_PER_IP="abc" or "0") previously
// produced parseInt -> NaN/0, which silently disabled the limiter entirely
// (NaN comparisons are always false) — now it falls back to the default.
function envInt(name, dflt) {
  const n = parseInt(process.env[name], 10);
  return Number.isSafeInteger(n) && n > 0 ? n : dflt;
}

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

// The availability probe (target=__probe__) is pure routing metadata — it
// costs no upstream calls and no money. Exempting it keeps page-load probes
// from eating the per-IP budget (#8).
const RATE_LIMIT_EXEMPT_TARGETS = new Set(['__probe__']);

function checkRateLimit(req, event, target) {
  if (RATE_LIMIT_EXEMPT_TARGETS.has(String(target || ''))) return null;
  const ipCap = envInt('RATE_LIMIT_PER_IP', 30);
  const sessCap = envInt('RATE_LIMIT_PER_SESSION', 60); // per browser session, same 1-min window
  const now = Date.now();
  const ip = clientIp(req, event);
  if (!consume(bucketsIP, ip, ipCap)) {
    logWarn('rate-limit', { scope: 'ip', ip });
    // Report the REAL seconds until this bucket's window resets (read AFTER
    // consume, which guarantees the entry exists) instead of always 60.
    const resetAt = bucketsIP.get(ip).resetAt;
    return { retryAfter: Math.max(1000, Math.ceil((resetAt - now) / 1000) * 1000), scope: 'ip' };
  }
  const sess = clientSession(req, event);
  if (sess && !consume(bucketsSession, sess, sessCap)) {
    logWarn('rate-limit', { scope: 'session', ip });
    const resetAt = bucketsSession.get(sess).resetAt;
    return { retryAfter: Math.max(1000, Math.ceil((resetAt - now) / 1000) * 1000), scope: 'session' };
  }
  return null;
}

/* ---------------------------- Response caching ---------------------------- */
// #5: small in-instance LRU for idempotent, slowly-changing upstream lookups
// (author lists, works, MX records). Keys are route + normalized params —
// NEVER raw emails and never API keys. TTLs stay short (minutes) because
// research metadata changes rarely and freshness matters little. Cache hits
// skip the upstream call entirely, protecting quota and rate-limit budget.
const CACHE_MAX_ENTRIES = 200;
const responseCache = new Map(); // cacheKey -> { value, expiresAt }

function cacheGet(key) {
  const e = responseCache.get(key);
  if (!e) return null;
  if (e.expiresAt <= Date.now()) { responseCache.delete(key); return null; }
  // LRU touch: re-insert so iteration order tracks recency.
  responseCache.delete(key);
  responseCache.set(key, e);
  return e.value;
}

function cacheSet(key, value, ttlMs) {
  while (responseCache.size >= CACHE_MAX_ENTRIES) {
    // Evict least-recently-used (first inserted after touches).
    const oldest = responseCache.keys().next();
    if (oldest.done) break;
    responseCache.delete(oldest.value);
  }
  responseCache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

// Canonical cache key: route name + sorted query params, minus volatile /
// privacy-sensitive entries (api_key, mailto, raw email, consent flag). For
// email-verify the key carries only the DOMAIN (MX records are per-domain)
// plus the verification scope — a full address never enters the cache.
function cacheKey(routeName, params) {
  const skip = new Set(['api_key', 'mailto', 'consent', 'email', 'search', 'target']);
  const parts = [];
  for (const [k, v] of params.entries()) {
    if (skip.has(k)) continue;
    parts.push(`${k}=${String(v).toLowerCase()}`);
  }
  parts.sort();
  if (routeName === 'email-verify') {
    const email = cleanEmail(params.get('email')) || '';
    const scope = String(params.get('consent') || '') === 'full' ? 'full' : 'domain';
    parts.push(`scope=${scope}`, `domain=${email.split('@')[1] || ''}`);
  } else {
    parts.push(`q=${String(params.get('search') || params.get('query.author') || '').toLowerCase()}`);
  }
  return `${routeName}|${parts.join('&')}`;
}

/* ---------------------------- Spending controls -------------------------- */
// Global Groq quota caps. Token counts come back on every Groq response, so
// we can meter real usage across warm instances within a window. When any
// cap trips, the route returns 429 "groq-cap" and the client falls back to
// the local template engine — spend can never exceed one window's worth.
//
// Two independent windows:
//   • requests  -> fixed 1-minute window  (GROQ_MAX_REQUESTS_PER_MIN)
//   • tokens    -> fixed 15-minute window (GROQ_MAX_TOKENS_PER_HOUR is an
//     hourly budget; serverless instances are short-lived, so a shorter
//     window keeps worst-case over-spend small while still throttling hard).
const groqUsage = {
  requests: 0,
  tokens: 0,
  minuteStart: Date.now(),      // start of the current request window
  tokenWindowStart: Date.now(), // start of the current token/spend window
  alerted: {}
};

function groqRollover() {
  const now = Date.now();
  if (now - groqUsage.minuteStart >= WINDOW_MS) {          // per-minute counter
    groqUsage.requests = 0;
    groqUsage.minuteStart = now;
    groqUsage.alerted = {};
  }
  if (now - groqUsage.tokenWindowStart >= TOKEN_WINDOW_MS) { // token budget
    groqUsage.tokens = 0;
    groqUsage.tokenWindowStart = now;
  }
}

function groqCapStatus() {
  groqRollover();
  const reqCap = envInt('GROQ_MAX_REQUESTS_PER_MIN', 10);
  const tokCap = envInt('GROQ_MAX_TOKENS_PER_HOUR', 60000);
  if (groqUsage.requests >= reqCap) return 'requests';
  if (groqUsage.tokens >= tokCap) return 'tokens';
  return null;
}

// Seconds until the earliest window reset — used for Retry-After on 429s
// instead of a hard-coded "60".
function groqRetryAfterSeconds() {
  const now = Date.now();
  const toNextMinute = Math.ceil((groqUsage.minuteStart + WINDOW_MS - now) / 1000);
  const toNextTokenWindow = Math.ceil((groqUsage.tokenWindowStart + TOKEN_WINDOW_MS - now) / 1000);
  return String(Math.max(1, Math.min(toNextMinute, toNextTokenWindow)));
}

function recordGroqUsage(tokens) {
  groqRollover();
  groqUsage.requests += 1;
  groqUsage.tokens += Math.max(0, tokens | 0);
  const reqCap = envInt('GROQ_MAX_REQUESTS_PER_MIN', 10);
  const tokCap = envInt('GROQ_MAX_TOKENS_PER_HOUR', 60000);
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
  checkRateLimit, clientIp, clientSession, envInt,
  cacheGet, cacheSet, cacheKey,
  cacheGet, cacheSet, cacheKey,
  groqCapStatus, groqRetryAfterSeconds, recordGroqUsage,
  noteAbuse
};
