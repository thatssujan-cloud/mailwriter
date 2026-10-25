/* ==========================================================================
   LetterDesk — js/backend.js
   Serverless proxy configuration and the central fetch wrapper used by the
   research engines. Loaded as a classic script from index.html BEFORE the
   inline app code, so dataFetch/dataPost are defined before first use.

   IMPORTANT: /api/search is a SERVERLESS FUNCTION (api/search.js) that only
   executes on Vercel or Netlify. GitHub Pages serves it as plain text, which
   previously caused a SILENT fallback to keyless direct calls. The probe in
   PROXY_STATUS below detects that situation once per page load and disables
   the proxy path explicitly (with a console warning) instead of failing
   quietly. Deployment + verification steps: see SECURITY.md and README.md.
   ========================================================================== */
/* ==================================================================
   SERVERLESS PROXY CONFIG (Vercel / Netlify) — see api/search.js
   ------------------------------------------------------------------
   This page works with zero setup: OpenAlex is queried directly and
   needs no API key. Paid services (Groq drafting, Hunter.io, Abstract,
   ZeroBounce) DO require keys that must NEVER ship in client code —
   they live only in hosting environment variables:

     Vercel:   vercel env add GROQ_API_KEY / OPENALEX_API_KEY ...
     Netlify:  Site settings → Environment variables

   Set USE_SERVER_PROXY = true once deployed; until then the site
   stays fully functional against keyless OpenAlex + local checks.
================================================================== */
const BACKEND = {
  USE_SERVER_PROXY: (location.protocol === 'https:' && location.hostname !== '' && !/^(localhost|127\.0\.0\.1)$/.test(location.hostname)),
  get proxyUrl() { return '/api/search'; }
};

// Browser session id for server-side per-session rate limiting
// (RATE_LIMIT_PER_SESSION in api/_shared.js). Random, persisted per tab;
// contains no personal data.
function ldSessionId() {
  try {
    let s = sessionStorage.getItem('ld_sid');
    if (!s || !/^[\w:-]{8,64}$/.test(s)) {
      s = 'ld-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
      sessionStorage.setItem('ld_sid', s);
    }
    return s;
  } catch (e) {
    return 'ld-' + Math.random().toString(36).slice(2, 10);
  }
}

/* ------------------- Proxy availability self-check ----------------------- */
// One cheap probe per page load distinguishes three states:
//   'ready'    — function executes and responds with JSON
//   'absent'   — 404/405 or raw JS/HTML answer (e.g. GitHub Pages): the
//                serverless runtime is NOT executing api/search.js. We log
//                a loud warning (no longer silent) and skip proxy attempts.
//   'unknown'  — network error; retried lazily on the next call.
// lastError records the most recent structured proxy error ({error, retryAfter})
// so UI code can surface "rate limited — retry in Ns" instead of failing
// silently into generic fallbacks (#7/#8 surfacing).
const PROXY_STATUS = { state: 'unknown', checkedAt: 0, lastError: null };

// Parse a non-OK proxy response body for the structured error shape that
// api/search.js returns: {"error": "...", "retryAfter": <seconds>}. Safe on
// empty/non-JSON bodies. Stores the result on PROXY_STATUS.lastError.
async function recordProxyError(r) {
  let info = null;
  try {
    const ct = r.headers.get('content-type') || '';
    if (ct.includes('json')) {
      const j = await r.json();
      if (j && typeof j.error === 'string') {
        info = { status: r.status, error: j.error, retryAfter: Number(j.retryAfter) || null };
      }
    }
  } catch (e) { /* body unreadable — fall through with null */ }
  if (!info) info = { status: r.status, error: `HTTP ${r.status}`, retryAfter: null };
  PROXY_STATUS.lastError = info;
  return info;
}

// fetch with an AbortController-based timeout (#9). Rejects with a
// TimeoutError when the request exceeds timeoutMs; always cleans up the
// timer and abort listener so no handles leak.
async function proxyFetch(url, init, timeoutMs = 15000) {
  const ctrl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, timeoutMs);
  try {
    return await fetch(url, Object.assign({}, init, { signal: ctrl.signal }));
  } catch (e) {
    if (timedOut) throw new DOMException(`proxy request timed out after ${timeoutMs}ms`, 'TimeoutError');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function probeProxy() {
  PROXY_STATUS.checkedAt = Date.now();
  try {
    // An intentionally invalid target must come back as JSON 400 (or 429 —
    // the function may already be rate-limiting this session, which still
    // proves it is executing) ONLY if a real function is running; static
    // hosts return 200 + raw JS source. 5 s cap so a slow cold start can't
    // stall the first search.
    const r = await proxyFetch(`${BACKEND.proxyUrl}?target=__probe__`,
      { headers: { 'X-Session-Id': ldSessionId() } }, 5000);
    const ct = r.headers.get('content-type') || '';
    const jsonErr = ct.includes('json');
    if ((r.status === 400 || r.status === 429) && jsonErr) {
      PROXY_STATUS.state = 'ready';
      if (r.status === 429) await recordProxyError(r); // remember the limit window
    } else if (jsonErr && !r.ok) {
      // Any other JSON error still proves the function executes.
      PROXY_STATUS.state = 'ready';
      await recordProxyError(r);
    } else {
      PROXY_STATUS.state = 'absent';
      console.warn('[LetterDesk] /api/search is not executing as a serverless function on this host ' +
        `(got HTTP ${r.status}). GitHub Pages cannot run it — deploy to Vercel or Netlify (see SECURITY.md). ` +
        'Falling back to keyless direct calls; AI draft mode will use local templates.');
    }
  } catch (e) {
    PROXY_STATUS.state = 'unknown';
  }
  return PROXY_STATUS.state;
}

// Central fetch wrapper: routes through the serverless proxy when it's
// available (keys stay server-side), falls back to direct keyless calls.
async function dataFetch(target, params) {
  const qs = new URLSearchParams(params).toString();
  if (BACKEND.USE_SERVER_PROXY) {
    if (PROXY_STATUS.state === 'unknown' || Date.now() - PROXY_STATUS.checkedAt > 5 * 60 * 1000) {
      await probeProxy();
    }
    if (PROXY_STATUS.state === 'ready') {
      try {
        const r = await proxyFetch(`${BACKEND.proxyUrl}?target=${encodeURIComponent(target)}&${qs}`,
          { headers: { 'X-Session-Id': ldSessionId() } });
        if (r.ok) {
          PROXY_STATUS.lastError = null;
          const json = await r.json();
          if (json && (json.results || json.status || json.success !== undefined)) return json;
        } else if (r.status === 404 || r.status === 405) {
          // Function gone/unreachable mid-session — re-probe next time.
          PROXY_STATUS.state = 'unknown';
        } else {
          // 400/429/5xx — record {error, retryAfter} so callers/UI can surface it (#7/#8).
          await recordProxyError(r);
        }
      } catch (e) { /* transient network error / timeout — caller falls back direct */ }
    }
  }
  return null; // caller performs its own direct fetch
}

/* POST variant used by the AI generation mode (Groq / Llama 3). Sends the
   draft brief to the serverless proxy — the GROQ_API_KEY lives only in the
   hosting environment and never ships in client code. Resolves null when
   the proxy is absent, rate-limited, or over its spending cap, so callers
   fall back to the local template engine without breaking the UX. */
async function dataPost(target, payload) {
  if (!BACKEND.USE_SERVER_PROXY) return null;
  if (PROXY_STATUS.state === 'absent') return null;
  if (PROXY_STATUS.state === 'unknown') {
    const s = await probeProxy();
    if (s === 'absent') return null;
  }
  try {
    const r = await proxyFetch(`${BACKEND.proxyUrl}?target=${encodeURIComponent(target)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': ldSessionId() },
      body: JSON.stringify(payload || {})
    });
    if (!r.ok) {
      if (r.status === 404 || r.status === 405) PROXY_STATUS.state = 'unknown';
      else await recordProxyError(r); // 429/400/5xx — surface via PROXY_STATUS.lastError (#7/#8)
      return null;
    }
    PROXY_STATUS.lastError = null;
    const json = await r.json();
    return (json && json.text) ? json : null;
  } catch (e) { return null; }
}
