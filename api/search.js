/**
 * /api/search — Serverless proxy for LetterDesk (Vercel & Netlify Functions)
 * ============================================================================
 * WHY THIS EXISTS
 *  • Browsers cannot do DNS/MX lookups and anonymous API use is rate-limited.
 *    A server-side proxy fixes CORS and lets us attach real API keys.
 *  • Keys NEVER ship in client code. Store them in the hosting dashboard:
 *      Vercel:   Project → Settings → Environment Variables → `vercel env add`
 *      Netlify:  Site configuration → Environment variables
 *    Supported variables (all optional — each feature degrades gracefully):
 *      OPENALEX_API_KEY   free key at https://openalex.org/settings/api
 *      OPENALEX_MAILTO    your email (polite pool → higher rate limits)
 *      HUNTER_API_KEY     https://hunter.io/api/keys         (email verify v2)
 *      ABSTRACT_API_KEY   https://docs.abstractapi.com/email (email validation)
 *      ZEROBOUNCE_API_KEY https://www.zerobounce.net         (email validation)
 *
 * ROUTES (query-string based so one file works on both platforms)
 *  GET /api/search?target=openalex-authors&search=Yoshua+Bengio
 *      → proxied OpenAlex author search (adds api_key + mailto server-side)
 *  GET /api/search?target=openalex-works&authorId=A5086198262
 *      → most recent publications for an OpenAlex author id
 *  GET /api/search?target=email-verify&email=j.smith@university.edu
 *      → { mx_active, deliverable, quality, provider } using whichever
 *        verification key is configured (Hunter → Abstract → ZeroBounce →
 *        plain DNS MX check via dns.google as a last resort)
 *
 * DEPLOYMENT QUICK START
 *  Vercel:  `npm i -g vercel && vercel` from this folder — /api/*.js files
 *           are detected automatically as functions. Add env vars, redeploy.
 *  Netlify: connect the repo; no build command needed — /api/*.js are picked
 *           up as Netlify Functions automatically. Add env vars in the UI.
 */

const JSON_HEADERS = {
  'Content-Type': 'application/json',
  // Lock CORS down to your deployed origin once you know it, e.g.
  // 'Access-Control-Allow-Origin': 'https://letterdesk.vercel.app'
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Cache-Control': 'no-store'
};

const ok  = body => ({ statusCode: 200, headers: JSON_HEADERS, body: JSON.stringify(body) });
const bad = (msg, code = 400) => ({ statusCode: code, headers: JSON_HEADERS, body: JSON.stringify({ error: msg }) });

/* ----------------------------- OpenAlex -------------------------------- */
async function openalexAuthors(params) {
  const q = String(params.get('search') || '').trim();
  if (!q) return bad('Missing "search" parameter.');
  const usp = new URLSearchParams({
    search: q,
    'per-page': params.get('perPage') || '5',
    select: 'id,display_name,orcid,summary_stats,last_known_institutions,topics,works_count,cited_by_count'
  });
  if (process.env.OPENALEX_API_KEY) usp.set('api_key', process.env.OPENALEX_API_KEY);
  if (process.env.OPENALEX_MAILTO)  usp.set('mailto',  process.env.OPENALEX_MAILTO);
  const res = await fetch(`https://api.openalex.org/authors?${usp}`);
  if (!res.ok) return bad(`OpenAlex upstream error ${res.status}`, 502);
  return ok(await res.json());
}

async function openalexWorks(params) {
  const authorId = String(params.get('authorId') || '').replace(/[^A-Za-z0-9_\-]/g, '');
  if (!authorId) return bad('Missing "authorId" parameter.');
  const usp = new URLSearchParams({
    filter: `author.id:${authorId}`,
    sort: 'publication_date:desc',
    'per-page': '3',
    select: 'title,publication_year,doi'
  });
  if (process.env.OPENALEX_API_KEY) usp.set('api_key', process.env.OPENALEX_API_KEY);
  if (process.env.OPENALEX_MAILTO)  usp.set('mailto',  process.env.OPENALEX_MAILTO);
  const res = await fetch(`https://api.openalex.org/works?${usp}`);
  if (!res.ok) return bad(`OpenAlex upstream error ${res.status}`, 502);
  return ok(await res.json());
}

/* -------------------------- Email verification ------------------------- */
async function emailVerify(params) {
  const email = String(params.get('email') || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad('Malformed email.');
  const domain = email.split('@')[1];

  // 1) Hunter.io — https://hunter.io/api/v2/verify
  if (process.env.HUNTER_API_KEY) {
    try {
      const r = await fetch(`https://hunter.io/api/v2/verify?email=${encodeURIComponent(email)}&api_key=${process.env.HUNTER_API_KEY}`);
      if (r.ok) {
        const j = await r.json();
        const d = j.data || {};
        return ok({
          provider: 'hunter',
          mx_active: d.mx_records ? d.mx_records.length > 0 : d.result !== 'no_mx',
          deliverable: d.result === 'deliverable',
          quality: d.score != null ? d.score / 100 : null
        });
      }
    } catch (e) { /* fall through to next provider */ }
  }

  // 2) Abstract API — https://email-validation.api.abstractapi.com/v1/
  if (process.env.ABSTRACT_API_KEY) {
    try {
      const r = await fetch(`https://email-validation.api.abstractapi.com/v1/?api_user=${process.env.ABSTRACT_API_KEY}&email=${encodeURIComponent(email)}`);
      if (r.ok) {
        const j = await r.json();
        return ok({
          provider: 'abstract',
          mx_active: j.smtp_check === true || j.reachable === true,
          deliverable: j.reachable === true || j.quality === 'good',
          quality: j.quality || null
        });
      }
    } catch (e) { /* fall through */ }
  }

  // 3) ZeroBounce — https://api.zerobounce.net/v2/validate
  if (process.env.ZEROBOUNCE_API_KEY) {
    try {
      const r = await fetch(`https://api.zerobounce.net/v2/validate?api_key=${process.env.ZEROBOUNCE_API_KEY}&email=${encodeURIComponent(email)}`);
      if (r.ok) {
        const j = await r.json();
        return ok({
          provider: 'zerobounce',
          mx_active: j.status !== 'invalid',
          deliverable: j.status === 'valid',
          quality: j.status
        });
      }
    } catch (e) { /* fall through */ }
  }

  // 4) No paid key configured → free DNS-over-HTTPS MX probe (server-side,
  //    not subject to browser limits).
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
    const j = await r.json();
    const mxActive = Array.isArray(j.Answer) && j.Answer.length > 0;
    return ok({ provider: 'dns-mx-only', mx_active: mxActive, deliverable: null, quality: null });
  } catch (e) {
    return ok({ provider: 'none', mx_active: null, deliverable: null, quality: null });
  }
}

/* ------------------------------- Router -------------------------------- */
async function route(params) {
  switch (params.get('target')) {
    case 'openalex-authors': return openalexAuthors(params);
    case 'openalex-works':   return openalexWorks(params);
    case 'email-verify':     return emailVerify(params);
    default: return bad('Unknown target. Use openalex-authors | openalex-works | email-verify.');
  }
}

function toResponse(result) {
  return new Response(result.body, { status: result.statusCode, headers: result.headers || JSON_HEADERS });
}

// Vercel (Node/Edge Function, Web-standard Request → Response).
// Prefer this file as an Edge function: keep it dependency-free (it is).
export default async function vercelHandler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: JSON_HEADERS });
  }
  const params = new URL(req.url).searchParams;
  return toResponse(await route(params));
}

// Netlify Functions (CommonJS event format). The block below is only used
// when the file is loaded by Netlify's Node runtime; harmless elsewhere.
try {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports.handler = async (event) => {
      if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: JSON_HEADERS, body: '' };
      const params = new URLSearchParams(event.queryStringParameters || {});
      return route(params);
    };
  }
} catch (e) { /* non-CJS environment — ignore */ }
