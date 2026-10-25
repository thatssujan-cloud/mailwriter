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
 *      SEMANTIC_SCHOLAR_API_KEY  optional, raises S2 rate limits to 1 rps
 *                                 https://www.semanticscholar.org/product/api
 *      HUNTER_API_KEY     https://hunter.io/api/keys         (email verify v2)
 *      ABSTRACT_API_KEY   https://docs.abstractapi.com/email (email validation)
 *      ZEROBOUNCE_API_KEY https://www.zerobounce.net         (email validation)
 *      GROQ_API_KEY       https://console.groq.com/keys      (free Llama 3.3 70B
 *                                 drafts — never ship this key in client code)
 *
 * ROUTES (query-string based so one file works on both platforms)
 *  GET /api/search?target=openalex-authors&search=Yoshua+Bengio
 *      → proxied OpenAlex author search (adds api_key + mailto server-side)
 *  GET /api/search?target=openalex-works&authorId=A5086198262
 *      → most recent publications for an OpenAlex author id
 *  GET /api/search?target=semantic-authors&search=Yoshua+Bengio
 *      → proxied Semantic Scholar author search (server-side API key when set)
 *  GET /api/search?target=crossref-works&query.author=Yoshua+Bengio
 *      → proxied Crossref recent-work lookup (polite-pool mailto server-side)
 *  GET /api/search?target=email-verify&email=j.smith@university.edu
 *      → { mx_active, deliverable, quality, provider } using whichever
 *        verification key is configured (Hunter → Abstract → ZeroBounce →
 *        plain DNS MX check via dns.google as a last resort)
 *  POST /api/search?target=groq-draft   body: { prompt }
 *      → streams a high-converting RA/TA outreach draft from the free Groq
 *        endpoint running Llama 3.3 70B Versatile. Returns
 *        { text, model, words }. 404 "not-configured" when no key is set —
 *        the client then falls back to its built-in template engine.
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

/* --------------------- Semantic Scholar (engine 2) ---------------------- */
async function semanticAuthors(params) {
  const q = String(params.get('search') || '').trim();
  if (!q) return bad('Missing "search" parameter.');
  const fields = 'name,paperCount,citationCount,hIndex,affiliations,papers.title,papers.year,papers.tldr,papers.citationCount,papers.externalIds.DOI';
  const url = `https://api.semanticscholar.org/graph/v1/author/search?query=${encodeURIComponent(q)}` +
              `&limit=5&fields=${encodeURIComponent(fields)}`;
  const headers = {};
  if (process.env.SEMANTIC_SCHOLAR_API_KEY) headers['x-api-key'] = process.env.SEMANTIC_SCHOLAR_API_KEY;
  try {
    const res = await fetch(url, { headers });
    if (!res.ok) return bad(`Semantic Scholar upstream error ${res.status}`, 502);
    return ok(await res.json());
  } catch (e) {
    return bad('Semantic Scholar unreachable.', 502);
  }
}

/* ------------------------- Crossref (engine 3) -------------------------- */
async function crossrefWorks(params) {
  const q = String(params.get('query.author') || params.get('search') || '').trim();
  if (!q) return bad('Missing "query.author" parameter.');
  const usp = new URLSearchParams({
    'query.author': q,
    rows: '8', sort: 'published', order: 'desc',
    filter: 'type:journal-article,from-pub-date:2024-01-01',
    select: 'title,DOI,issued,author,is-referenced-by-count,container-title'
  });
  usp.set('mailto', process.env.OPENALEX_MAILTO || 'letterdesk@users.noreply.github.com');
  try {
    const res = await fetch(`https://api.crossref.org/works?${usp}`);
    if (!res.ok) return bad(`Crossref upstream error ${res.status}`, 502);
    return ok(await res.json());
  } catch (e) {
    return bad('Crossref unreachable.', 502);
  }
}

/* -------------------- Groq / Llama 3 AI draft generation ---------------- */
// Free tier: https://console.groq.com — model llama-3.3-70b-versatile.
// The API key lives ONLY in server env vars; the client sends a prompt and
// receives finished text. On any failure the client falls back to its local
// template engine, so this route can never break the app.
const GROQ_MODEL = 'llama-3.3-70b-versatile';
const CLICHE_LIST = 'delve, delve into, testament, pivotal, profound, I hope this email finds you well, ' +
  'I am writing to express my interest, esteemed, passionate about, harnessing, landscape, ' +
  'furthermore, moreover, additionally, in today\'s world, unlock, elevate, showcase, leverage';

async function groqDraft(req) {
  if (!process.env.GROQ_API_KEY) return bad('not-configured', 404);
  let prompt = '';
  try {
    const body = await req.json();
    prompt = String((body && body.prompt) || '').slice(0, 6000);
  } catch (e) { return bad('Expected a JSON body with a "prompt" string.'); }
  if (prompt.trim().length < 20) return bad('Prompt too short to generate from.');
  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0.6,
        max_tokens: 700,
        messages: [
          { role: 'system', content:
            'You are an admissions-outreach editor for international graduate students applying for funded ' +
            'RA/TA positions. Rewrite the supplied brief as a plain, human email. HARD RULES: under 150 words; ' +
            'no subject line unless asked; never invent credentials, grades, or publications; banned phrases: ' +
            CLICHE_LIST + '. Output only the email text.' },
          { role: 'user', content: prompt }
        ]
      })
    });
    if (!res.ok) return bad(`Groq upstream error ${res.status}`, 502);
    const j = await res.json();
    const text = (((j.choices || [])[0] || {}).message || {}).content || '';
    if (!text.trim()) return bad('Groq returned an empty completion.', 502);
    return ok({ text: text.trim(), model: j.model || GROQ_MODEL, words: text.trim().split(/\s+/).length });
  } catch (e) {
    return bad('Groq request failed.', 502);
  }
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
async function route(params, req) {
  switch (params.get('target')) {
    case 'openalex-authors':  return openalexAuthors(params);
    case 'openalex-works':    return openalexWorks(params);
    case 'semantic-authors':  return semanticAuthors(params);
    case 'crossref-works':    return crossrefWorks(params);
    case 'email-verify':      return emailVerify(params);
    case 'groq-draft':        return groqDraft(req);
    default: return bad('Unknown target. Use openalex-authors | openalex-works | semantic-authors | crossref-works | email-verify | groq-draft.');
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
  const url = new URL(req.url);
  const params = url.searchParams;
  // POST bodies (e.g. groq-draft prompt) are read from the Request itself.
  if (req.method === 'POST' && !params.get('target')) params.set('target', 'groq-draft');
  return toResponse(await route(params, req));
}

// Netlify Functions (CommonJS event format). The block below is only used
// when the file is loaded by Netlify's Node runtime; harmless elsewhere.
try {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports.handler = async (event) => {
      if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: JSON_HEADERS, body: '' };
      const params = new URLSearchParams(event.queryStringParameters || {});
      if (event.httpMethod === 'POST' && !params.get('target')) params.set('target', 'groq-draft');
      // Wrap the Lambda event in a Web-standard Request so shared routes work.
      const fakeReq = {
        json: async () => JSON.parse(event.body || '{}')
      };
      return route(params, fakeReq);
    };
  }
} catch (e) { /* non-CJS environment — ignore */ }
