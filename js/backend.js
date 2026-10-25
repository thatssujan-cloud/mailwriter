/* ==========================================================================
   LetterDesk — js/backend.js
   Serverless proxy configuration and the central fetch wrapper used by the
   research engines in js/core.js. Loads before core.js (classic script).
   ========================================================================== */
/* ==================================================================
   SERVERLESS PROXY CONFIG (Vercel / Netlify) — see api/search.js
   ------------------------------------------------------------------
   This page works with zero setup: OpenAlex is queried directly and
   needs no API key. Paid verification services (Hunter.io, Abstract,
   ZeroBounce) DO require keys that must never ship in client code.
   Deploy this folder to Vercel or Netlify and the /api/search proxy
   function picks up your environment variables server-side:

     Vercel:   vercel env add OPENALEX_API_KEY / HUNTER_API_KEY ...
     Netlify:  Site settings → Environment variables

   Set USE_SERVER_PROXY = true once deployed; until then the site
   stays fully functional against keyless OpenAlex + local checks.
================================================================== */
const BACKEND = {
  USE_SERVER_PROXY: (location.protocol === 'https:' && location.hostname !== '' && !/^(localhost|127\.0\.0\.1)$/.test(location.hostname)),
  get proxyUrl() { return '/api/search'; }
};

// Central fetch wrapper: routes through the serverless proxy when it's
// available (keys stay server-side), falls back to direct keyless calls.
async function dataFetch(target, params) {
  const qs = new URLSearchParams(params).toString();
  if (BACKEND.USE_SERVER_PROXY) {
    try {
      const r = await fetch(`${BACKEND.proxyUrl}?target=${encodeURIComponent(target)}&${qs}`);
      if (r.ok) {
        const json = await r.json();
        if (json && (json.results || json.status || json.success !== undefined)) return json;
      }
    } catch (e) { /* proxy unavailable — fall through to direct call */ }
  }
  return null; // caller performs its own direct fetch
}
