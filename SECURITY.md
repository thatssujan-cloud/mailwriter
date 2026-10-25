# LetterDesk — Security & Deployment Notes (`/api/search` proxy)

This document tracks the hardening of the serverless proxy in `api/search.js`
and the checklist for verifying it is actually deployed and reachable.

## 1. Supported backends — and the GitHub Pages problem

**GitHub Pages cannot run server-side scripts.** On Pages, `api/search.js` is
served as *static text*: a request to `/api/search?...` returns HTTP 200 with
raw JavaScript source, the client's JSON parse silently fails, and every call
quietly fell back to keyless direct fetches (no AI drafts, no email
verification, browser-CORS-limited research). That silent fallback is fixed:

- **Client detection** (`js/backend.js`): a once-per-load probe calls
  `/api/search?target=__probe__`. A real function answers **JSON 400**; static
  hosting answers 200 + JS source → the proxy is marked `absent`, a loud
  `console.warn` explains the situation, and proxy attempts stop until
  re-probed. No more silent degradation.
- **Deployment targets**: `vercel.json` (Node 20 functions, `_shared.js
  excluded from routing) and `netlify.toml` (esbuild function bundling) are
  committed so either platform detects `api/*.js` automatically.

**Verify after deploy:**

```bash
curl -si "https://<your-origin>/api/search" | head -5
# ✅ expect: HTTP/… 400  +  content-type: application/json  +  {"error":"unknown-target"} style body
# ❌ if you see `/**` or `export default` in the body → you are still on a
#    static host (Pages) and the function is NOT executing.
```

## 2. CORS — wildcard removed

`Access-Control-Allow-Origin: *` is gone. The function now echoes an origin
**only** when it exactly matches the `ALLOWED_ORIGINS` env list (comma-
separated production origins). Same-origin requests (no `Origin` header) work;
other cross-origins receive no CORS header and browsers block them. Preflight
(`OPTIONS`) is answered with the allow-listed origin, `GET, POST, OPTIONS`,
`Content-Type` headers, and `Vary: Origin`.

## 3. Rate limiting (per IP and per session)

Fixed-window counters in `api/_shared.js`:

| Env var                  | Default | Scope                                        |
|--------------------------|---------|----------------------------------------------|
| `RATE_LIMIT_PER_IP`      | 30/min  | first hop of `X-Forwarded-For` / client IP   |
| `RATE_LIMIT_PER_SESSION` | 60/min  | `X-Session-Id` header sent by the client     |

The client generates a random per-tab session id (`sessionStorage`, no
personal data) and sends it on every proxy call. Over-limit callers get
`429` + `Retry-After`. Note: serverless instances are short-lived, so this is
a best-effort first line of defense — pair it with platform WAF rules (Vercel Firewall / Netlify) for hard guarantees.

## 4. Groq spending controls

- Global caps enforced **before** any upstream call:
  `GROQ_MAX_REQUESTS_PER_MIN` (default 10) and `GROQ_MAX_TOKENS_PER_HOUR`
  (default 60 000 tokens ≈ spend budget), metered from each response's
  `usage.total_tokens`.
- Tripping a cap returns `429 {"error":"groq-cap"}`; the client then uses its
  local template engine, so UX never breaks and spend can't exceed one window.
- Usage alerts: structured `warn` log events `groq-usage-alert` (80%) and
  `groq-cap-reached` (100%). Also enable **Groq console usage/budget alerts**
  as the upstream source of truth, and route Vercel/Netlify logs to your alert
  channel (e.g., Slack via log drain).

## 5. SSRF / parameter whitelisting

- `target` must be one of: `openalex-authors`, `openalex-works`,
  `semantic-authors`, `crossref-works`, `email-verify`, `groq-draft`. Anything
  else → sanitized `400 unknown-target`. No arbitrary upstream forwarding.
- Every outbound request goes through `safeFetch()`: **https-only**, hostname
  allow-list (`api.openalex.org`, `api.semanticscholar.org`,
  `api.crossref.org`, `hunter.io`, `email-validation.api.abstractapi.com`,
  `api.zerobounce.net`, `dns.google`, `api.groq.com`), `redirect: 'error'`,
  and hard timeouts (9 s lookups / 20 s Groq). Blocked attempts are logged as
  `ssrf-blocked`.
- Inputs validated: search strings ≤ 200 chars with control-char/URL-scheme
  rejection, `perPage` clamped 1–25, `authorId` regex-checked, emails
  strictly pattern-matched, prompts ≤ 6 000 chars.

## 6. Hardened HTTP handling

- Methods: only `GET` (lookups) and `POST` (groq-draft). Others → `405` +
  `Allow` header. `OPTIONS` handled for preflight. GET to `groq-draft` and
  POST to lookup targets are rejected.
- Body-size limit: `Content-Length` checked against 4 KB, then actual byte
  count re-checked after read; oversized → `413 payload-too-large`.
- Invalid JSON → `400 invalid-json`; responses always
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.

## 7. Sanitized errors

Error bodies contain only short machine-readable codes
(`{"error":"upstream-unavailable"}`, `rate-limited`, `groq-cap`, …). Upstream
status lines, payloads, stack traces and environment details go exclusively
to structured server logs.

## 8. API secrets

All keys (`GROQ_API_KEY` etc.) live **only** in hosting environment variables.
A repo-wide scan confirms no key material appears in `index.html` or `js/*`;
the client never reads or sends secrets — it only posts prompts to
`/api/search`. Use `.env.example` for local dev; never commit `.env.local`.
Rotate any key that was ever placed in client code.

## 9. Abuse monitoring

Structured JSON logs on every request plus warn-level events:
`rate-limit`, `ssrf-blocked`, `abuse-pattern` (≥10 rejected requests from one
IP within 15 min → flagged-for-ban), `upstream-error`, `internal-error`,
`groq-usage-alert`, `groq-cap-reached`. Alerting recipe:

- Vercel: Project → Alerts (errors) + log stream → filter `level:"warn"`.
- Netlify: Log drains → Datadog/Papertrail/Sentry; alert on the event names above.
- Optional: feed `abuse-pattern` IPs into a WAF deny rule.

## Quick deploy (Vercel)

```bash
npm i -g vercel
vercel                      # deploys static site + api/search function
vercel env add GROQ_API_KEY production
vercel env add ALLOWED_ORIGINS production   # https://<origin>
vercel --prod
curl -si https://<origin>/api/search | head -5   # must be JSON 400
```
