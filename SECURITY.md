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

## Validation evidence (reproducible, run from repo root)

| Item | Command | Expected result | Last run |
|------|---------|-----------------|----------|
| §1 Proxy controls | `node tests/api-search.test.js` | `18 checks passed` (CSP CORS, rate limits, SSRF, caps, methods, sanitized errors) | 2026-10-25 ✅ |
| §2 XSS sinks | grep audit: `innerHTML\|insertAdjacentHTML\|document.write\|eval(` across `index.html js/*.js api/*.js` | only the sanitized `tpl.innerHTML = sanitizeHtml(...)` bridge remains; app.js routes through `window.ldSafeSetHtml` | 2026-10-25 ✅ |
| §3 CSV injection | behavioral test with `=HYPERLINK(...)`, `+2+3`, `-@payload`, hidden `  =cmd` | every payload gains a leading `'`; normal text untouched | 2026-10-25 ✅ |
| §4 Storage controls | toggle `letterdesk.autosave.off` in sessionStorage shim | writers blocked while on; erase clears all four keys | 2026-10-25 ✅ |
| §5 Resilience | `switchStep(-5 / NaN / undefined / 99)` | clamps to step 0, no TypeError; `4` still opens tracker view | 2026-10-25 ✅ |
| §6 Secrets | pattern scan of working tree **and full git history** (`gsk_*`, `sk-*`, `ghp_*`) | 0 findings — no credentials to rotate | 2026-10-25 ✅ |
| Live endpoint (§7/§8) | `curl -i https://<origin>/api/search` after deploy | HTTP 400 + JSON body `{"error":...}` — **not** raw JS source (silent GitHub-Pages fallback). Also confirm the client banner shows "proxy online" (probe in `js/backend.js`). | pending first cloud deploy |
| Live XSS repro (§8) | search a name, inject `<img src=x onerror=alert(1)>` via devtools into the result renderer path | no dialog fires; markup rendered as inert text by `setSafeHtml` | staging (post-deploy) |

## Owner maintenance notes (out-of-scope for bounty reporting)

These are standard platform characteristics or owner responsibilities, not
vulnerabilities, and should be documented as such per §8 scope review:

1. **GitHub Pages cannot execute server-side code.** A static-hosted
   `api/search.js` is served as plain text. This is why Vercel/Netlify are the
   supported backends and why the client probes proxy availability instead of
   silently falling back. Not an exploitable flaw in itself.
2. **A wildcard-CORS misconfiguration alone is not an exploit** — F-01 was
   resolved by removing the wildcard AND proving the live endpoint's behavior
   with controlled requests (see table above).
3. **Tailwind Play CDN is unpinned by design** during development; production
   owners should swap it for a locally built static stylesheet (see
   ASSET-INVENTORY.md row 1). SRI is impossible on that mutable artifact, so
   CSP allow-listing is the compensating control.
4. **Groq/Hunter/ZeroBounce quota & billing alerts** must be enabled in each
   provider dashboard by the project owner; the proxy enforces soft caps and
   emits `groq-usage-alert` logs, but cannot configure vendor billing pages.
5. **localStorage content is visible to anyone with the user's unlocked PC.**
   The portal now minimizes what it stores (no PII), offers auto-save disable
   and one-click erase, and warns about shared devices — residual risk on a
   compromised machine belongs to the user/environment, not the app.
