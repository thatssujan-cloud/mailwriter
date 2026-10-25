# LetterDesk — Third-Party Asset Inventory (§6 Supply Chain)

Last reviewed: 2026-10-25. Every external asset the portal loads, its pinning
status, integrity coverage, and where it is referenced.

| # | Asset | Version / Pin | Loaded by | SRI | Notes |
|---|-------|---------------|-----------|-----|-------|
| 1 | Tailwind CSS (Play CDN) | `https://cdn.tailwindcss.com` — **unpinned mutable build** | `index.html` `<head>` script | ❌ not possible (bytes change over time; a static hash would break the site) | Mitigated instead by CSP `script-src` allow-list + `crossorigin`. **Owner action:** for production, replace with a locally-built, versioned `tailwind.css` (static utility build) so no CDN JS runs at all. |
| 2 | DOMPurify | `dompurify@3.2.4` (jsDelivr, immutable artifact) | Dynamically injected in `index.html` (`loadDomPurify`) | ✅ `sha384-eEu5CTj3qGvu9PdJuS+YlkNi7d2XxQROAFYOr59zgObtlcux1ae1Il3u7jvdCSWu` | Fail-safe: on hash mismatch or offline, the built-in `fallbackSanitize()` stays active — sanitization never silently disappears. |
| 3 | Google Fonts (Inter, JetBrains Mono) | Query-pinned (`wght@400..800`, css2 API) | `index.html` stylesheet link | n/a (CSS only) | CSP restricts to `fonts.googleapis.com` / `fonts.gstatic.com`. Font failure degrades to system fonts — cosmetic only. |
| 4 | OpenAlex API | `https://api.openalex.org` v1 (no version in URL; upstream-stable) | client `fetchWithRetry` + server proxy `safeFetch` host allow-list | n/a (JSON data, never markup) | Responses treated as untrusted: escaped via `escapeHtml`/`setSafeHtml`; SSRF host whitelist enforced server-side. |
| 5 | Semantic Scholar API | `https://api.semanticscholar.org/graph/v1` | same as #4 | n/a | Same untrusted-data handling. |
| 6 | Crossref API | `https://api.crossref.org/works` | same as #4 | n/a | Same untrusted-data handling. |
| 7 | Google DNS-over-HTTPS | `https://dns.google/resolve` | MX/domain lookup path | n/a | Domain-only lookups unless explicit full-address consent (§4). |
| 8 | Groq API | `https://api.groq.com/openai/v1` — model pinned in `api/search.js` env default | **server-side only** (`api/search.js`) | n/a | Key lives exclusively in `GROQ_API_KEY` deployment env var; spending caps + usage alerts in `api/_shared.js`. Never referenced from any client file. |
| 9 | Hunter.io / Abstract API / ZeroBounce | email-verification upstreams | **server-side only**, behind `?consent=full` gate (§4 opt-in) | n/a | Keys in env vars; full addresses sent only after explicit user consent. |
| 10 | Local scripts | `js/backend-config.js`, `js/backend.js`, `js/app.js` | `index.html` | same-origin (`'self'` in CSP) | No raw `innerHTML`, `eval`, `document.write`, or `insertAdjacentHTML` sinks remain (verified by `tests/final-verify` checks). |

## Pinning & rotation policy
- jsDelivr artifacts are addressed by **exact major.minor.patch** (never `@3` or `latest`).
- Any dependency bump requires: re-download artifact → recompute `sha384` → update
  `integrity` attribute here and in `index.html` → run `node tests/api-search.test.js`.
- Secret scan of repo **and full git history** performed 2026-10-25
  (`gsk_*`, `sk-*`, `ghp_*` patterns): **0 findings**; nothing to rotate. Re-run before every release.
- Serverless runtime deps: none — `api/search.js` + `api/_shared.js` use only Node/Web standard
  built-ins (`crypto`, `fetch`), so there is no npm supply chain on the backend.
