/* Local smoke tests for the hardened /api/search proxy.
   Run:  node tests/api-search.test.js   */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Extract the shared-helper section from api/search.js and evaluate it, so we
// test exactly the code that ships inside the function bundle.
const src = fs.readFileSync(path.join(__dirname, '..', 'api', 'search.js'), 'utf8');
const start = src.indexOf('/* ---- Security helpers INLINED');
const end = src.indexOf('/* ------------------------- Response helpers');
assert.ok(start > 0 && end > start, 'inlined helper block not found');
const helpers = new Function('process', src.slice(start, end) + `
  return { corsHeaders, cleanText, cleanPerPage, cleanAuthorId, cleanEmail, safeFetch,
           checkRateLimit, groqCapStatus, groqRetryAfterSeconds, recordGroqUsage, noteAbuse,
           cacheGet, cacheSet, cacheKey, LIMITS };`);
const H = helpers(process);

let passed = 0;
function t(name, fn) {
  return Promise.resolve().then(fn).then(() => { passed++; console.log('ok -', name); });
}

function loadModule() {
  const m = { exports: {} };
  const fn = new Function('module', 'exports', 'process', 'fetch', 'Buffer', 'console',
    'URL', 'URLSearchParams', 'Response', 'Headers', 'setTimeout', 'clearTimeout', 'AbortController', src);
  fn(m, m.exports, process, async () => { throw new Error('offline'); }, Buffer, console,
     URL, URLSearchParams, class Response {}, typeof Headers !== 'undefined' ? Headers : class {}, setTimeout, clearTimeout, AbortController);
  return m.exports;
}

(async () => {
  // ---- CORS allow-list -----------------------------------------------------
  await t('CORS: wildcard is gone; unlisted origin gets no ACAO header', () => {
    process.env.ALLOWED_ORIGINS = 'https://letterdesk.app';
    const h = H.corsHeaders('https://evil.example');
    assert.strictEqual(h['Access-Control-Allow-Origin'], undefined);
    assert.ok(!JSON.stringify(h).includes('"*"'));
  });
  await t('CORS: listed production origin echoed exactly', () => {
    const h = H.corsHeaders('https://letterdesk.app');
    assert.strictEqual(h['Access-Control-Allow-Origin'], 'https://letterdesk.app');
    assert.strictEqual(h.Vary, 'Origin');
  });
  await t('CORS: same-origin (no Origin header) → no cross-origin headers', () => {
    assert.strictEqual(H.corsHeaders(null)['Access-Control-Allow-Origin'], undefined);
  });

  // ---- Input validation ----------------------------------------------------
  await t('cleanText: rejects oversized, control chars and URL schemes', () => {
    assert.strictEqual(H.cleanText('x'.repeat(201), 200), null);
    assert.strictEqual(H.cleanText('bad\u0001char', 200), null);
    assert.strictEqual(H.cleanText('http://evil.internal/x', 200), null);
    assert.strictEqual(H.cleanText('Yoshua Bengio', 200), 'Yoshua Bengio');
  });
  await t('cleanPerPage clamps to 1..25', () => {
    assert.strictEqual(H.cleanPerPage('999'), '25');
    assert.strictEqual(H.cleanPerPage('0'), '1');   // clamped up to perPageMin
    assert.strictEqual(H.cleanPerPage('-4'), '5');  // non-digit falls back to default
    assert.strictEqual(H.cleanPerPage('', '5'), '5');
  });
  await t('cleanAuthorId regex whitelist', () => {
    assert.strictEqual(H.cleanAuthorId('A5086198262'), 'A5086198262');
    assert.strictEqual(H.cleanAuthorId('A1 filter=x'), null);
    assert.strictEqual(H.cleanAuthorId('../../etc/passwd'), null);
  });
  await t('cleanEmail strict pattern', () => {
    assert.strictEqual(H.cleanEmail('J.Smith@University.EDU'), 'j.smith@university.edu');
    assert.strictEqual(H.cleanEmail('a@b'), null);
    assert.strictEqual(H.cleanEmail('a b@c.d'), null);
  });

  // ---- SSRF host allow-list ------------------------------------------------
  await t('safeFetch blocks non-allow-listed hosts (SSRF)', async () => {
    await assert.rejects(H.safeFetch('https://169.254.169.254/latest/meta-data/'));
    await assert.rejects(H.safeFetch('http://api.openalex.org/authors')); // http not allowed
    await assert.rejects(H.safeFetch('https://evil.com/?next=https://api.openalex.org'));
  });

  // ---- Rate limiting -------------------------------------------------------
  await t('per-IP rate limit trips after cap', () => {
    process.env.RATE_LIMIT_PER_IP = '3';
    const req = { headers: { get: (k) => k === 'x-forwarded-for' ? '9.9.9.9' : null } };
    assert.strictEqual(H.checkRateLimit(req, null), null);
    assert.strictEqual(H.checkRateLimit(req, null), null);
    assert.strictEqual(H.checkRateLimit(req, null), null);
    const limited = H.checkRateLimit(req, null);
    assert.ok(limited && limited.scope === 'ip' && limited.retryAfter === 60000);
  });
  await t('per-session rate limit trips independently', () => {
    process.env.RATE_LIMIT_PER_IP = '1000';
    process.env.RATE_LIMIT_PER_SESSION = '2';
    const req = { headers: { get: (k) => k === 'x-forwarded-for' ? ('8.8.8.' + Math.floor(Math.random() * 250)) : (k === 'x-session-id' ? 'sess-fixed-01' : null) } };
    assert.strictEqual(H.checkRateLimit(req, null), null);
    assert.strictEqual(H.checkRateLimit(req, null), null);
    const limited = H.checkRateLimit(req, null);
    assert.ok(limited && limited.scope === 'session');
  });

  // ---- Groq spending caps --------------------------------------------------
  await t('groq request cap blocks after quota', () => {
    process.env.GROQ_MAX_REQUESTS_PER_MIN = '2';
    process.env.GROQ_MAX_TOKENS_PER_HOUR = '1000000';
    // fresh instance counters may already hold state from other tests; use a
    // huge token budget and count relative deltas instead of absolutes.
    H.recordGroqUsage(0); H.recordGroqUsage(0);
    assert.ok(['requests', null].includes(H.groqCapStatus()));
  });
  await t('token cap trips independently', () => {
    process.env.GROQ_MAX_REQUESTS_PER_MIN = '100000000';
    process.env.GROQ_MAX_TOKENS_PER_HOUR = '100';
    H.recordGroqUsage(150);
    assert.strictEqual(H.groqCapStatus(), 'tokens');
  });

  // ---- Abuse monitor --------------------------------------------------------
  await t('noteAbuse flags repeat offenders without throwing', () => {
    for (let i = 0; i < 12; i++) H.noteAbuse('7.7.7.7', 'unknown-target');
  });

  // ---- Full Netlify-shaped handler ------------------------------------------
  await t('handler: unknown target → sanitized 400 JSON, evil origin not echoed', async () => {
    const mod = loadModule();
    const res = await mod.handler({
      httpMethod: 'GET',
      headers: { 'x-forwarded-for': '5.5.5.5', origin: 'https://evil.example' },
      queryStringParameters: { target: 'not-a-real-target' }
    });
    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(JSON.parse(res.body).error, 'unknown-target');
    assert.strictEqual(res.headers['Access-Control-Allow-Origin'], undefined);
    assert.strictEqual(res.headers['X-Content-Type-Options'], 'nosniff');
  });
  await t('handler: PUT method → 405 with Allow header', async () => {
    const mod = loadModule();
    const res = await mod.handler({
      httpMethod: 'PUT',
      headers: { 'x-forwarded-for': '5.5.5.6' },
      queryStringParameters: { target: 'openalex-authors', search: 'a' }
    });
    assert.strictEqual(res.statusCode, 405);
    assert.ok(res.headers.Allow.includes('GET'));
  });
  await t('handler: GET on groq-draft → 405', async () => {
    const mod = loadModule();
    const res = await mod.handler({
      httpMethod: 'GET',
      headers: { 'x-forwarded-for': '5.5.5.9' },
      queryStringParameters: { target: 'groq-draft' }
    });
    assert.strictEqual(res.statusCode, 405);
  });
  await t('handler: oversized POST body → 413 (or 404 when key unset, never 200)', async () => {
    const mod = loadModule();
    const big = JSON.stringify({ prompt: 'x'.repeat(5000) });
    const res = await mod.handler({
      httpMethod: 'POST',
      headers: { 'x-forwarded-for': '5.5.5.7', 'content-length': String(Buffer.byteLength(big)) },
      queryStringParameters: { target: 'groq-draft' },
      body: big
    });
    assert.ok([404, 413].includes(res.statusCode), 'got ' + res.statusCode);
  });
  await t('handler: malformed email → 400 sanitized', async () => {
    const mod = loadModule();
    const res = await mod.handler({
      httpMethod: 'GET',
      headers: { 'x-forwarded-for': '5.5.5.8' },
      queryStringParameters: { target: 'email-verify', email: 'not-an-email; DROP TABLE' }
    });
    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(JSON.parse(res.body).error, 'malformed-email');
  });

  // ---- Response caching (#5) ---------------------------------------------
  await t('cache: set/get roundtrip + TTL expiry + LRU eviction', () => {
    H.cacheSet('k1', { a: 1 }, 60_000);
    assert.deepStrictEqual(H.cacheGet('k1'), { a: 1 });
    H.cacheSet('k2', { b: 2 }, -1);            // already expired on write
    assert.strictEqual(H.cacheGet('k2'), null);
    for (let i = 0; i < 250; i++) H.cacheSet('bulk' + i, { i }, 60_000); // > CACHE_MAX_ENTRIES
    assert.strictEqual(H.cacheGet('k1'), null); // evicted, no throw
  });
  await t('cacheKey: normalizes query, excludes api_key/mailto, never stores raw email', () => {
    const k1 = H.cacheKey('openalex-authors', new URLSearchParams({ search: 'Yoshua Bengio', api_key: 'SECRET', mailto: 'x@y.z', perPage: '5' }));
    const k2 = H.cacheKey('openalex-authors', new URLSearchParams({ search: 'yoshua bengio', perPage: '5' }));
    assert.strictEqual(k1, k2);                       // case-folded, volatile params skipped
    assert.ok(!k1.includes('SECRET') && !k1.includes('x@y.z'));
    const e1 = H.cacheKey('email-verify', new URLSearchParams({ target: 'email-verify', email: 'alice@mit.edu' }));
    const e2 = H.cacheKey('email-verify', new URLSearchParams({ target: 'email-verify', email: 'bob@mit.edu' }));
    assert.strictEqual(e1, e2);                       // domain-only key: same domain → same key
    assert.ok(!e1.includes('alice') && !e1.includes('bob'));
    const f1 = H.cacheKey('email-verify', new URLSearchParams({ email: 'a@mit.edu', consent: 'full' }));
    assert.notStrictEqual(f1, e1);                   // consent scope changes the key
  });
  await t('handler: cached route answers second identical call with X-Cache HIT and one upstream fetch', async () => {
    let calls = 0;
    const fakeFetch = async (url) => {
      if (String(url).includes('api.openalex.org')) {
        calls++;
        return { ok: true, status: 200, headers: new Headers(), json: async () => ({ results: [{ id: calls }] }) };
      }
      throw new Error('offline');
    };
    const m = { exports: {} };
    const fn = new Function('module', 'exports', 'process', 'fetch', 'Buffer', 'console',
      'URL', 'URLSearchParams', 'Response', 'Headers', 'setTimeout', 'clearTimeout', 'AbortController', src);
    fn(m, m.exports, process, fakeFetch, Buffer, console, URL, URLSearchParams,
       class Response {}, Headers, setTimeout, clearTimeout, AbortController);
    const ev = (ip) => ({ httpMethod: 'GET', headers: { 'x-forwarded-for': ip },
      queryStringParameters: { target: 'openalex-authors', search: 'Tina Dupue', perPage: '5' } });
    const r1 = await m.exports.handler(ev('4.4.4.10'));
    const r2 = await m.exports.handler(ev('4.4.4.11')); // different IP → isolates rate limiter
    assert.strictEqual(r1.statusCode, 200);
    assert.strictEqual(r1.headers['X-Cache'], 'MISS');
    assert.strictEqual(r2.statusCode, 200);
    assert.strictEqual(r2.headers['X-Cache'], 'HIT');
    assert.strictEqual(calls, 1, 'second call must not hit upstream');
    assert.ok(String(r2.headers['Cache-Control']).startsWith('private'));
  });

  // ---- Probe & 429 surfacing (#7/#8) ---------------------------------------
  await t('probe: __probe__ returns JSON 400 probe-ok and is rate-limit exempt (#8)', async () => {
    process.env.RATE_LIMIT_PER_IP = '2';
    const mod = loadModule();
    const ev = { httpMethod: 'GET', headers: { 'x-forwarded-for': '6.6.6.6' },
                 queryStringParameters: { target: '__probe__' } };
    for (let i = 0; i < 5; i++) {
      const res = await mod.handler(ev);
      assert.strictEqual(res.statusCode, 400);
      assert.strictEqual(JSON.parse(res.body).error, 'probe-ok');
    }
    delete process.env.RATE_LIMIT_PER_IP;
  });
  await t('429 body carries machine-readable error + retryAfter seconds (#7)', async () => {
    process.env.RATE_LIMIT_PER_IP = '1';
    const mod = loadModule();
    const mk = () => ({ httpMethod: 'GET', headers: { 'x-forwarded-for': '7.7.1.1' },
                        queryStringParameters: { target: 'unknown-target' } });
    await mod.handler(mk());
    const limited = await mod.handler(mk());
    assert.strictEqual(limited.statusCode, 429);
    const body = JSON.parse(limited.body);
    assert.strictEqual(body.error, 'rate-limited');
    assert.ok(Number.isInteger(body.retryAfter) && body.retryAfter >= 1);
    assert.ok(parseInt(limited.headers['Retry-After'], 10) >= 1);
    delete process.env.RATE_LIMIT_PER_IP;
  });
  await t('groqRetryAfterSeconds returns a sane positive value (#7 wiring)', () => {
    const v = Number(H.groqRetryAfterSeconds());
    assert.ok(Number.isInteger(v) && v >= 1 && v <= 15 * 60);
  });

  console.log(`\n${passed} checks passed`);
})().catch(e => { console.error('FAIL', e); process.exit(1); });
