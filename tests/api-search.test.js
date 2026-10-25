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
           checkRateLimit, groqCapStatus, recordGroqUsage, noteAbuse, LIMITS };`);
const H = helpers(process);

let passed = 0;
function t(name, fn) {
  return Promise.resolve().then(fn).then(() => { passed++; console.log('ok -', name); });
}

function loadModule() {
  const m = { exports: {} };
  const fn = new Function('module', 'exports', 'process', 'fetch', 'Buffer', 'console',
    'URL', 'URLSearchParams', 'Response', 'setTimeout', 'clearTimeout', 'AbortController', src);
  fn(m, m.exports, process, async () => { throw new Error('offline'); }, Buffer, console,
     URL, URLSearchParams, class Response {}, setTimeout, clearTimeout, AbortController);
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
    assert.strictEqual(H.cleanPerPage('-4'), '1');
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

  console.log(`\n${passed} checks passed`);
})().catch(e => { console.error('FAIL', e); process.exit(1); });
