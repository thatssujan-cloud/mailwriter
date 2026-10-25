#!/usr/bin/env node
/**
 * scripts/build-search.js — single-source-of-truth bundler for /api/search.
 *
 * api/_shared.js is the ONLY place the security helpers live. This script
 * inlines it verbatim into api/search.js between the two marker comments,
 * producing a self-contained function file that works on both the Vercel
 * legacy /api router and Netlify Functions without any bundler config.
 *
 *   node scripts/build-search.js         # regenerate api/search.js
 *   node scripts/build-search.js --check # exit 1 if api/search.js is stale
 *
 * `--check` runs in CI (see .github/workflows/ci.yml) so the inlined block
 * can never silently drift from _shared.js again.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SHARED_PATH = path.join(ROOT, 'api', '_shared.js');
const SEARCH_PATH = path.join(ROOT, 'api', 'search.js');

const START_MARK = '/* ---- Security helpers INLINED';
const END_MARK = '/* ------ end of inlined api/_shared.js helpers ------ */';

const NEW_HEADER =
  '/* ---- Security helpers INLINED from api/_shared.js — DO NOT EDIT THIS BLOCK.\n' +
  '      Source of truth: api/_shared.js. Regenerate with:\n' +
  '          node scripts/build-search.js\n' +
  '      CI enforces freshness with: node scripts/build-search.js --check ---- */\n';

function inlineBody() {
  const shared = fs.readFileSync(SHARED_PATH, 'utf8');
  const bodyStart = shared.indexOf('/* ------------------------------ Logging');
  const bodyEnd = shared.lastIndexOf('module.exports = {');
  if (bodyStart < 0 || bodyEnd < bodyStart) {
    throw new Error('_shared.js markers not found — update scripts/build-search.js');
  }
  return shared.slice(bodyStart, bodyEnd).trimEnd();
}

function build() {
  const src = fs.readFileSync(SEARCH_PATH, 'utf8');
  const start = src.indexOf(START_MARK);
  const end = src.indexOf(END_MARK, start);
  if (start < 0 || end <= start) {
    throw new Error('api/search.js is missing the INLINED helper markers/sentinel');
  }
  const rebuilt =
    src.slice(0, start) +
    NEW_HEADER +
    inlineBody() + '\n' + END_MARK +
    src.slice(end + END_MARK.length);
  return { src, rebuilt };
}

const check = process.argv.includes('--check');
const { src, rebuilt } = build();

if (check) {
  if (rebuilt !== src) {
    console.error('STALE: api/search.js does not match api/_shared.js.\n' +
                  'Run: node scripts/build-search.js && commit the result.');
    process.exit(1);
  }
  console.log('ok - api/search.js is in sync with api/_shared.js');
} else {
  fs.writeFileSync(SEARCH_PATH, rebuilt);
  console.log('built api/search.js from api/_shared.js (' +
              Buffer.byteLength(rebuilt, 'utf8') + ' bytes)');
}
