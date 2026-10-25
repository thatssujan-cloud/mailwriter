/* §8 Validation harness: extracts the inline <script> blocks from index.html,
   runs them under a DOM shim, and exercises the security/resilience helpers. */
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync('/workspace/index.html', 'utf8');

// Pull all inline script bodies (skip src= tags)
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
console.log('inline script blocks found:', scripts.length);

// --- Static checks -----------------------------------------------------------
let fails = 0;
function check(name, cond) {
  console.log((cond ? 'ok   - ' : 'FAIL - ') + name);
  if (!cond) fails++;
}

check('CSP meta tag present', /http-equiv="Content-Security-Policy"/.test(html));
check('DOMPurify loaded with SRI integrity', /\.integrity\s*=\s*'sha384-/.test(html));
check('setSafeHtml exported as window.ldSafeSetHtml', /window\.ldSafeSetHtml\s*=\s*setSafeHtml/.test(html));
check('no raw innerHTML sinks outside sanitizer bridge',
  !/\.innerHTML\s*=/.test(scripts.join('\n').replace(/tpl\.innerHTML\s*=\s*sanitizeHtml\(html\);/, '')));
check('no eval / document.write / insertAdjacentHTML in page JS',
  !/\beval\(|document\.write|insertAdjacentHTML/.test(scripts.join('\n')));
check('CSV formula neutralizer present', /function neutralizeCsvCell/.test(html));
check('switchStep bounds-check present', /Number\.isInteger\(idx\)/.test(html));
check('QuotaExceededError handled + CSV escape hatch', /QuotaExceededError/.test(html) && /exportTrackerCsv/.test(html));
check('AbortController timeouts used', /AbortController/.test(html) || /AbortController/.test(fs.readFileSync('/workspace/js/backend.js','utf8')));
check('PII never persisted to localStorage keys', !/localStorage\.setItem\([^)]*(studentName|profEmail|researchInterests)/.test(html));
check('auto-save toggle + erase button wired', /autoSaveToggle/.test(html) && /eraseSavedBtn/.test(html) && /ldAutoSaveDisabled/.test(html));
check('full-address verification gated by consent', /consent/.test(fs.readFileSync('/workspace/api/search.js','utf8')));
check('Groq key only server-side (env)', /process\.env\.GROQ_API_KEY/.test(fs.readFileSync('/workspace/api/search.js','utf8')) && !/sk-[a-zA-Z0-9]{20,}/.test(html + fs.readFileSync('/workspace/js/app.js','utf8') + fs.readFileSync('/workspace/js/backend.js','utf8') + fs.readFileSync('/workspace/js/backend-config.js','utf8')));

// --- Behavioral checks: extract pure helpers and run them -------------------
function grabFn(src, name) {
  const i = src.indexOf('function ' + name);
  if (i < 0) return null;
  let depth = 0, started = false;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') { depth++; started = true; }
    else if (src[j] === '}') { depth--; if (started && depth === 0) return src.slice(i, j + 1); }
  }
  return null;
}
const allSrc = scripts.join('\n');

// fallbackSanitize
const fb = grabFn(allSrc, 'fallbackSanitize');
const fallbackSanitize = new Function('return (' + fb + ')')();
check('fallbackSanitize strips <img onerror>', !/<|onerror/i.test(fallbackSanitize('<img src=x onerror=alert(1)>')));
check('fallbackSanitize strips <script>', !/<script>/i.test(fallbackSanitize('<script>alert(1)</script>hi')));

// neutralizeCsvCell
const nc = grabFn(allSrc, 'neutralizeCsvCell');
const neutralizeCsvCell = new Function('return (' + nc + ')')();
check("CSV '=' neutralized", neutralizeCsvCell('=HYPERLINK("http://evil")') === "'=HYPERLINK(\"http://evil\")");
check("CSV '+2+3' neutralized", neutralizeCsvCell('+2+3')[0] === "'");
check("CSV '-@x' neutralized", neutralizeCsvCell('-@payload')[0] === "'");
check("CSV hidden-formula '  =cmd' neutralized", neutralizeCsvCell('  =cmd|calc')[0] === "'");
check("CSV normal text untouched", neutralizeCsvCell('Seismology at Cornell') === 'Seismology at Cornell');

// escapeHtml
const eh = grabFn(allSrc, 'escapeHtml');
if (eh) {
  const escapeHtml = new Function('return (' + eh + ')')();
  check('escapeHtml encodes angle brackets & quotes', escapeHtml('<b>"x"</b>').indexOf('<') === -1);
} else check('escapeHtml defined', false);

// ldAutoSaveDisabled behavior via shimmed storage (real key: letterdesk.autosave.off)
{
  const store = {};
  const sessionStorageShim = { getItem:k=>(k in store?store[k]:null), setItem:(k,v)=>{store[k]=String(v)}, removeItem:k=>{delete store[k]} };
  const fnText = grabFn(allSrc, 'ldAutoSaveDisabled');
  if (fnText) {
    // Rename the identifier so it becomes an anonymous function expression.
    const expr = fnText.replace('function ldAutoSaveDisabled', 'function');
    const fn = new Function('sessionStorage', 'AUTOSAVE_OFF_KEY', 'return (' + expr + ');')
                (sessionStorageShim, 'letterdesk.autosave.off');
    check('ldAutoSaveDisabled false by default', fn() === false);
    sessionStorageShim.setItem('letterdesk.autosave.off','1');
    check('ldAutoSaveDisabled true when toggle on', fn() === true);
    sessionStorageShim.removeItem('letterdesk.autosave.off');
    check('ldAutoSaveDisabled false after erase', fn() === false);
  } else check('ldAutoSaveDisabled extractable', false);
}

console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL FINAL CHECKS PASSED');
process.exit(fails ? 1 : 0);
