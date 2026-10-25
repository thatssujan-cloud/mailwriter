/* ==========================================================================
   LetterDesk — js/app.js
   UX enhancement layer: sticky navigation, scroll progress, reveal
   animations, back-to-top button, keyboard shortcuts (with a "?" help
   modal), focus management and graceful form auto-save.

   This file is ADDITIVE — it never overrides the core generator logic that
   lives inline in index.html. All hooks degrade safely if an element is
   missing, so the page keeps working even when loaded partially.
   ========================================================================== */
(function () {
  'use strict';

  var doc = document;
  function $(id) { return doc.getElementById(id); }
  function on(el, evt, fn, opts) { if (el) el.addEventListener(evt, fn, opts || false); }

  /* §2 Sink audit: no raw innerHTML anywhere in this file. All markup below
     is static template literals (no user data interpolated), but it is still
     routed through the page's DOMPurify-backed safe sink when available
     (window.ldSafeSetHtml, defined by index.html). If this script ever runs
     standalone without the core page, we fall back to a local sanitizer that
     strips every tag — fail-safe, never fail-open. */
  function safeHtml(el, html) {
    if (!el) return;
    if (typeof window.ldSafeSetHtml === 'function') { window.ldSafeSetHtml(el, html); return; }
    el.textContent = String(html == null ? '' : html)
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/<\/?[a-zA-Z][^>]*>/g, '');   // strip markup, keep text
  }
  var prefersReducedMotion = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ------------------------------------------------------------------
     1. Skip link — instant keyboard access to the generator
  ------------------------------------------------------------------ */
  function buildSkipLink() {
    if ($('ldSkipLink')) return;
    var a = doc.createElement('a');
    a.id = 'ldSkipLink';
    a.href = '#generator';
    a.textContent = 'Skip to generator';
    doc.body.insertBefore(a, doc.body.firstChild);
    on(a, 'click', function () {
      var first = $('studentName');
      if (first) setTimeout(function () { first.focus({ preventScroll: true }); }, 300);
    });
  }

  /* ------------------------------------------------------------------
     2. Sticky compact nav + scroll-progress bar
        Appears once the user scrolls past the hero masthead.
  ------------------------------------------------------------------ */
  function buildStickyNav() {
    if ($('ldStickyNav')) return;

    var nav = doc.createElement('nav');
    nav.id = 'ldStickyNav';
    nav.setAttribute('aria-label', 'Quick navigation');
    safeHtml(nav,
      '<span class="ld-brand"><span class="ld-brand-dot" aria-hidden="true"></span>LetterDesk</span>' +
      '<a class="ld-nav-link" href="#generator" data-ld-scroll>Generator</a>' +
      '<button type="button" class="ld-nav-link" data-ld-action="tips">Contact Tips</button>' +
      '<button type="button" class="ld-nav-link" data-ld-action="humanize">Humanize</button>' +
      '<button type="button" data-ld-action="copy" title="Copy email body">Copy</button>' +
      '<button type="button" data-ld-action="help" title="Keyboard shortcuts (?)">?</button>');

    var bar = doc.createElement('div');
    bar.id = 'ldScrollProgress';
    bar.setAttribute('aria-hidden', 'true');

    doc.body.appendChild(nav);
    doc.body.appendChild(bar);

    var header = doc.querySelector('header');
    var backToTop = null; // created below; guarded reference

    function updateOnScroll() {
      var y = window.scrollY || doc.documentElement.scrollTop || 0;
      var trigger = header ? Math.max(120, header.offsetHeight - 80) : 300;
      nav.classList.toggle('ld-visible', y > trigger);
      var h = doc.documentElement.scrollHeight - window.innerHeight;
      bar.style.width = (h > 0 ? Math.min(100, (y / h) * 100) : 0) + '%';
      if (!backToTop) backToTop = $('ldBackToTop');
      if (backToTop) backToTop.classList.toggle('ld-visible', y > 500);
    }
    window.addEventListener('scroll', updateOnScroll, { passive: true });
    window.addEventListener('resize', updateOnScroll);
    updateOnScroll();

    /* Nav actions route to the same elements the page already wires up */
    on(nav, 'click', function (e) {
      var link = e.target.closest('a[data-ld-scroll]');
      if (link) {
        e.preventDefault();
        var target = $(link.getAttribute('href').slice(1));
        if (target) target.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth' });
        return;
      }
      var btn = e.target.closest('button[data-ld-action]');
      if (!btn) return;
      switch (btn.getAttribute('data-ld-action')) {
        case 'tips': {
          var tipsToggle = $('tipsToggle'), tipsPanel = $('tipsPanel');
          if (tipsToggle && tipsPanel) {
            tipsPanel.classList.add('open');
            tipsToggle.setAttribute('aria-expanded', 'true');
            tipsToggle.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth', block: 'center' });
          }
          break;
        }
        case 'humanize': {
          var hb = $('humanizeBtn');
          if (hb) { hb.click(); hb.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
          break;
        }
        case 'copy': {
          var cb = $('copyBodyBtn');
          if (cb) cb.click();
          break;
        }
        case 'help': openHelp(true); break;
      }
    });
  }

  /* ------------------------------------------------------------------
     3. Back-to-top button
  ------------------------------------------------------------------ */
  function buildBackToTop() {
    if ($('ldBackToTop')) return;
    var b = doc.createElement('button');
    b.id = 'ldBackToTop';
    b.type = 'button';
    b.setAttribute('aria-label', 'Back to top');
    b.title = 'Back to top';
    safeHtml(b,
      '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none"' +
      ' stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M12 19V5"/><path d="m5 12 7-7 7 7"/></svg>');
    doc.body.appendChild(b);
    on(b, 'click', function () {
      window.scrollTo({ top: 0, behavior: prefersReducedMotion ? 'auto' : 'smooth' });
      var logo = doc.querySelector('header a[aria-label]');
      if (logo) logo.focus({ preventScroll: true });
    });
  }

  /* ------------------------------------------------------------------
     4. Scroll-reveal for cards & sections (IntersectionObserver)
  ------------------------------------------------------------------ */
  function buildReveals() {
    if (!('IntersectionObserver' in window) || prefersReducedMotion) return;
    var targets = doc.querySelectorAll('main section > div, #tipsPanel > div');
    Array.prototype.forEach.call(targets, function (el) { el.classList.add('ld-reveal'); });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          en.target.classList.add('ld-in');
          io.unobserve(en.target);
        }
      });
    }, { rootMargin: '0px 0px -40px 0px', threshold: 0.05 });
    Array.prototype.forEach.call(targets, function (el) { io.observe(el); });
  }

  /* ------------------------------------------------------------------
     5. Keyboard shortcuts + help modal
        G  → generate email      H  → humanize
        C  → copy body           M  → mailto handoff
        R  → reset form          /  → focus professor search
        ?  → toggle this help    Esc → close help / search results
     (Shortcuts are ignored while typing in inputs/textareas.)
  ------------------------------------------------------------------ */
  var HELP_ROWS = [
    ['G', 'Generate the email draft'],
    ['H', 'Run the Humanizer on the draft'],
    ['C', 'Copy the email body to clipboard'],
    ['M', 'Open the mailto: send-to-outlook handoff'],
    ['R', 'Reset the form to defaults'],
    ['/', 'Jump to the professor search box'],
    ['?', 'Show / hide this shortcut list'],
    ['Esc', 'Close overlays']
  ];

  function buildHelpModal() {
    if ($('ldShortcutHelp')) return;
    var wrap = doc.createElement('div');
    wrap.id = 'ldShortcutHelp';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('aria-label', 'Keyboard shortcuts');
    var rows = HELP_ROWS.map(function (r) {
      return '<li class="flex items-center justify-between gap-4 py-1.5 border-b border-slate-100 last:border-0">' +
             '<span class="text-sm text-slate-600">' + r[1] + '</span><span class="kbd">' + r[0] + '</span></li>';
    }).join('');
    safeHtml(wrap,
      '<div class="ld-modal">' +
      '<div class="flex items-center justify-between mb-3">' +
      '<h3 style="font-weight:800;font-size:1.05rem;">Keyboard shortcuts</h3>' +
      '<button type="button" id="ldHelpClose" aria-label="Close" style="cursor:pointer;border:none;background:#f1f5f9;border-radius:.5rem;width:2rem;height:2rem;font-weight:700;">✕</button>' +
      '</div><ul style="list-style:none;padding:0;margin:0;">' + rows + '</ul>' +
      '<p style="margin:.9rem 0 0;font-size:.72rem;color:#64748b;">Tip: press <span class="kbd">?</span> anywhere to toggle this panel.</p>' +
      '</div>');
    doc.body.appendChild(wrap);
    on(wrap, 'click', function (e) {
      if (e.target === wrap || e.target.id === 'ldHelpClose') openHelp(false);
    });
  }

  function openHelp(show) {
    buildHelpModal();
    var m = $('ldShortcutHelp');
    if (!m) return;
    m.classList.toggle('ld-open', !!show);
    if (show) {
      var c = $('ldHelpClose');
      if (c) c.focus();
    }
  }

  function bindShortcuts() {
    doc.addEventListener('keydown', function (e) {
      var t = e.target;
      var typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' ||
                         t.tagName === 'SELECT' || t.isContentEditable);

      // §5 Resilience / PC usability: never hijack keys while a modifier is
      // held (Ctrl+C copy, Ctrl+G browser search, Cmd shortcuts, etc.) —
      // except Escape and the help toggle, which are safe to intercept.
      if ((e.ctrlKey || e.metaKey || e.altKey) && e.key !== 'Escape' && e.key !== '?') return;
      // Never fire single-letter shortcuts inside form fields or while the
      // Zoom cheat-sheet modal is open (prevents accidental re-generation).
      if (typing) return;
      var zoomModal = $('zoomModal');
      if (zoomModal && !zoomModal.classList.contains('hidden')) return;

      if (e.key === 'Escape') {
        openHelp(false);
        var sr = $('searchResults');
        if (sr) sr.classList.add('hidden');
        return;
      }
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return; // legacy guard kept for safety

      var map = {
        g: 'assistantForm',       // submit via requestSubmit → uses existing handler
        h: 'humanizeBtn',
        c: 'copyBodyBtn',
        m: 'mailtoBtn',
        r: 'resetBtn'
      };
      var key = e.key.toLowerCase();

      if (key === '?' || (e.shiftKey && key === '/')) { e.preventDefault(); openHelp(true); return; }
      if (key === '/') {
        var ps = $('profSearch');
        if (ps) { e.preventDefault(); ps.focus(); ps.select(); }
        return;
      }
      var id = map[key];
      if (!id) return;
      e.preventDefault();
      if (key === 'g') {
        var form = $('assistantForm');
        if (form) {
          if (typeof form.requestSubmit === 'function') form.requestSubmit();
          else form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        }
        return;
      }
      var btn = $(id);
      if (btn && !btn.disabled) btn.click();
    });
  }

  /* ------------------------------------------------------------------
     6. Auto-save the form (localStorage) so returning users keep context

     §4 Privacy — Minimize LocalStorage Usage: sensitive personal details
     (student name, academic background, research interests/focus, tool
     skills, professor name AND professor email) are NEVER persisted to
     localStorage any more; they can be read back by whoever uses this
     browser next. Only low-sensitivity UI preferences are saved. Full
     persistence is further gated behind the "Disable auto-save" toggle
     in index.html (window.ldAutoSaveDisabled()), and everything stored
     can be wiped with the "Erase saved data" button.
  ------------------------------------------------------------------ */
  var STORE_KEY = 'letterdesk-form-v1';
  // PII fields that must never touch localStorage (§4 remediation).
  var SENSITIVE_FIELDS = ['studentName', 'background', 'profName',
                          'researchFocus', 'toolSkill', 'profEmail'];
  // Only non-sensitive UI preferences remain persisted.
  var SAVE_FIELDS = ['degreeMajor', 'termYear', 'assistType', 'emailFormat', 'tone'];

  // P1-2 null safeguards: every element lookup is checked before any
  // property is read or written, so a hidden/not-yet-rendered field can
  // never throw "Cannot set properties of null" and kill the script.
  function restoreForm() {
    // §4 Privacy: honour the "Disable auto-save" toggle — when persistence
    // is off we neither read nor write localStorage on this page.
    if (typeof window.ldAutoSaveDisabled === 'function' && window.ldAutoSaveDisabled()) return;
    try {
      var raw = localStorage.getItem(STORE_KEY);
      if (!raw) return;
      var saved = JSON.parse(raw);
      if (!saved || typeof saved !== 'object') return;
      // One-time scrub: older builds persisted PII under this key. Drop any
      // sensitive values so they stop lingering in storage on shared devices.
      var scrubbed = false;
      SENSITIVE_FIELDS.forEach(function (id) {
        if (Object.prototype.hasOwnProperty.call(saved, id)) {
          delete saved[id];
          scrubbed = true;
        }
      });
      if (scrubbed) {
        try { localStorage.setItem(STORE_KEY, JSON.stringify(saved)); } catch (e) {}
      }
      SAVE_FIELDS.forEach(function (id) {
        var el = $(id);
        if (el && typeof el.value === 'string' &&
            typeof saved[id] === 'string' && !el.value.trim()) {
          el.value = saved[id];
        }
      });
    } catch (err) { /* storage unavailable or corrupt — ignore */ }
  }

  // P1-2 / P2-4 safeguards: every DOM read is null-guarded (an element that
  // is hidden or not yet rendered must never throw "Cannot read properties
  // of null" and kill the rest of the script), and setItem is wrapped so a
  // QuotaExceededError (private mode, full storage) degrades gracefully
  // instead of breaking subsequent execution.
  function saveFormDebounced() {
    // §4 Privacy: "Disable auto-save" toggle — no writes when persistence is off.
    if (typeof window.ldAutoSaveDisabled === 'function' && window.ldAutoSaveDisabled()) return;
    clearTimeout(saveFormDebounced._t);
    saveFormDebounced._t = setTimeout(function () {
      var data = {};
      SAVE_FIELDS.forEach(function (id) {
        var el = $(id);
        if (el && typeof el.value === 'string') data[id] = el.value;
      });
      safeSetItem(STORE_KEY, JSON.stringify(data), 'Could not auto-save your form — browser storage is full or unavailable.');
    }, 400);
  }

  // Shared guarded localStorage writer (used by auto-save here; the core
  // tracker/checklist writers in index.html carry equivalent try/catch).
  // §4 Privacy: single choke-point that honours the "Disable auto-save"
  // toggle so NO page script persists data while persistence is off.
  function safeSetItem(key, value, warnMsg) {
    if (typeof window.ldAutoSaveDisabled === 'function' && window.ldAutoSaveDisabled()) {
      return false; // auto-save disabled by the user — skip silently
    }
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (err) {
      var quota = err && (err.name === 'QuotaExceededError' ||
                          err.code === 22 || err.code === 1014);
      try {
        console.warn('localStorage write failed (' + key + '):', err);
      } catch (e) { /* no console — ignore */ }
      if (quota && doc.getElementById('trackModePanel')) {
        // Storage is running low: nudge the user to export their CSV backup
        // before more saves fail (P2 remediation guidance).
        notify(warnMsg + ' Export your tracker CSV and remove stale entries to free space.', 'error');
      } else {
        notify(warnMsg, 'error');
      }
      return false;
    }
  }

  // Fire the page's toast system when present, otherwise log quietly.
  function notify(msg, variant) {
    if (typeof window.showToast === 'function') {
      try { window.showToast(msg, variant || 'info'); return; } catch (e) {}
    }
    try { console.info('[LetterDesk]', msg); } catch (e) {}
  }

  function bindAutoSave() {
    var form = $('assistantForm');
    if (!form) return;
    restoreForm();
    on(form, 'input', saveFormDebounced);
    on(form, 'change', saveFormDebounced);
    on($('resetBtn'), 'click', function () {
      try { localStorage.removeItem(STORE_KEY); } catch (err) {}
    });
  }

  /* ------------------------------------------------------------------
     7. Small touches: enter-to-search hint & button busy spinner
  ------------------------------------------------------------------ */
  function polishButtons() {
    // Show a spinner inside the generate button while it's disabled/loading.
    var gen = $('generateBtn');
    if (!gen) return;
    var mo = new MutationObserver(function () {
      var busy = gen.disabled;
      var sp = gen.querySelector('.ld-spinner');
      if (busy && !sp) {
        var s = doc.createElement('span');
        s.className = 'ld-spinner';
        s.setAttribute('aria-hidden', 'true');
        gen.insertBefore(s, gen.firstChild);
        gen.appendChild(doc.createTextNode(' '));
      } else if (!busy && sp) {
        sp.remove();
        if (gen.firstChild && gen.firstChild.nodeType === 3 && !gen.firstChild.textContent.trim()) {
          gen.firstChild.remove();
        }
      }
    });
    mo.observe(gen, { attributes: true, attributeFilter: ['disabled'] });
  }

  /* ------------------------------------------------------------------
     8. Write-flow step navigation — adapted from the proposed switchStep
        snippet so it matches this page's real markup:
          • Steps are toggled with .ld-step / .is-active (opacity +
            visibility), NOT display/hidden classes — the inline styles in
            the original snippet clash with Tailwind `hidden` utilities and
            would break dropdowns like #searchResults.
          • Nav items are the [data-goto-step] chips inside
            ol[aria-label='Write flow steps']; the arrow <li>s carry no chip
            and must be skipped, so index mapping is derived from
            data-goto-step instead of forEach position.
          • The tracker is #trackModePanel (a sibling mode panel toggled via
            the `hidden` attribute by the core script); it is only shown for
            a dedicated "tracker" request, never as an extra write step.
  ------------------------------------------------------------------ */
  var WRITE_STEPS = ['stepSearch', 'stepDetails', 'stepDraft', 'stepVerify'];

  // Expose a global switchStep(stepIndex) contract (0 = Search … 3 = Verify,
  // 4 = tracker view) so other scripts/tests can drive the flow directly.
  window.switchStep = function switchStep(stepIndex) {
    if (stepIndex === 4) { showTrackerView(); return; }
    var targetId = WRITE_STEPS[stepIndex];
    if (!targetId) return;

    // Show exactly one step section (class-based — never touch style.display)
    doc.querySelectorAll('.ld-step').forEach(function (sec) {
      sec.classList.toggle('is-active', sec.id === targetId);
    });

    // Sync the active state of the step chips in the indicator bar
    doc.querySelectorAll('#stepIndicator [data-goto-step]').forEach(function (chip) {
      chip.classList.toggle('is-active', Number(chip.dataset.gotoStep) === stepIndex + 1);
    });

    // Keep the Write mode visible; leave Track mode to its own toggle
    var writePanel = $('writeModePanel');
    if (writePanel) writePanel.hidden = false;
    var trackPanel = $('trackModePanel');
    if (trackPanel) trackPanel.hidden = true;

    var main = doc.querySelector('main');
    if (main) main.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth' });
  };

  // Explicitly jump to the tracker view (index 4 / Track tab button)
  function showTrackerView() {
    doc.querySelectorAll('.ld-step').forEach(function (sec) {
      sec.classList.remove('is-active');
    });
    var writePanel = $('writeModePanel');
    if (writePanel) writePanel.hidden = true;
    var trackPanel = $('trackModePanel');
    if (trackPanel) trackPanel.hidden = false;
    var main = doc.querySelector('main');
    if (main) main.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth' });
  }

  function bindStepNav() {
    // Step chips: map through data-goto-step (1-based) → array index (0-based).
    // Arrow <li>s in the ordered list carry no chip and are skipped naturally.
    doc.querySelectorAll('#stepIndicator [data-goto-step]').forEach(function (chip) {
      chip.style.cursor = 'pointer';
      chip.addEventListener('click', function (e) {
        e.preventDefault();
        window.switchStep(Number(chip.dataset.gotoStep) - 1);
      });
    });

    // Mode tabs: Write returns to Step 1, Track reveals the tracker panel
    on($('modeWriteBtn'), 'click', function () { window.switchStep(0); });
    on($('modeTrackBtn'), 'click', showTrackerView);

    // Inline transition links ("← Back to draft", "Edit details", …).
    // Only plain href="#" anchors are scanned so real deep links stay intact.
    // Order matters: check verify/pre-send before draft before details.
    var linkTargets = [
      { re: /verify|pre-?send/i,   idx: 3 },
      { re: /\bdraft\b/i,          idx: 2 },
      { re: /\bdetails\b|manual/i, idx: 1 }
    ];
    doc.querySelectorAll("a[href='#']").forEach(function (link) {
      var text = (link.innerText || link.textContent || '').toLowerCase();
      for (var i = 0; i < linkTargets.length; i++) {
        if (linkTargets[i].re.test(text)) {
          (function (idx) {
            link.addEventListener('click', function (e) {
              e.preventDefault();
              window.switchStep(idx);
            });
          })(linkTargets[i].idx);
          break;
        }
      }
    });
  }


  /* ------------------------------------------------------------------
     Init
  ------------------------------------------------------------------ */
  function init() {
    buildSkipLink();
    buildStickyNav();
    buildBackToTop();
    buildReveals();
    buildHelpModal();
    bindShortcuts();
    bindAutoSave();
    bindStepNav();
    polishButtons();
  }

  if (doc.readyState === 'loading') {
    doc.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
