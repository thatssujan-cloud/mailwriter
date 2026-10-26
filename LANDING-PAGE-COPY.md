# LetterDesk — Landing Page Copy
**Positioning:** Web-based outreach assistant for MSc/PhD applicants seeking geoscience research advisors.
**Voice:** Peer-mentor, not marketer. Precise, evidence-first, zero hype. Every claim below is backed by a shipped feature (live OpenAlex/Semantic Scholar/Crossref search, browser-only drafting, deterministic polish, rule-based pre-send reviewer, MX email checks). No account required to run your first search.

---

## 1. Hero

**Eyebrow:** For MSc & PhD applicants in the Earth sciences

**Title (H1):**
# Find the right geoscience supervisor. Send an email they actually answer.

**Subtitle:**
LetterDesk searches live publication data to surface active researchers in your subfield, drafts a personalized inquiry from facts you can verify, and runs a rule-based check before you hit send — all without creating an account, and with your draft never leaving your browser.

**Primary CTA button:** `Search supervisors free — no account needed` → jumps straight into Step 1
**Secondary link:** `See how it works →` (opens the 3-sentence explainer)

**Trust strip (under CTA):**
✓ No sign-up for your first search · ✓ Works for any country's academic domains (.edu, .ac.uk, .edu.au, .ac.ca…) · ✓ Your drafts are never stored on our servers

---

## 2. Three Key Value Pillars

### Pillar 1 — Live publication search, not a stale directory
**Headline:** Real researchers. Real papers. Queried the moment you search.
Static "find a supervisor" lists go out of date the instant they're published. LetterDesk queries three scholarly engines — **OpenAlex, Semantic Scholar, and Crossref** — restricted to Geology & Earth Sciences authors, then merges and de-duplicates the results into one ranked shortlist. You see who is *publishing now*, what they publish about, and which recent papers give you a genuine hook for your opening line. One search term — "seismology at Cornell" or a professor's name — is all it takes.

### Pillar 2 — Browser-only privacy: your draft is yours alone
**Headline:** Your name, your CV details, your words — they stay in your tab.
Applying to grad school means sharing sensitive things: your name, background, research interests. LetterDesk is deliberately **local-first**. Drafts, edits, and tracker entries are generated and kept entirely in your browser. The only thing that leaves your machine is the search query itself (sent to public scholarly APIs) and, if you choose to verify an address, the university *domain* for a DNS mail-server check. There's no profile to build, no analytics pipeline harvesting your personal statement, and an auto-save kill-switch plus one-click "erase saved data" if you ever want to wipe your traces.

### Pillar 3 — Rule-based verification: no invented facts, ever
**Headline:** A deterministic reviewer — because a hallucinated compliment ends your application.
Generic AI email writers invent paper titles, flatter professors for work they didn't do, and promise enthusiasm they can't source. LetterDesk does the opposite: its **pre-send reviewer is a rules engine, not a language model guessing at truth.** It flags unverifiable claims, checks that every fact in your draft traces back to what you entered or to real publication metadata, scores readiness out of 100, and shows exactly what still needs your confirmation — including a funding-audit card that states plainly: *publication activity does not imply an open funded position.* What you send, you can stand behind.

---

## 3. How It Works — Four Stages

**Section intro:** Supervisor outreach is a process, not a paste-job. LetterDesk walks you through it in four steps — and you can jump between them freely.

### Step 1 · Search — find a lab worth writing to
Type a professor's name, a university, or a topic ("volcanology," "stable isotopes at ETH"). LetterDesk hits OpenAlex, Semantic Scholar and Crossref live, filters to earth-science authors, and returns de-duplicated candidate cards with affiliation, recent publications, and a fit signal. Click a result and Step 2 arrives pre-filled — including a likely email pattern already checked against the university's mail server.

### Step 2 · Details — tell them who you are (to us, locally)
Enter your degree program, term, research focus, tools you actually use (GIS, mass spectrometry, field mapping), and the kind of assistantship you're seeking. These fields feed the drafter — and stay in your browser. Prefer to skip ahead? Everything is optional; you can hand-write in Step 3 too.

### Step 3 · Draft — generate an email built only on real facts
Hit **Generate Email** and get a subject line plus a professional, direct inquiry assembled from your inputs and verified publication metadata — never from invented compliments. Watch the live word-count gauge keep you under the ~150-word ceiling that busy professors actually read. Then press **Polish This Email**: a deterministic readability pass that varies sentence rhythm and strips stock corporate phrasing *without changing a single fact* — with a side-by-side comparison and one-click undo.

### Step 4 · Verify — pass the pre-send review before you risk the reply
The **Smart Pre-Send Reviewer** grades your draft out of 100 and lists what passes and what doesn't. The **Verified Professor Audit Card** consolidates what the publication record supports — and what it doesn't. The **University & Funding Audit Card** records only evidence-backed statuses, never predictions, alongside a checklist you complete as you confirm openings on department pages. Email status turns green only when the domain's MX records show a live mail server — full-address deliverability checks run strictly on your explicit opt-in.

**Micro-copy under the steps:** *Four steps, ten minutes, one email you won't cringe about later.*

---

## 4. FAQ

**Q: Do you store my data or require an account?**
A: No account is needed to search, draft, or verify. LetterDesk is local-first: your name, background text, drafts, and outreach tracker live in your browser, not on our servers. Only two things ever leave your device — your search query (sent to public scholarly APIs like OpenAlex) and, during email verification, the university *domain* (checked against public DNS records). Auto-save covers non-sensitive preferences only, can be disabled with one toggle, and there's an "Erase saved data" button that clears everything instantly.

**Q: How accurate are the supervisor profiles? Where does the data come from?**
A: Profiles are built from live publication metadata — author names, affiliations, and recent papers reported by OpenAlex, Semantic Scholar, and Crossref — so they reflect reality as these registries record it, not a curated list we froze last year. Two honest caveats: affiliation data in publishing metadata occasionally lags a job move, and LetterDesk deliberately **never** claims to know whether a professor has funding or open positions. That's why every result comes with links to verify on the department's own faculty page before you send. We'd rather hand you a correct shortlist than a confident guess.

**Q: How does email verification work — and does my professor's address get sent somewhere?**
A: By default, verification is **domain-only**: we look up the university domain's MX (mail-exchanger) records via Google DNS-over-HTTPS to confirm the school actually receives mail there, then match the address against that institution's standard format. The complete email address is *not* transmitted. If — and only if — you tick "Verify full address" does the address go to a third-party deliverability service (Hunter.io / Abstract API / ZeroBounce) through our rate-limited proxy, and that consent lasts for your current browser tab only. Unverified addresses are always clearly marked; we never present a pattern-guessed address as confirmed.

**Q: Isn't this just another AI email generator?**
A: No — and the difference matters for applications. An LLM option exists for drafting, but the polishing pass is deterministic (it rewrites rhythm and tone, never facts), and the pre-send reviewer is a rules engine that flags anything it cannot trace to your inputs or to real publication data. Generic AI flatters professors with papers they didn't write. LetterDesk can't invent a compliment, because it only writes what it can cite.

**Q: Will LetterDesk get me admitted or guarantee a funded position?**
A: No tool can honestly promise that, so we won't. LetterDesk maximizes your odds by getting the *right* people your actual email — current publishers in your subfield, addressed correctly, with a message that reads as if you did your homework (you did — the search did most of it). Publication activity does not imply an open funded seat; our funding audit card exists precisely to keep you checking those facts yourself before relying on them.

**Q: Which programs and countries does it work for?**
A: Any program where you cold-email a potential advisor — MSc and PhD applications across the US, UK, EU, Australia, Canada and beyond. The email verifier recognizes international academic domains (.edu, .ac.uk, .edu.au, .ac.ca and country variants), and searches cover geoscience authors worldwide.

**Q: Does it work outside geoscience?**
A: LetterDesk is purpose-built for Earth-sciences outreach — the topic filters, templates, and tips are tuned for seismologists, petrologists, hydrologists, geomodelers and their admissions realities. That focus is why the emails come out sounding like a colleague, not a form letter.

---

## 5. Closing Call to Action

**Headline:** Your future advisor published a paper last month. You can mention it by lunchtime.

**Body:** No sign-up. No credit card. No sales funnel disguised as a "free trial." Type one research topic and watch LetterDesk pull live publication data, shortlist the people worth contacting, and draft an email that survives a skeptic's fact-check.

**Button:** `Run your first search — free, no account` → scrolls to Step 1 search box

**Reassurance line:** *Takes 10 seconds. Worst case, you've learned who's publishing in your field today.*

---

## Appendix — Microcopy & Alternate Headlines (A/B options)

| Slot | Option A | Option B |
|---|---|---|
| H1 | Find the right geoscience supervisor. Send an email they actually answer. | Stop emailing blind. Write geoscience advisors who are publishing *right now*. |
| Subtitle | (as above) | Search live publication data, draft a verifiable MSc/PhD inquiry, and check every claim before you send — in your browser, no account. |
| Hero CTA | Search supervisors free — no account needed | Find a Supervisor → |
| Closing CTA | Run your first search — free, no account | Search your field now — no sign-up |

**Privacy badge (header chip):** `Local-first · search queries sent to scholarly APIs`
**Step chips (nav):** Search · find a lab → Details · about you → Draft · write it → Verify · check facts

**Copywriting rationale (for the team):**
- Lead with the outcome (a reply), not the mechanism — mechanism appears in pillars/steps as proof.
- All claims map to shipped features in `index.html` (#profSearch live search, #humanizeBtn deterministic polish, #reviewPanel rule-based reviewer, #fullEmailConsent opt-in, #autoSaveToggle/#eraseSavedBtn storage controls) — nothing promised that the product can't deliver.
- Objections handled in order of visitor anxiety: privacy → accuracy → email safety → "is this just ChatGPT?" → outcome expectations.
- Explicit honesty constraints honored throughout: no predicted admission/funding outcomes, affiliation caveats stated, pattern-guessed addresses never claimed as confirmed.
