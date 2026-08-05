# TODO

Working checklist. See [PLAN.md](PLAN.md) for rationale and [README.md](README.md) for setup.

**Where this stands:** 243 tests pass with no API key. The security controls, mock
client, and controller loop are built and tested. **Nothing has ever called the real
Claude API** — the tool schemas, `strict: true` mode, and the mid-conversation system
message are all built from documentation, not from an observed response. That is the
single largest unknown in the project.

Suggested order: **API key → `--demo` → fix what breaks → 30 questions → expand eval →
platform reconciliation.** The first three are about an hour and will tell you more
about the project's real state than anything else here.

---

## 1. Blocked on you — nobody else can do these

- [ ] Write the **30+ example questions** (PLAN.md §9 day 1). This is the spec;
      everything downstream derives from it. Categories: active alarms · alarm details ·
      events · logs · device status · summaries · follow-ups · unsupported.
- [ ] Confirm the **target platform** — Genetec, Milestone, Nedap, a SIEM, in-house?
      Ask MTC now; this has a long lead time and blocks §4.
- [ ] Obtain the **API documentation**: endpoints, auth, query params, response
      envelope, pagination, rate limits, error codes.
- [ ] Confirm which fields are **sensitive in their schema**, and get sign-off on the
      data flow before any real data is used.
- [ ] Decide **who the users are** — console operators? managers? Drives tone, default
      verbosity, and which of the five functions matters most.

## 2. Needs an API key — the entire LLM path is unverified

- [ ] Add `ANTHROPIC_API_KEY` to `.env`
- [ ] `python scripts/ask.py --demo` — the first real call. Expect breakage.
- [ ] Verify **`strict: true` tool schemas are accepted**. Generated from Pydantic and
      never sent to the API. Most likely thing to fail.
- [ ] Verify the **mid-conversation `role: "system"` message** works on
      `claude-opus-5`. If rejected, fall back to a `<system-reminder>` block inside the
      user turn (`chatbot/controller.py`, `process_message`).
- [ ] Verify **follow-up context** across turns: "which one is newest?" → "show that
      device"
- [ ] Verify the **read-only refusal** fires on "restart it" and does not fabricate
      success
- [ ] Confirm **prompt caching** is hitting — `usage.cache_read_input_tokens` should be
      non-zero from turn 2 onward
- [ ] Check `effort: "low"` is right for routing; try `medium` if routing is sloppy
- [ ] Record baseline **cost and latency** per turn

## 3. Evaluation

- [ ] Expand `tests/evaluation_cases.json` from **34 → 50+** using the question list
- [ ] Run `RUN_LIVE_EVAL=1 python -m pytest tests/test_evaluation.py`
- [ ] Fix routing failures — change the prompt only against **measured** failures
- [ ] Verify the **injection cases**: poisoned records must not provoke extra tool calls
      or echo `SECURITY_API_TOKEN`
- [ ] Record a **baseline pass rate**, so later prompt edits are measurable rather than
      vibes

## 4. Real API integration

- [ ] **Reconcile `security_client/api_client.py`** against the vendor's actual docs —
      paths, parameter names, response shape. Currently written against an assumed
      contract and marked UNVERIFIED in the module docstring.
- [ ] Fix `_unpack()` — it assumes `{"alarms": [...], "total": N}`. If the platform
      returns no total, decide there what to do rather than silently reporting the page
      size as the total (which would break truncation disclosure).
- [ ] Handle **real pagination** if the API pages
- [ ] Obtain a **read-only service account** — the account itself should lack write
      permission, not merely the client
- [ ] Test against a **staging instance** before anything production
- [ ] **Regenerate fixtures** to match the real schema once known
      (`python scripts/generate_fixtures.py`)
- [ ] Exercise the **error taxonomy** for real: 401, 403, 404, timeout, malformed
      response, rate limit

## 5. Gaps worth closing before calling it done

- [ ] **No auth on the UI.** Anyone who can reach the Streamlit port gets full read
      access to security data. Acceptable for a local PoC; must be stated explicitly if
      it is ever demoed on a network.
- [ ] **`api_client.py` has no tests** — every other module does. Needs
      `httpx.MockTransport` coverage for: path allowlist, GET-only, limit capping, 404 →
      `None`.
- [ ] **No rate limiting** — nothing stops a user looping and burning tokens
- [ ] **The audit log records the resulting call, not the question.** Deliberate (the
      question may contain PII), but make it a conscious, documented decision rather
      than an oversight.
- [ ] **No conversation length cap** — long sessions grow context until something
      breaks. Add a turn limit or enable compaction.

## 6. Documentation and handover

- [ ] Have someone who is not you follow the README setup from scratch
- [ ] Write up what **phase 2 requires**: authentication, per-user permissions, explicit
      confirmation, and an audit trail tied to a real identity
- [ ] Put the known limitations somewhere the reviewer will actually see them
- [ ] Rehearse the demo end to end

---

## Done

- [x] `SecurityClient` Protocol + `QueryResult` with truncation disclosure
- [x] Pydantic discriminated union, `extra="forbid"`, tool schemas generated from the
      models so they cannot drift
- [x] Action allowlist, field sanitization (allowlist not blocklist), result caps
      enforced in two independent layers
- [x] Seeded fixture generator — 100 alarms, 309 events, 801 logs, 30 devices, plus
      planted demo records, an auth-failure burst, and prompt-injection payloads
- [x] `MockSecurityClient`
- [x] Tool-use controller loop with a per-turn tool-call budget
- [x] System prompt + untrusted-data delimiter
- [x] `TimeWindow` enum resolution (the model has no clock)
- [x] Structured audit logging with secret redaction
- [x] Streamlit UI with evidence expanders and a status sidebar
- [x] `scripts/ask.py` CLI harness — one-shot, interactive, `--demo`, `--dry-run`
- [x] `RealSecurityApiClient` skeleton — GET-only, allowlisted paths (**unverified**)
- [x] 243 tests: schemas, mock client, security rules, controller, audit, eval structure
- [x] Evaluation harness + 34 seed cases across all seven categories
- [x] Configuration errors distinguished from retrieval failures

## Out of scope for v1

Acknowledge or close alarms · assign incidents · run device health checks · generate
reports · documentation RAG.

All gated on authentication, per-user permissions, explicit confirmation, and an audit
trail that ties an action to a real identity — none of which exist yet. `user_id` is
stubbed as `local-dev` on purpose rather than invented.
