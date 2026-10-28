# NeuroShell IRE — Frontend Design Specification

**Product:** NeuroShell IRE — Intent Recognition Engine (Component 01 of the NeuroShell autonomous penetration-testing framework)
**Purpose of this doc:** Complete, build-ready design for the IRE operator console UI.
**Scope:** Web application consumed by human operators (analyst / operator / admin) to author, parse, validate, review and observe NLU security commands, plus the escalation review queue and pipeline telemetry.
**Status:** Greenfield — no existing frontend (grep-verified: zero `.html` files in the service).
**Base:** FastAPI backend at `src/api/main.py`, schema v2 in `src/schemas/intent_schema.py`, config surfaces in `config/{settings,features,enforcement_policy,rbac_policy}`.

---

## 1. Product Context & Goals

IRE converts natural-language offensive-security commands ("stealth ICMP discover 192.168.1.0/24") into validated, schema-constrained JSON contracts consumed by downstream Components (Dynamic Planner / Exploit Orchestrator). The frontend is the **command channel, the safety surface, and the observability cockpit** for that pipeline.

### 1.1 Goals
1. **Command authoring with structured feedback** — turn a free-text command into an inspectable, explainable intent contract.
2. **Safety transparency** — show *why* something was blocked or warned: which validator fired, which rule, with severity. The pipeline's whole value is "provably safe structured output"; the UI must make that proof legible.
3. **Human-in-the-loop operations** — the escalation queue (`/parse/plan` → 202 `pending_review`) needs an approval workstation.
4. **Pipeline observability** — health, model status, cache state, latency, entropy, per-intent distribution.
5. **Role-aware surfaces** — the UI must respect caller role semantics (viewer / analyst / operator / admin) end-to-end.

### 1.2 Operational reality the design must accommodate (measured)
- **Latency is long:** full-pipeline p50 ≈ 16 s, p95 ≈ 70 s on CPU-only ultrabook hardware (`eval/Data Collection/results/exp3_comparison.md`). Requests can reach the 60 s Ollama timeout.
- **Cache is the fast path:** cache-hit p50 ≈ 44 ms (semantic-cache cross-tab, canonical checkpoint). A large share of repeat commands should feel near-instant.
- **Contracts matter more than text:** the UI's core artifact is the JSON contract (v2 response / PlannerContract), not the chat bubble.
- **Feature flags gate behaviour:** XAI, uncertainty estimation, etc. are disabled; surfaces for them must degrade gracefully at runtime from `/admin/features`.

### 1.3 Non-goals (v1)
- No job/execution tracking — IRE only *parses*, it does not run scans (that is Component 02). Do not imply execution status.
- No multi-user auth UI — role is a per-request header/field, not an identity system.
- No mobile-first build — primary target is a desktop workstation; responsive *fallback* only.

---

## 2. Personas & Roles

| Persona | Role | Needs | Can see |
|---|---|---|---|
| **Security Operator** (primary) | operator | Author complex commands, inspect contracts & CVE/tool hints, resolve warnings, multi-turn sessions | Console, sessions, contracts, warnings |
| **Pentest Analyst** | analyst | Passive recon & scanning only; read-only intent exploration | Console with policy-limited intents, telemetry |
| **Engagement Lead / Admin** (secondary) | admin | Approve escalated contracts, audit findings, scope & policy config, feature flags | Everything incl. Review Queue, Audit, Policy, Settings |
| **Viewer / Auditor** (rare) | viewer | Observe only; **no operations**. Pre-inference blocked by RBAC poll | Read-only console (intent cards), telemetry |

UI implications:
- A **role switcher** sits in the top bar (part of the request, driver of RBAC behaviour) — it is *lab*, not identity. Real deployments wire it to SSO/token.
- When the switch produces `INTENT_ACCESS_DENIED`, the response card renders the RBAC denial prominently with "what this role can do" (from `GET /admin/rbac/{role}`).
- `viewer` role should show the console in a "recon-only / disabled composer" mode *before* round-trip (client feature knowledge).

---

## 3. Design Principles

1. **The contract is the artifact.** Every screen that touches a parse result is built around a *contract card*: intent → target → parameters → validation trail. Raw JSON is one click away, never the default.
2. **Safety before speed in presentation.** Blocked outcomes render with dominant, unambiguous danger styling; warnings are loud but not alarmist; success is calm. Error taxonomy (§8 of `research-extraction.md`) gets a permanent legend colour.
3. **Show the pipeline, don't hide it.** A per-request validation timeline (M1→S7) makes the "why" visible: which stage produced each finding, with severity chip.
4. **Assume long waits, design for 44 ms.** Distinguish cache-hit (instant) from inference (progressed). Always allow "background it" — the contract result lands in a History side panel.
5. **Explorable, shallow UI.** Every taxonomy value (intent, target type, hallucination class, error code, stage) is a navigable element with a definition tooltip (data from the static taxonomy map).
6. **Keyboard-first where it matters.** Operator is a terminal-native persona: composer autofocus, Ctrl+Enter to parse, `/` to focus composer, numbers for history items.
7. **Everything is copyable / inspectable.** Any contract card has "Copy JSON", "Open in planner", "View raw response" actions. Operators pipe these into other tooling.

---

## 4. API Contract Summary (the data model the UI consumes)

### 4.1 Endpoints & auth
| Method/Path | Auth | Purpose |
|---|---|---|
| `GET /health`, `GET /` | none | readiness banner |
| `POST /parse` | `X-API-Key` | parse command → v1/v2 response |
| `POST /parse/plan` | `X-API-Key` | parse → PlannerContract; may return 202 escalation or 422 |
| `GET /metrics` | key | pipeline metrics snapshot |
| `GET /session/{id}` / `DELETE /session/{id}` | key | session info / clear |
| `GET /admin/rbac/{role}` | key | role permission summary |
| `GET /admin/features`, `POST /admin/features/reload` | key | feature flags (+reload) |
| `GET /admin/enforcement-policy` | key | policy map + reasoning |
| `GET /admin/escalations?status=pending` | key | review queue |
| `POST /admin/escalations/{id}/resolve` | key | approve/reject + note |
| `GET /admin/audit/summary` | key | aggregate findings |
| `GET /engagement/scope` | key | current scope config |

Headers the UI sets: `X-API-Key`, `X-IRE-Schema-Version: 2` (always 2 in v1 UI; keep v1 for power users via a toggle).

### 4.2 `POST /parse` v2 response (superset used by Console)
| Field | Type | UI treatment |
|---|---|---|
| `status` | `success │ error` | card banner colour |
| `intent` | IntentType | headline chip + definition tooltip |
| `target` | `{type, value}` | monospace value + type badge |
| `ports`, `modifiers`, `cve_ids` | lists | chip groups; CVEs link out |
| `tool_hint`, `schedule` | string/null | hint row |
| `confidence` | float | gauge; <0.5 → amber, <0.7 → warning on planner |
| `rejection_reason` | string | reason block when REJECTED |
| `scope_warnings` | string[] | warning list with `SCOPE_WARNING` / `ARCH_WARNING` tags |
| `latency_ms` | int | time chip |
| `error/stage/field/detail` | (error only) | error panel per §4.5 |
| `sub_intent` | string | sub-category chip (e.g. `NETWORK_SCAN.SYN_STEALTH`) |
| `uncertainty_band` | low/med/high | entropy meter |
| `raw_entropy`, `tier_triggered`, `resolution_method` | — | "How it decided" debug line |
| `cache_hit` | exact/semantic/none | latency chip prefix (⚡ exact / ≈ semantic) |
| `rbac_role`, `session_turns` | — | context line |
| `validation_findings` | ValidationFinding[] | **the validation trail** (§4.4) |
| `schema_version` | 2 | — |

Response headers also carry `X-IRE-Latency-Ms`, `X-IRE-Intent`, `X-IRE-Cache-Hit` (useful for the request inspector).

### 4.3 `POST /parse/plan` responses
- **200** → `PlannerContract` (intent, sub_intent, target, ports, modifiers, cve_ids, tool_hint, schedule, confidence, rejection_reason, scope_warnings, session_id). The "Planner Preview" tab.
- **202** → `{status:"pending_review", escalation_id, message, hallucination_class, detail}` → switches Console into *Escalation submitted* state with "Open Review Queue" action.
- **422** → `CONTRACT_VALIDATION_FAILED` → contract-pane error state.
- API errors (400/401/413/429/503/500) → global toast/panel mappings (§6.5).

### 4.4 `ValidationFinding` trail (the safety story)
```json
{ "validator": "network_validator", "passed": true,
  "hallucination_class": "OUT_OF_SCOPE_TARGET",
  "detail": "Target 8.8.8.8 outside engagement scope",
  "severity": "block" }        // block | warn (escalate rarely)
```
Rendered as a **rail** — each validator name (M1…S7) shows ✓ / ✗ chip + severity tint; hover/click reveals detail + hallucination-class tag + policy reasoning.

### 4.5 Error taxonomy colour map (permanent legend)
| Code | Source | UI colour |
|---|---|---|
| `ADVERSARIAL_INPUT_BLOCKED` | adversarial_detector | destructive-red |
| `INTENT_ACCESS_DENIED` | rbac_guard | destructive-red |
| `INPUT_VALIDATION_FAILED` | input_normalizer | warning-amber |
| `INFERENCE_FAILED` | inference | neutral-red |
| `JSON_PARSE_FAILED` | json_parser | warning-amber |
| `SCHEMA_VALIDATION_FAILED` | schema_validator | destructive-red |
| `REGEX_VALIDATION_FAILED` | regex_validator | destructive-red |
| `NETWORK_ARCHITECTURE_VIOLATION` | network_validator | destructive-red |
| `SCOPE_VIOLATION` | scope_guard | destructive-red |
| `CONTRACT_VALIDATION_FAILED` | contract_validator (422) | destructive-red |
| `RATE_LIMIT_EXCEEDED` | slowapi (429) | warning-amber |
| HTTP 400/401/413/503/500 | api guards | neutral / warning |

### 4.6 Supporting payloads
- **Health:** `status, ollama, model, pipeline_stages, middleware{...}, session_store{active_sessions,max_sessions,...}, semantic_cache{entries,max_size,threshold,feature_enabled,model_loaded,total_hits}, inference_cache_size`
- **Metrics:** `total_requests, success_count, error_counts, intent_distribution, cache_hits{exact,semantic,miss}, latency_p50/p95/p99, average_semantic_entropy, max_semantic_entropy, tier_counts, uptime_seconds`
- **Scope:** `engagement_name, engagement_scope, engagement_mode, scope_mode, max_cidr_prefix, min_cidr_prefix, description`
- **Policy summary:** `scope_mode, engagement_mode, policy{CLASS→block|warn}, reasoning{CLASS→string}`
- **Escalation record:** `id, timestamp, session_id, raw_input_hash, intent_summary, hallucination_class, severity, enforcement_action, status, cached_contract_json`
- **Session info:** `session_id, turn_count, last_target, age_seconds`
- **Role summary:** `role, permitted_intents[...], restricted[...]`

---

## 5. Information Architecture & Navigation

### 5.1 Primary navigation (left rail)
```
┌────────────────────────────┐
│  ◈  NeuroShell IRE         │   logo + service
├────────────────────────────┤
│  ◧ CONSOLE                 │   /app            (primary)
│  ◫ SESSIONS                │   /app/sessions
│  ⚠ REVIEW QUEUE  [n]       │   /app/review     (admin badge count)
│  📊 TELEMETRY              │   /app/telemetry
│  🧬 VALIDATION AUDIT       │   /app/audit      (admin)
│  ▤ POLICY & RBAC           │   /app/policy     (admin)
│  ⚙ SETTINGS               │   /app/settings   (admin)
├────────────────────────────┤
│  ● healthy · gemma…e       │   health footer: status, model, live p50
└────────────────────────────┘
```
- **Role-aware nav:** viewer/analyst hide Review Queue, Audit, Policy, Settings. Composer disabled for viewer with policy hint.
- **Badge:** pending escalation count polled every 10 s while on any page.

### 5.2 Page inventory (v1)
| # | Page | Route | Auth tier |
|---|---|---|---|
| 1 | Console (composer + result) | `/app` | analyst+ (viewer read-only) |
| 2 | Sessions (history + multi-turn) | `/app/sessions` | analyst+ |
| 3 | Review Queue (escalations) | `/app/review` | admin |
| 4 | Telemetry (metrics dashboards) | `/app/telemetry` | analyst+ |
| 5 | Validation Audit (audit summary) | `/app/audit` | admin |
| 6 | Policy & RBAC explorer | `/app/policy` | admin |
| 7 | Settings (scope + features + connection) | `/app/settings` | admin |

---

## 6. Screen Designs

### 6.1 Global chrome
- **Top bar (per role/brand):** workspace name (engagement_name from `/engagement/scope`), role switcher (viewer/analyst/operator/admin), schema-version toggle (v1/v2) for power users, connection pill (health: healthy/degraded/unavailable from `/health`).
- **Status footer (left rail):** `● model ·n replies · latency p50` — refreshes health every 15 s; the only always-on polling (cheap, unauthenticated).

### 6.2 Console (primary screen)

**Layout:**
```
┌─────────────┴──────────────────────────────────────────────┐
│  Command Console                       role: operator ▾   │
├──────────────────────────────────────────────────────────────┤
│  Session: op-001 ▾  (turn 4/8)          [New session] [⚙]   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  "stealth ICMP discovery scan of 192.168.1.0/24        │ │  ← composer
│  │  then SMB enum against the DC for EternalBlue"         │ │  (autosuggest aliases)
│  │  [Parse ⏎]  [Parse → Planner]  [Clear]  2000 chars     │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌ IN-FLIGHT / RESULT PANEL ────────────────────────────┐  │
│  │ Contract Card                                        │  │
│  │   NETWORK_SCAN ✓   SCAN.SYN_STEALTH   subnet         │  │
│  │   192.168.1.0/24   ports: —  mods: stealth           │  │
│  │   [Detail] [Planner] [Copy JSON] [Raw]  ⚡cache 44ms │  │
│  │ Validation rail: M1✓ M2✓ M3✓ M4⚡ M5✓ … S7 ✓        │  │
│  └──────────────────────────────────────────────────────┘  │
├─────────────────────────┬──────────────────────────────────┤
│ HISTORY (this session)  │  RECENT (all sessions)           │
│  t4  NETWORK_SCAN       │  42s ▸ VULN AUDIT 10.0.0.5       │
│  t3  REJECTED            │  8m  ⚡ EXPLOITATION …           │
└─────────────────────────┴──────────────────────────────────┘
```

**States:**
1. **Idle** — composer focus; placeholder chips of example commands; char counter hits 2000 → warning + block.
2. **In-flight (parse)** — result panel shows animated stage pipeline (M1→S7) with live "current stage" line; elapsed timer; **cancel** (AbortController); because p95 is 70 s, show "long inference" hint at 30 s + option to keep waiting (auto-poll not needed; one fetch with `timeout: 90_000`).
3. **In-flight (planner)** — same plus ContractBuilder step; readiness is identical, so reuse.
4. **Cache hit** — result arrives near-instantly; show ⚡ exact / ≈ semantic chip instead of stage animation (no inference happened; stage rail shows M4 short-circuit).
5. **Success** — contract card (§6.3).
6. **Success-with-warnings** — card header shows amber "2 warnings" chip; warnings surface inline in the rail; a non-blocking callout lists `scope_warnings`.
7. **Blocked (error)** — full-width destructive panel: error code (big), stage, detail, `validation_findings` trail, "+ why (policy reasoning)" disclosure.
8. **Escalated (202)** — amber card "Contract withheld for human review" + escalation_id + [Open Review Queue] button.
9. **Empty / no-fire** — no parse performed: show taxonomy explorer alias lookup shortcut.

**Composer affordances:**
- Alias autocomplete from the static alias map (EternalBlue→CVE-2017-0144 etc.) — data-driven hint list.
- `role` selector tied to request; typed command trips client-side RBAC early-warning (e.g. exploitation keywords under `analyst` → amber "likely to be denied").

### 6.3 Contract Card (the core component, reused everywhere)

```
┌ NETWORK_SCAN ──────────────── ✓ approved ─────────┐
│ sub: SCAN.SYN_STEALTH        confidence  0.97 ⦿   │
│ target  SUBNET 192.168.1.0/24                     │
│ ports   —            cve    —                    │
│ mods    stealth      tool   nmap                  │
│ schedule —           session op-001 (t4)          │
│ ─ Validation rail ──────────────────────────────── │
│   M1✓ M2✓ M3✓ M4⚡ M5✓ S1✓ S2✓ S3✓ S4✓ S5✓ S6✓   │
│   S6B✓ S7✓   (● = warn · ✗ = block)              │
│ ── [Expand details] [Planner preview] [Copy] [Raw]│
└───────────────────────────────────────────────────┘
```
- **Seed panel:** everything below the headline is the "planner view" (exact PlannerContract fields). Confidence renders as a 0–1 gauge with threshold ticks at 0.5 / 0.7 (the schema's own heuristic thresholds).
- **Warning/blocked variants:** amber border + warning list / red border + error block.

### 6.4 Sessions

- **List:** session_id, turn_count, last target, age, TTL countdown (from `session_max_turns: 8`, `session_ttl_minutes: 30`).
- **Thread view:** replay turns as compact contract cards (+ raw command text as the "bubble" the card replaces), newest last; the composer remains active with the selected session_id.
- **Actions:** `DELETE /session/{id}` with confirm; "New session" mints a fresh id client-side (`crypto.randomUUID()`).

### 6.5 Review Queue (admin escalation workstation)

```
┌ Pending escalations (2) ──────────────────────────────┐
│ #12  14:03  EXPLOITATION on 192.168.1.5   FABRICATED_CVE
│      hash 2fd9… | contract cached | session op-001   │
│      [view contract] [Approve ▾] [Reject ▾ note…]    │
│ #11  13:58  PASSWORD_ATTACK …           CONTRADICTORY_ACTION_TARGET
└───────────────────────────────────────────────────────┘
```
- Polls `GET /admin/escalations?status=pending` every 10 s; badge updates globally.
- **Approve flow:** expand cached contract → read-only contract card → confirm (note optional) → `POST /admin/escalations/{id}/resolve {approve:true}` → success toast + the released contract becomes available to copy (API returns it).
- **Reject flow:** reason textbox (required by policy taste; API accepts empty) → resolve with `approve:false` → status "rejected".
- **Honesty constraint:** the record shows only `raw_input_hash` (privacy guarantee); UI labels it "input hashed — not stored (privacy)".

### 6.6 Telemetry

Layout = live snapshot header + chart grid.

**Header (from `/metrics`, refresh 10 s):**
```
tot 1,284 │ ok 1,102 │ block 87 │ warn 68 │ ⚡cache 114 │ p50 16.2s │ p95 68.9s │ uptime 3d4h
```
**Charts (client-calculated from metrics snapshot + cached samples):**
1. **Latency distribution:** p50/p95/p99 line over time (sample deltas each poll) — dual scale: ms + "inference vs cache" split (cache hits can't be derived per-request from `/metrics`; v1 shows the top-line split of `cache_hits` donut instead, flagged as global).
2. **Intent distribution** — horizontal bars, colour-coded per intent.
3. **Error counts by stage** — bar; click → error legend (§4.5).
4. **Cache hits hole** — donut exact/semantic/miss with threshold readout (`0.82`, `512 max`).
5. **Entropy** — rolling band strip low/med/high where entropy records exist; show "XAI / uncertainty flags off" tag when `/admin/features` says so.
6. **Tier counts** — T1 vs T2 resample ratio.

Empty states: zero requests → "Collect data by parsing commands" CTA. Data existing but flat (all zeros) and flags disabled → hint box quoting the exact feature flag that gates richer data.

### 6.7 Validation Audit (admin)

- Bar: total records + pending count over time (audit summary has no time-series; v1 charts the *current* `by_hallucination_class` and `by_enforcement_action` from `GET /admin/audit/summary`).
- Table of class counts with a one-line "what this means" (from policy reasoning).
- Callout: audit stores SHA-256 hashes, not raw input (privacy).

### 6.8 Policy & RBAC explorer (admin)

- **Enforcement policy table:** class × severity × reasoning, editable *view only* (editing is a config-file task; show "edit in config/enforcement_policy.py" hint) — re-renders on `reload` via `/admin/features/reload` button.
- **Scope card:** `engagement_name`, `engagement_scope`, `scope_mode`, `engagement_mode`, `max/min_cidr_prefix`, with the generated description string.
- **RBAC matrix:** role × intent grid (from rbac policy static map), highlight `RESTRICTED_ROLES=viewer` and `SENSITIVE_INTENTS`. Role summary lookup per row via `GET /admin/rbac/{role}`.

### 6.9 Settings (admin)

- **Connection:** base URL + API key entry (stored client-side), "Test connection" → `/health`, model readout.
- **Scope preview:** CIDR math visualisation (draw target vs scope on a simple IP grid only for SUBNET/IP targets) — a *read* view; writes are config-file operations flagged as such.
- **Feature flags:** read-only list from `/admin/features` with state badges + one "Reload" button (`POST /admin/features/reload`) + a security reminder that changes are process-wide.
- **Developer pane:** API key visibility toggle, raw response harness (build a request, see headers+body), OpenAPI link `/docs`.

---

## 7. Component Inventory (reusable)

| Component | Responsibility | Used by |
|---|---|---|
| `AppShell` | rail, topbar, health footer, route guard (role) | all |
| `RoleSwitcher` | request role selector, per-role capability hints | topbar |
| `CommandComposer` | textarea, alias autosuggest, char counter, quick-examples | Console |
| `AsyncParseButton` | fires /parse or /parse/plan with AbortController, 90 s timeout | Console |
| `PipeLineRail` | animated stage progress M1…S7 + static terminal rail | Console, ContractCard |
| `ContractCard` | the artifact (§6.3) with severity variants | Console, Sessions, Review, Planner |
| `PlannerChevron` | toggle to PlannerContract preview tab | Console card |
| `ValidationFindingChip` | validator ✓/✗/● with tooltip+reasoning | rail |
| `ConfidenceGauge` | 0–1 with threshold ticks | card |
| `ChipGroup` | ports/modifiers/cve/tool chips; CVE external links | card |
| `ErrorPanel` | taxonomy-mapped error rendering + findings trail | Console, Planner |
| `EscalationCard` / `ResolutionDialog` | queue item + approve/reject | Review |
| `SessionList` / `SessionThread` | session mgmt | Sessions |
| `MetricsHeader` / `ChartGrid` | telemetry snapshot + charts | Telemetry |
| `PolicyTable` / `RbacMatrix` / `ScopeCard` | config explorer | Policy |
| `StatusPill` | health projection | health footer |
| `ToastStack` | transient outcomes (auth, rate-limit, resolve) | global |
| `ContractInspector` | raw JSON + headers + response code viewer | debug pane everywhere |
| `TaxonomyLegend` | error/intent/class definitions & colours | inline collapsible |

---

## 8. Design System

### 8.1 Theme — "mission console" (dark-first)
Sole theme in v1 (telemetry is light-hostile); light theme out of scope. High contrast, low glare, read-forward.

### 8.2 Colour tokens (semantic, not raw)
```
bg/base        #0A0E14   page
bg/panel       #101722   cards, rails
bg/elevated    #171F2C   popovers, dialogs
border/hair    #1F2A3A   separators
text/primary   #E6EDF3
text/second    #8B98A9
status/success #2EA043   clean parse, healthy
status/ok      #3FB950   (de-emphasised success)
status/warn    #D29922   warnings, escalation, low confidence
status/block   #F85149   blocks, fatal, rate limit
status/info    #58A6FF   info, cache, neutral
intent colours 8-class hue map (NETWORK_SCAN=#58A6FF, EXPLOITATION=#F85149, PASSIVE_RECON=#3FB950, …) — documented in the static taxonomy map, applied to chips & charts consistently.
severity tint  block=1px solid #F85149@40 + bg tint ; warn=#D29922@25 ; ok=none
```
Pattern: **block=red is never decorative** — reserved for genuinely stopped outcomes; `warn` amber used for OOS, ungrounded confidence, ambiguity; everything else is neutral/info.

### 8.3 Typography
- UI: `Inter` (fallback system stack) — 13/15px base, 600 weights for metrics.
- **Code/contracts: `JetBrains Mono`** — every value from the contract (target, CVE, ports, hashes, timestamps) rendered in mono, tabular-nums for numbers/latency.
- Scale: 12 / 13 / 15 / 18 / 24 / 32 / 42. Density: compact (command consoles are dense; 40px rows default).

### 8.4 Shape, elevation, motion
- Radius: 8px cards, 6px chips, 4px controls; hairline borders layout the dark plane (shadow reserved for dialogs only).
- Motion: 120–180 ms, cubic-bezier(0.2,0,0,1); **no entrance animations spam**; only purposeful: rail stage advance, toast in/out, card expand. Respect `prefers-reduced-motion`.
- Loading: stage rail is the loader; spinners only in review/settle buttons. Skeleton only for dashboard initial fetch.

### 8.5 Iconography & branding
- Single-weight stroke icon set (Lucide) sized 16/20px.
- Brand mark: a shell glyph ◈ (neuro-shell) with circuit node motif; used in rail + auth screen.
- Empty-state illustration style: line-art node graphs (pipeline theme), not clip-art.

### 8.6 Accessibility
- `prefers-reduced-motion` honoured; WCAG 2.1 AA contrast (check all accent-on-dark pairs — block #F85149 on #0A0E14 must be AA: use text-aa variant where needed).
- All taxonomy affordances are text as well as colour (✗/✓/● glyphs + labels, never colour alone).
- Full keyboard: rail, dialog focus trap, conductor via Ctrl+Enter; ARIA roles for rail, alerts (`role="alert"` for blocks), status regions.
- Status changes announced via `aria-live="polite"` without chatter.

### 8.7 Responsive
Breakpoints: desktop-first (>=1280 primary), collapse rail→icons 960–1280, stack grid <960, "mobile unsafe" interstitial <480 (composer unusable — warn, do not pretend).

---

## 9. Interaction & State Flows

### 9.1 Parse flow (the critical path)
```
Composer (trim > 0, ≤2000) ── Parse
  │  role, session_id, schema version, X-API-Key
  ▼
fetch POST /parse  (timeout 90s, AbortController=cancel)
  │
  ├─ 200 success        → ContractCard (rail: cache or full stages)
  ├─ 200 error (envelope)→ ErrorPanel with findings trail   ← v2 returns errors inside 200!
  ├─ 429                → RateLimit toast + global throttle state (disable parse 60s w/ countdown) + link to /settings
  ├─ 401                → credential dialog (re-enter key)
  ├─ 413                → composer-local "too long" (already prevented) 
  ├─ 503                → "pipeline warming" panel with /health probe button
  └─ network/timeout    → retryable error panel + "background it" (job banner, no lost input)
```
**Critical implementation rule:** v2 pipeline errors arrive as HTTP 200 with `status:"error"` — the UI must classify on **body.status**, not HTTP code. Both `/parse` (200-envelope) and API guards (real codes) must map to the same visual system.

### 9.2 Planner flow
Same as parse + `POST /parse/plan`. Distinct outcomes: `pending_review` (202) → escalation state; released contract on approve (Review flow). PlannerCard never proposes execution — it is "ready for Component 02".

### 9.3 Escalation resolution flow
```
Review Queue → expand → [Approve] confirm → POST resolve(approve:true,note?)
   → success: card → "Approved · contract ready to copy"
             [Reject] → note dialog → resolve(approve:false,note)
   → card "Rejected · noted"  (both update badge count)
```
Polling: every 10 s while page visible; manual refresh button (terminal users hate surprise mutation).

### 9.4 Session management
- Turn counter vs `max_turns 8`: at turn 7 show "context full — next parse resets or trims" hint; beyond, offer "New session".
- TTL 30 min: session row shows `age/ttl`; expired sessions grayed with "clear" action.

### 9.5 Health & degradation
- Global status pill: healthy / degraded (=ollama down) / unavailable. Degraded opens a panel with the full health body (model, engine, cache stats) + "Recheck".
- On degraded, composer stays enabled but every parse will likely `INFERENCE_FAILED`; show pre-flight guess "Ollama unreachable — parses will fail" to stop wasted 90 s waits.

### 9.6 Rate-limit UX
On 429: toast "30 req/min exceeded", parse buttons go disabled with **countdown to next window** (client estimates from last-allowed + 60 s), then re-enable; metric easter egg: actual window is per-IP so the estimate is best-effort.

---

## 10. Security Design (frontend)

1. **API key handling:** stored in `sessionStorage` (tab-scoped, cleared on close — deliberately NOT localStorage) + offered in-memory-only mode. Never logged, never in URLs. Header-only via `X-API-Key`.
2. **Dev-mode awareness:** if consumer gets `dev_mode` (key `dev_insecure_key`) flag it in Settings ("DEVELOPMENT KEY — any client can parse").
3. **CORS origin:** FastAPI must list the exact origin (e.g. same-origin when SPA is served by FastAPI). Recommend **same-origin serving** (SPA build output served by FastAPI static mount) to avoid CORS entirely — single origin, single key. Document the alternative (CORS allowlist) if separate-hosting is chosen.
4. **No new auth flows:** role is a request field, matching backend semantics; surfaced to the user as "the role your key/identity will carry" — a future SSO/token replaces the switcher only.
5. **Content safety:** render all contract strings as text (React escapes by default); CVE/target/hash values are attacker-controlled strings — never `dangerouslySetInnerHTML`, no HREF construction except whitelisted CVE links (https://nvd.nist.gov/vuln/detail/).
6. **Hash display:** escalation records show truncated `raw_input_hash` (first 8 chars) — full string available on disclosure.
7. **Rate-limit side effects:** no background auto-refetch spam; health poll 15 s (public endpoint) is the floor; authenticated polls ≤ 10 s and only on visible pages.

---

## 11. Tech Stack Recommendation

**Recommendation (primary): React 18 + TypeScript + Vite + Tailwind + TanStack Query + React Router + Recharts, served same-origin by FastAPI.**

| Concern | Choice | Why |
|---|---|---|
| Framework | React 18 (function components, hooks) | component-heavy contract UI, rich state per card; largest ecosystem for query/chart/tabular tooling |
| Language | TypeScript strict | the contract surface is *data*; TS types mirror Pydantic models; prevents field drift |
| Build | Vite (dev server proxying `:8001`, build → `static/`) | instant HMR; trivial FastAPI static mount |
| Data fetching | TanStack Query | caching for /health, /metrics, /admin/*; mutation for /parse, resolve, delete; background refetch + staleTime policy |
| Styling | Tailwind (design tokens → theme config) | tokenized design system (§8) with zero runtime; dark tokens native |
| Charts | Recharts (composable) | latency/entropy/distribution; no heavyweight ECharts license surface |
| Router | React Router 6 | routes per §5.2 with role route guards |
| State | Zustand (app-shell, session, role) + query cache (server data) | minimal global state; server state lives in Query |
| Codegen | openapi-typescript from `/openapi.json` | regenerate TS client types as API evolves |

**Alternatives:**
- *HTMX + Jinja (FastAPI-served classic app):* much lighter, but the contract-card interactivity + 70 s async UX + dashboards get awkward; not recommended for panel-heavy UI.
- *Single-file vanilla app:* zero-dep honest option for a demo; fine as a throwaway PoC, not the operator console.
- *Distribution:* Docker multi-stage (node build → python runtime serves `static/`) aligns with existing `Dockerfile`/compose.

Provide `/app` mount in FastAPI: static fallback for SPA routes + `X-API-Key` header from a singleton API client module (`src/lib/api.ts`).

---

## 12. Proposed Repository Structure (frontend root `frontend/`)

```
frontend/
├── package.json  vite.config.ts  tsconfig.json  tailwind.config.ts
├── src/
│   ├── main.tsx  App.tsx  router.tsx
│   ├── api/
│   │   ├── client.ts         fetch wrapper: base URL, X-API-Key, timeout, abort, error-classify (body.status vs HTTP code)
│   │   ├── endpoints.ts      typed wrappers per §4.1
│   │   └── types.ts          generated + hand-augmented IREResponseV2, PlannerContract, ValidationFinding, Health, Metrics, Escalation, …
│   ├── state/                roles.ts, session.ts, app-shell.ts
│   ├── taxonomy/             colors.ts, definitions.ts (intent/target/hallucination-class/error-code → label + description + colour)
│   ├── components/           (§7 inventory)
│   │   ├── shell/            AppShell, SideRail, TopBar, HealthPill
│   │   ├── console/          CommandComposer, AsyncParseButton, PipeLineRail, StageChip
│   │   ├── contract/         ContractCard, ConfidenceGauge, ChipGroup, PlannerChevron, ContractInspector
│   │   ├── validation/       ValidationFindingChip, ErrorPanel, TaxonomyLegend
│   │   ├── review/           EscalationCard, ResolutionDialog, QueueBadge
│   │   ├── sessions/         SessionList, SessionThread
│   │   ├── telemetry/        MetricsHeader, ChartGrid, EntropyStrip
│   │   ├── admin/            PolicyTable, RbacMatrix, ScopeCard, FeatureFlagsList, SettingsPane
│   │   └── common/           Toast, Dialog, Tooltip, EmptyState, KeyInput, StatusDot
│   ├── pages/                ConsolePage, SessionsPage, ReviewPage, TelemetryPage, AuditPage, PolicyPage, SettingsPage
│   └── utils/                format.ts (duration, mono hashes, percentiles), cidr.ts (scope preview math), sample.ts
├── tests/                    vitest unit (formatters, classify) + playwright e2e (flows §9.1–9.4)
└── e2e/                      staged mock-server (MSW-like harness serving canned v2 responses incl. slow + error fixtures)
```

**Type-drift guard:** `/openapi.json` → `openapi-typescript`; CI step fails if generated types mismatch checked-in types.

---

## 13. Implementation Roadmap

| Phase | Scope | Exit criteria |
|---|---|---|
| **P0 — Foundation** | Vite+TS scaffold; Tailwind tokens (§8); API client w/ error classification; AppShell+router+role guard; health poll + status pill | health renders; role switch drives route guards; key stored; dev proxy works |
| **P1 — Console MVP** | Composer + AsyncParseButton + PipeLineRail + ContractCard + ErrorPanel; cache vs inference states; sessions create/pick; copy JSON | parity with §6.2 on the golden examples (cache-hit instant, full pipeline animated, blocked variants correct) |
| **P2 — Planner + Review** | PlannerChevron tab; /parse/plan flow incl. 202 state; Review Queue page + resolution dialogs + badge polling | approve/reject round-trips with contract release viewable |
| **P3 — Observability** | Telemetry snapshot+charts; Audit page; Policy/RBAC/Scope explorer; Settings incl. reload features + debug harness | all admin surfaces read API accurately; empty states honest |
| **P4 — Depth** | Sessions thread replay; keyboard map; error taxonomy legend; rate-limit countdown; degraded-mode pre-warning; accessibility pass | flow tests §9 pass on Playwright incl. slow/error fixtures |
| **P5 — Hardening** | openapi typegen CI; e2e suite in Docker; reduced-motion/contrast audit; perf audit (no jank on 70 s in-flight + polling) | CI green; Lighthouse a11y ≥ 0.95 score; 60 fps while in-flight |

---

## 14. Testing Strategy

- **Unit (vitest):** formatters (duration humanizing, hash truncation, percentile math), `client.classify(response)` (200-envelope error vs success vs 429/401/413/503), cidr scope-preview math, gauge ticks.
- **Component:** ContractCard severity variants, PipeLineRail stage transitions, EscalationCard approve/reject, RoleSwitcher gating, RateLimit countdown timer.
- **E2E (Playwright) against a **mock server** that replays canonical fixtures:** golden success, cache hit (44 ms), full-pipeline slow (simulated 20 s, assert rail animation + cancel), every error taxonomy row §4.5, 202 escalation, 429 with countdown, 401 re-auth, 503 degraded hint.
- **Real-backend smoke:** one file of Playwright tests tagged `@real` that hit a running IRE with dev key (golden_cache scenario) — CI-gated separately, since 70 s latencies are unacceptable in unit smoke.
- **A11y checks:** axe in CI; keyboard-only flow scripts.

---

## 15. Acceptance Criteria (top 10)

1. Parse returns a rendered contract card within 100 ms of response arrival; cache hits show the ⚡ path with no stage animation.
2. Any blocking outcome renders via ErrorPanel inside an HTTP-200 body identically to a real 4xx (both reach the same component).
3. The validation rail never shows "all green" when `validation_findings` contains failed entries (data-driven, not derived).
4. Role switch to `analyst` + exploitation-command attempt shows RBAC denial with permitted-intent list (from live `/admin/rbac/analyst` when available — graceful client-side fallback otherwise).
5. Escalation badge reflects live pending count ≤10 s; approve/reject updates the list without a full refresh.
6. 429 disables parse with a countdown; user is never blindly retried.
7. Degraded health (Ollama down) disables the 90 s wait trap with a pre-flight warning.
8. All contract-value strings render as text (CSP-friendly, no HTML injection).
9. Keyboard: `/` focus composer, Ctrl+Enter parse, Esc cancels in-flight, number-key history selection.
10. OpenAPI-generated types are source-controlled; CI gate fails on drift.

---

## 16. Open Questions (to resolve before build)

1. **Hosting model:** same-origin SPA served by FastAPI (recommended, no CORS) vs separate statics host (needs CORSMiddleware allowlist incl. auth headers)?
2. **Key storage:** `sessionStorage` + in-memory toggle accepted? Or require re-entry per browser session?
3. **Role switcher honesty:** acceptable that role is a per-request field (no SSO) for v1? Confirm no requirement for real identity binding in release scope.
4. **Planner visibility:** should non-admin users see "Parse → Planner" (contract is the Component-02 handoff) or is that admin-only? Backend allows all; UI asks.
5. **Charts detail tier:** is `/metrics` snapshot (aggregate, in-memory, 1000-sample cap) sufficient, or must the UI accumulate its own history between polls (client-side timeseries) — affects P3 scope.
6. **Multi-user signalling:** any need for server-push (WebSocket/SSE) for review-queue updates in a team setting, or is 10 s polling fine for local/lab single-operator usage?
7. **Light theme** requirement deferred — confirm dark-only is acceptable.
8. **Branding assets:** engagement starts as "Lab Environment"; do you want hideable branding for the published demo (e.g. paper screenshots)?