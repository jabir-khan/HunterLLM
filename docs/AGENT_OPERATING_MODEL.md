# How the Cursor agent (Fable 5) works — and what to port into HunterLLM

This is a plain-language, faithful description of how I (the coding/agent model
you're talking to in Cursor) actually operate: the tools I can call, the
knowledge I draw on, the loop I run, and the judgment rules that keep me from
being confidently wrong. It is written so you can read it side-by-side with
HunterLLM and decide, together, what is worth copying.

It is **not** a verbatim dump of a proprietary system prompt — it's an honest
functional description. Where a capability of mine has a HunterLLM analog, the
`→ HunterLLM` line says whether we already have it, and what "adding it" means.

---

## 1. The core idea that makes an agent feel "intelligent"

I am not smart because I know more facts. I am useful because I run a
**disciplined loop with tools and verify my own claims before I state them.**
Almost everything below is a variation on one rule:

> **Never assert what you can cheaply check. Check it, then assert it with the evidence.**

A model that guesses sounds confident and is often wrong (false positives). A
model that gathers evidence first is slower per step but *right*, and right is
what earns trust — in code and in bug bounty.

→ HunterLLM: this is exactly the `REASONING & CALIBRATION` + `SIGNAL DISCIPLINE`
sections we added to `SYSTEM_BUG_HUNTER`. The doc below breaks down the parts
that a *training set* and a *prompt* can each reinforce.

---

## 2. Tools I actually have (and the HunterLLM analog)

| My tool | What it does for me | HunterLLM analog / what to add |
|---|---|---|
| **Read file** | Read exact source before editing/claiming | Read a saved HTTP request/response, JS bundle, source snippet before triaging |
| **Grep / Glob (ripgrep)** | Find symbols/strings fast across a repo | `katana`/`gau` for endpoints, `grep`/`trufflehog` over JS & source for secrets/params |
| **Shell** | Run commands, tests, git; observe real output | The pentest toolchain the prompt already lists: `subfinder/httpx/ffuf/nuclei/sqlmap/dalfox` |
| **Edit / Write** | Make precise, reversible changes | Write nuclei templates, PoC scripts, report drafts |
| **Lint / test runners** | Verify a change didn't break anything | Re-run the probe / reproduce on a 2nd account = the "did it really work" check |
| **Web search / fetch** | Pull current docs when memory is stale | Pull the program's scope/policy page, CVE details, vendor advisories |
| **Sub-agents / parallelism** | Fan out independent exploration | Run recon on many hosts concurrently; triage findings in parallel |
| **Todo / plan tracking** | Hold a multi-step plan without losing state | An engagement checklist: recon → enum → per-surface hypotheses → chain → report |
| **Browser automation** | Drive a real browser, screenshot, inspect DOM | Validate XSS execution, OAuth flows, client-side sinks in a real browser |

The gap between me and a *chat-only* HunterLLM is not knowledge — it's **the
hands**. That's why the earlier plan pointed at Strix (or an MCP tool layer):
HunterLLM is the brain (policy/judgment), the tool runner is the hands. This
doc is about making the brain as good as possible; wiring hands is a separate,
already-scoped track (`docs/agent_strix.md`). **§10 gives the precise per-tool
contracts** (inputs/outputs/constraints/side-effects) to build that layer.

---

## 3. The loop I run on every non-trivial task

```
UNDERSTAND → EXPLORE → HYPOTHESIZE → ACT (smallest step) → OBSERVE →
VERIFY / FALSIFY → (repeat) → REPORT with evidence
```

1. **Understand** the real goal, not the literal words. Restate it if ambiguous.
2. **Explore before acting.** I read the actual files / responses. I do not
   theorize about code I haven't looked at. (Bug-hunt analog: enumerate the
   surface and read the real traffic before claiming a vuln.)
3. **Hypothesize** a specific, falsifiable claim.
4. **Act with the smallest step** that tests the hypothesis. One decisive probe,
   not a shotgun.
5. **Observe** the real output. The tool result is ground truth, not my memory.
6. **Verify or falsify.** Try to break my own conclusion. Reproduce it.
7. **Report** with the evidence inline and a calibrated confidence.

→ HunterLLM already has an autonomous loop line; what's newly added to the
prompt from this doc is the **EXPLORE-first** and **VERIFY/FALSIFY** emphasis
(sections `OPERATING METHOD` and `VERIFICATION & PROOF`).

---

## 4. How I judge — exact rules (the anti-false-positive core)

These are stated as rules I actually apply, in the imperative, so they can be
lifted straight into a prompt, a rubric, or DPO preference pairs. Each maps 1:1
to a bug-bounty false-positive class.

**R1 — Evidence gate.** Do not state a claim as fact unless you can point to a
specific observation that produced it. The observation must be one of: a
status-code/response-length/response-content differential, an error string, an
out-of-band callback, a measurable timing gap, or bytes reflected/executed. If
you have none, the correct output is a hypothesis explicitly labeled as such,
plus the one check that would settle it. "Looks vulnerable" without an
observation is not permitted.

**R2 — Falsify before you assert.** For every candidate finding, enumerate the
benign explanations and rule each out *before* claiming a bug. The standard
benign set: a WAF/proxy returning a generic block, an input-size or type guard,
an intended feature/documented behavior, a cache serving a stale response, a
framework default (e.g. cookies already `SameSite=Lax`), or your own leftover
session state. State which benign causes you excluded and how. Most false
positives die at this step.

**R3 — Confidence is mandatory and defined.**
  - `CONFIRMED` = reproduced from a clean state with a concrete artifact (a
    saved request/response pair, a callback log, a diff between control and test).
  - `LIKELY` = one strong signal, exactly one step short of proof; name that step.
  - `SPECULATIVE` = theory only, no observation yet; say so in those words.
  Never present `LIKELY` or `SPECULATIVE` with the language of `CONFIRMED`.

**R4 — Reproduce before reporting.** A result that occurred once may be luck (a
race window, a cached response, warmed state, a shared session). Trigger it
again from a clean state (fresh session/incognito/new token). If it does not
reproduce deterministically, it is not `CONFIRMED` — keep it as a labeled lead.

**R5 — Negative control.** Prove the behavior is caused by your input, not the
baseline. Re-run the exact request with the payload removed, and/or as a second
identity you legitimately control. The *difference* between control and test is
the proof. No difference → no finding.

**R6 — Attribute out-of-band effects.** For blind/OOB vulns, use a unique
per-test OAST subdomain or canary token so any callback is unambiguously caused
by your specific probe and not background noise or another tester.

**R7 — Scanner output is a lead, never a finding.** Treat every automated hit
(nuclei/sqlmap/dalfox/etc.) as an unproven hypothesis and put it through R1–R5
before it is allowed to be called a vulnerability. Unverified scanner output is
the single largest source of false positives.

**R8 — Root cause over symptom.** Identify the underlying cause and report that
with its strongest demonstrated impact, rather than filing the first visible
artifact (or filing the same shared-component bug N times across hosts). One
root-cause report beats forty symptom tickets.

**R9 — Impact gate (severity is earned, not asserted).** A finding counts only
if it crosses a security boundary: a privileged action, another user's/tenant's
data, a secret, or an executing sink. If it does not, label it informational and
do not inflate it. Grade severity by the *demonstrated* reachable impact, not the
theoretical worst case.

**R10 — Escalate to the highest provable impact, then stop.** Once you have a
foothold, ask "what does this unlock?" and chain toward RCE / ATO / full or
cross-tenant data exposure — but stop at the first solid proof of that impact.
Do not keep exploiting past proof, and never run destructive or
availability-impacting actions to "demonstrate" severity.

**R11 — Minimize blast radius.** Use the smallest probe/change that answers the
question. One sensitive read, one OAST hit, one controlled cross-account read
using canaries — never mass-enumeration of real users/records.

**R12 — Separate OBSERVED / INFERRED / ASSUMED.** Keep these three distinct in
your reasoning and in your output. Never let an inference or assumption be
narrated as an observation.

**R13 — No fabrication.** Never invent CVE IDs, advisory URLs, API endpoints,
version strings, parameter names, or tool flags. A guessed path/param must be
marked "candidate — verify."

→ HunterLLM: R9/R10 are the `SIGNAL DISCIPLINE` prompt section and the
`llm_falsepos` / `llm_highimpact` training buckets. R1–R7 are the new
`VERIFICATION & PROOF` prompt section. R7 (scanner triage) is the single most
valuable *new training bucket* to add — see §9.

---

## 5. How I avoid rabbit holes (self-correction)

- Every retry must be justified by **new evidence**, not hope. Repeating a failed
  action unchanged is banned.
- After a few failed attempts on one hypothesis, I **stop and pivot** to a
  different hypothesis rather than grinding.
- If I'm stuck, I say what I observed, what blocked me, and the most likely next
  step — I don't fake progress.
- I don't over-engineer: I do the simplest thing that satisfies the goal, and I
  don't add scope the task didn't ask for.

→ HunterLLM: this is the new `SELF-CORRECTION` section in the prompt. It's also
a strong candidate for **DPO** (reject "tries the same payload 20 times" /
"lectures instead of pivoting"; prefer "pivots with a new hypothesis").

---

## 6. Where high-impact bugs actually cluster (my prioritization prior)

When time is limited, I bias toward the surfaces with the highest
impact-per-hour, and I *skip* the low-yield noise:

**Hunt first (high severity lives here):**
- Authn/authz surfaces: login, SSO, password reset, OAuth/OIDC callbacks,
  session issuance → ATO.
- Object/tenant access: APIs, GraphQL, anything with an id/filter → IDOR/BOLA,
  cross-tenant reads.
- Server-side fetch / URL handling → SSRF → cloud metadata → role takeover.
- Anything that reaches a sink: `exec`, SQL builder, template, deserializer → RCE.
- Agent/LLM tool calling → excessive agency, argument injection (the 2025 frontier).
- Distinctive / forgotten hosts: dev/staging/old, odd tech, admin panels.

**Deprioritize (low yield / usually N/A):**
- Marketing-page clones, missing security headers alone, verbose banners,
  self-XSS, "no rate limit" with no demonstrated attack, jailbreaks/harmful-content
  on LLM targets.

→ HunterLLM: encoded in the `decision`/`llm_highimpact` training rows and the
prompt's `SIGNAL DISCIPLINE`. Easy to extend with more worked "fresh scope,
limited time, what first?" examples.

---

## 7. How I communicate a result (why it reads as competent)

- **Lead with the outcome** ("what happened / what I found"), then the evidence,
  then the detail. Not a play-by-play.
- Artefacts (commands, requests, PoCs) in fenced blocks; prose is the wrapper.
- State confidence and what would raise it.
- Be honest about what failed or is unverified. Never dress a maybe as a yes.

→ HunterLLM: already the `OUTPUT DISCIPLINE` + report standard sections.

---

## 8. What I do NOT have (so we set expectations honestly)

- No memory across sessions beyond what's in the repo/context.
- No ground truth beyond the tools' output — if I can't run it, I can't confirm it.
- I can be wrong; the loop and verification are what catch it, not omniscience.

---

## 9. Shortlist: what we could add to HunterLLM next

Ranked by expected impact on "high-impact, low-false-positive":

1. **DPO preference layer** — the single biggest lever. Teach *chosen vs
   rejected*: calibrated evidence-backed answer (chosen) vs confident-but-wrong /
   lecture / false-positive (rejected). Prompts can *ask* for calibration; DPO
   *rewards* it.
2. **Verification/reproduction training rows** — worked examples of "it happened
   once → reproduce from clean state / 2nd account → only then report."
3. **Tool-result reading rows** — given raw nuclei/sqlmap/burp output, separate
   true positives from scanner noise (this is where most FP come from).
4. **Hands (execution layer)** — MCP tools or Strix so the brain can actually
   run the probes it proposes and observe real output (closes the loop).
5. **More "limited time, fresh scope" decision rows** — sharpen the
   prioritization prior in §6.

---

## 10. Tool contracts — the execution layer to build for HunterLLM

This is the precise version of §2, written as a **contract per tool**: name,
purpose, inputs, output, hard constraints, and when the agent should reach for
it. It is the interface HunterLLM's "hands" (an MCP server or a Strix-style
runner) should expose so the model can close the OBSERVE→VERIFY loop itself.
Design notes that matter regardless of implementation:

- **Every tool returns a structured result** with at minimum: `ok` (bool),
  `stdout`/`content`, `exit_code`/`status`, `duration_ms`, and `truncated`
  (bool). The model reasons over *real* output, so never silently drop it —
  truncate with a marker and offer a follow-up read.
- **Read-only vs state-changing is explicit.** Every tool declares a
  `side_effects` level (`none` | `local_write` | `network_active`
  | `destructive`). The policy layer blocks `destructive` and gates
  `network_active` on confirmed scope. This is how you enforce R10/R11 in code,
  not just in the prompt.
- **Scope is enforced at the tool, not the prompt.** A network tool checks the
  target against the authorized scope list before firing. Judgment in the prompt
  is a backstop; the allowlist in the tool is the control.

Contracts (`side_effects` in brackets):

- **read_file** [none] — Read an exact artefact before reasoning about it.
  In: `path`, optional `offset`/`limit`. Out: numbered lines + `truncated`.
  Use: read saved request/response, JS bundle, source, scan output. Rule R1
  depends on this — you cannot cite evidence you have not read.

- **search** (grep/ripgrep) [none] — Find strings/patterns across many files.
  In: `pattern` (regex), optional `glob`/`path`, `output_mode`
  (`content`|`files`|`count`). Out: matches with file:line. Use: hunt secrets,
  params, endpoints, sink calls (`exec`, `query`, `innerHTML`) in source/JS.

- **find_files** (glob) [none] — Locate files by name pattern. In: `glob`,
  `dir`. Out: paths by mtime. Use: enumerate what exists before searching.

- **run_command** (shell) [none→destructive; declared per call] — Execute a
  command and capture real output. In: `command`, `cwd`, `timeout_ms`,
  `background` (bool). Out: `stdout`, `stderr`, `exit_code`, `duration_ms`,
  `pid` if backgrounded. Constraints: no destructive flags without explicit
  approval; long-running commands must support background execution plus a
  poll/await companion so recon scans don't block. Use: the pentest toolchain (`subfinder`, `httpx`, `ffuf`,
  `nuclei`, `sqlmap`, `curl`) — but each result is a *lead* (R7) until verified.

- **await_command** [none] — Poll/stream a backgrounded run. In: `job_id`,
  `block_until_ms`, optional match `pattern`. Out: new output + `running`/`done`
  + `exit_code`. Use: watch a long scan for a sentinel line without busy-waiting.

- **write_file / edit_file** [local_write] — Create/modify a file precisely and
  reversibly. In (edit): `path`, `old_string` (unique), `new_string`. Out:
  applied diff. Use: write a nuclei template, a PoC script, a report draft.
  Constraint: edit must fail if `old_string` is non-unique (forces the model to
  look, not guess).

- **http_request** [network_active] — Send one crafted HTTP request and get the
  full raw response. In: method, url, headers, body, `follow_redirects`. Out:
  status, headers, body, timing. Constraints: url must pass scope allowlist;
  rate-limited. Use: the single decisive "act small" probe; the control/test
  pair for R5; timing capture for oracle bugs.

- **oast_client** [network_active] — Allocate a unique callback host and read
  its interactions. In: `action` (`allocate`|`poll`), `token`. Out: subdomain +
  interaction log (DNS/HTTP/SMTP with source IP + timestamp). Use: R6 — prove a
  blind/OOB effect is attributable to your probe. Backed by
  Collaborator/interact.sh; never personal infra.

- **browser** [network_active] — Drive a real browser for client-side truth.
  In: `navigate`/`click`/`type`/`snapshot`/`screenshot`/`eval_js`. Out: DOM
  snapshot, screenshot image, console/network logs. Use: confirm XSS actually
  *executes* (`document.domain`), walk an OAuth/redirect flow, inspect a
  client-side sink. This is what turns "it rendered" into "it executed" (kills
  the #1 XSS false positive).

- **web_fetch / web_search** [network_active, read-only] — Pull current external
  info. In: `url` or `query`. Out: readable text/result list. Use: fetch the
  program's scope/policy page, a CVE advisory, vendor docs — when the model's
  memory may be stale. Never a substitute for confirming on the target itself.

- **plan/todo** [none] — Hold and update a multi-step engagement plan. In: list
  of steps with status. Out: current plan. Use: keep the recon→enum→hypothesis
  →chain→report state across a long engagement without losing the thread.

- **spawn_subagent** [inherits] — Fan out an independent sub-task with its own
  context (e.g. recon on a host cluster, triage a batch of findings), returning
  a summary. Use: parallelize breadth so the main thread keeps depth. Constrain
  concurrency and scope per child.

Minimum viable set to make HunterLLM *agentic* (in priority order):
`read_file` + `search` → `run_command` (+`await_command`) → `http_request` +
`oast_client` → `browser`. With those, the model can propose a probe, run it,
read real output, run a negative control, and attribute an OOB hit — i.e.
actually execute rules R1–R7 instead of only reciting them. Strix already
provides most of this (sandboxed shell + browser + HTTP); an MCP wrapper
exposing these contracts is the alternative. See `docs/agent_strix.md`.

See also: `docs/agent_strix.md` (execution layer), `scripts/build_reasoning_chains.py`
(where the reasoning training rows live).
