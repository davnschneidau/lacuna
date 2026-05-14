# Lacuna — Context Strategy (Mythos-style)

> A deep dive on how Lacuna keeps a multi-hour, multi-repo, multi-agent scan coherent without context rot, mirroring the mechanisms Anthropic uses in Mythos / Project Glasswing.

---

## Part 1 — What Mythos actually does, in Anthropic's published terms

Mythos (the marketing name) and Glasswing (the project) sit on top of techniques Anthropic has documented in *Effective context engineering for AI agents* (Sep 2025) and the *Managing context on the Claude Developer Platform* announcement. The marketing language ("infinite context window", "server-side compaction", "context editing") maps to four concrete mechanisms plus an architectural pattern:

| Mythos behavior (marketing) | Anthropic-documented mechanism | What it actually is |
|---|---|---|
| "Server-side context compaction" | **Compaction** | Summarize message history near the limit, restart with the summary, preserve architectural decisions and unresolved bugs, drop redundant tool output. |
| "Context editing — explicitly forget stale tool results" | **Context editing / tool result clearing** | API-level feature on the Claude Developer Platform that automatically clears stale tool calls and results when approaching token limits. |
| "Maintains coherence across long workflows" | **Memory tool / structured note-taking** | Client-side file storage exposed as tools. Agent reads/writes its own NOTES across sessions. |
| "Specialized agents for different bug classes" | **Sub-agent architecture** | Isolated subagents that explore deeply, return condensed summaries to the parent. |
| "Just-in-time understanding of the codebase" | **Just-in-time retrieval** | Agents hold lightweight identifiers (paths, queries) and load content on demand instead of pre-stuffing the window. |

Two structural patterns sit underneath these:

1. **The session is not the context window.** Independent of any single technique, the durable record of an agent's work is an event log on disk — not the model's transcript. The transcript is a *view* over the log; compaction is a re-projection.
2. **Attention budget is the scarce resource.** Performance degrades smoothly as the window fills (the "context rot" phenomenon), so the win is not "bigger window" but "fewer high-signal tokens per turn."

Lacuna inherits all five mechanisms and both patterns. The rest of this document is how.

---

## Part 2 — Lacuna's five-tier context model

```
                  attention budget
                       ▲
                       │  ████  Tier 1: System prompt + skills (small, durable)
                       │  ████  Tier 2: Just-in-time references (KG handles, paths)
durable │  ephemeral   │  ████  Tier 3: Working scratch (current turn's reasoning)
        │              │  ████  Tier 4: Subagent isolation (out of parent context)
        ▼              │  ████  Tier 5: KG + event log (durable, off-context)
```

Each tier has explicit rules.

### Tier 1 — System prompt + active skills
The orchestrator's CLAUDE.md plus whatever skills are auto-invoked. Budget: **~4-8K tokens**. Never grows during the scan. Lives at the top of context across compactions.

### Tier 2 — Just-in-time references
Handles to durable state: KG status summary, manifest path, current phase, list of pending hypothesis IDs (not their content). Budget: **~2-4K tokens**. Refreshed at every turn via the `SessionStart` and `UserPromptSubmit` hooks.

### Tier 3 — Working scratch
The current reasoning chain, current tool calls, intermediate decisions. Budget: **whatever's left until compaction trigger**. Expected to be lost — the agent commits anything important to the KG before it can be compacted away.

### Tier 4 — Subagent isolation
A subagent has its own Tier 1-3. The orchestrator never sees its working scratch — only the explicit summary the subagent writes. Anthropic's documented pattern: subagents can burn tens of thousands of tokens internally, return ~1-2K tokens. Lacuna's hunter and validator agents follow this contract precisely.

### Tier 5 — Knowledge graph + event log
Durable. Lives in SQLite at `/state/lacuna.db`. *This is the agent's memory.* Compaction summaries are lossy; the KG is not. After every compaction, the orchestrator re-reads from the KG, not from the summary.

---

## Part 3 — The Lacuna event log (the "session ≠ context window" pattern)

Borrowing the pattern documented in Anthropic's agent harness work: every meaningful action is recorded as a typed event in an append-only log. The context window is reconstructed from the log; the log is the source of truth.

```sql
CREATE TABLE event_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  agent           TEXT NOT NULL,          -- 'orchestrator', 'hunter-injection', etc.
  event_type      TEXT NOT NULL,          -- see below
  payload_json    TEXT NOT NULL,
  parent_event_id INTEGER REFERENCES event_log(id)
);

CREATE INDEX idx_event_agent_ts ON event_log(agent, ts);
CREATE INDEX idx_event_type_ts  ON event_log(event_type, ts);
```

Event types:
- `user_message` — Initial directive, or human re-engagement in ad-hoc mode
- `assistant_turn` — Each model response (thinking + tool calls + text)
- `tool_call` — Every MCP tool invocation with args
- `tool_result` — The tool's response (large payloads stored by reference: `payload_ref:/state/tool_results/abc123.json`)
- `subagent_spawn` — Parent → child handoff with input contract
- `subagent_return` — Child → parent with output summary
- `compaction_checkpoint` — Before/after pair around every compaction
- `hook_fired` — Any hook execution, with decision
- `kg_write` — Any KG mutation (denormalized for replayability)

**Why this matters for context strategy.** When compaction happens, you don't lose the work — you lose the *transcript view* of the work. The event log retains everything. If a finding goes wrong six hours into a scan, you can replay the relevant slice. If an agent oscillates, you can detect it from event patterns. If a chain depends on something the agent "forgot," you can re-inject it from the log on demand via a tool call.

This is also how Lacuna supports `--resume`: load the event log, rebuild the KG view, optionally project a small synthetic transcript into the new context window so the orchestrator picks up where it left off.

---

## Part 4 — The five context mechanisms, wired up

### 4.1 Compaction (with a Lacuna-specific summarization prompt)

Claude Code's default compaction is good but generic. Lacuna overrides the compaction prompt via `.claude/settings.json` to make sure the things that matter to a security scan survive compaction.

```json
{
  "compaction": {
    "trigger_at_percent": 70,
    "system_prompt_override": "You are compacting the working transcript of Lacuna, an agentic security scanner. Preserve, in this order: (1) the current phase and active hypothesis being investigated, (2) any partially-formed primitives or chain candidates not yet written to the KG, (3) the reasoning chain for the current finding under validation (red arguments, blue arguments, reconciliation in progress), (4) outstanding tool calls awaiting results, (5) the orchestrator's plan for the next 3-5 actions. Discard: raw tool outputs already summarized into KG entries, file excerpts no longer being reasoned about, refuted hypotheses (they're in the KG), and all conversational pleasantries. Output a compressed transcript that lets the orchestrator continue without re-doing work. The KG is the source of truth — do not duplicate KG content in the summary."
  }
}
```

The trigger is set to **70% rather than the default 92%** because Lacuna's PreCompact hook needs headroom to do its own work (see 4.2). The remaining 30% is deliberate slack for the PreCompact KG flush.

### 4.2 The PreCompact hook — the KG flush

This is *the* most important Lacuna-specific mechanism. Before any compaction happens, this hook scans the transcript and forces any in-flight reasoning into the KG so it survives summarization regardless of how good the summary is.

```python
#!/usr/bin/env python3
# .claude/hooks/pre_compact_flush.py
"""
Runs before Claude Code compacts the transcript. Extracts in-flight reasoning
artifacts and persists them to the KG so they survive summarization.

The compaction prompt is best-effort. The KG is guarantees.
"""
import json, sys, sqlite3, os, re, uuid
from datetime import datetime

hook_input = json.load(sys.stdin)
transcript = hook_input.get("transcript", "")
agent_name = hook_input.get("agent", "orchestrator")
db_path = os.environ["LACUNA_KG_PATH"]
db = sqlite3.connect(db_path)
db.execute("PRAGMA foreign_keys = ON;")

# 1. Extract any unsaved hypotheses (agents are instructed to mark these)
HYPOTHESIS_BLOCK = re.compile(
    r"<hypothesis-draft>\s*(\{.*?\})\s*</hypothesis-draft>", re.DOTALL
)
for match in HYPOTHESIS_BLOCK.finditer(transcript):
    h = json.loads(match.group(1))
    h.setdefault("id", f"hyp-{uuid.uuid4().hex[:12]}")
    h.setdefault("status", "pending")
    h.setdefault("hunter", agent_name)
    db.execute(
        """INSERT OR IGNORE INTO hypotheses
           (id, hunter, shape, repo, file, line, description,
            attacker_scenario, confidence, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (h["id"], h["hunter"], h["shape"], h.get("repo"), h.get("file"),
         h.get("line"), h["description"], h.get("attacker_scenario"),
         h.get("confidence", 0.3), h["status"]),
    )

# 2. Extract partial primitives (validator emits these as findings are confirmed)
PRIMITIVE_BLOCK = re.compile(
    r"<primitive-draft>\s*(\{.*?\})\s*</primitive-draft>", re.DOTALL
)
for match in PRIMITIVE_BLOCK.finditer(transcript):
    p = json.loads(match.group(1))
    p.setdefault("id", f"prim-{uuid.uuid4().hex[:12]}")
    db.execute(
        """INSERT OR IGNORE INTO primitives
           (id, finding_id, name, description, prerequisites, effects,
            repos_involved, chain_explored)
           VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
        (p["id"], p.get("finding_id"), p["name"], p["description"],
         json.dumps(p["prerequisites"]), json.dumps(p["effects"]),
         ",".join(p["repos_involved"])),
    )

# 3. Extract chain candidates the chain-builder was investigating
CHAIN_BLOCK = re.compile(
    r"<chain-candidate>\s*(\{.*?\})\s*</chain-candidate>", re.DOTALL
)
for match in CHAIN_BLOCK.finditer(transcript):
    c = json.loads(match.group(1))
    if c.get("status") != "exploring":
        continue
    # Park as an open candidate in a worktable so chain-builder resumes
    db.execute(
        """INSERT OR REPLACE INTO chain_candidates
           (id, primitive_ids, goal, narrative_so_far)
           VALUES (?, ?, ?, ?)""",
        (c["id"], json.dumps(c["primitive_ids"]), c["goal"],
         c.get("narrative_so_far", "")),
    )

# 4. Snapshot the orchestrator's stated next-actions so it can re-orient
NEXT_ACTIONS = re.compile(
    r"<next-actions>\s*(.*?)\s*</next-actions>", re.DOTALL
)
m = NEXT_ACTIONS.search(transcript)
if m:
    db.execute(
        "INSERT INTO orchestrator_state (ts, key, value) VALUES (?, 'next_actions', ?)",
        (datetime.utcnow().isoformat(), m.group(1).strip()),
    )

# 5. Audit log the compaction itself
db.execute(
    """INSERT INTO event_log (agent, event_type, payload_json)
       VALUES (?, 'compaction_checkpoint',
               json_object('phase', 'pre', 'transcript_bytes', ?))""",
    (agent_name, len(transcript)),
)
db.commit()
db.close()

# Allow compaction to proceed
print(json.dumps({"decision": "allow"}))
sys.exit(0)
```

The agent-side contract is that **all hunters, validators, and the chain-builder must wrap in-flight artifacts in `<hypothesis-draft>`, `<primitive-draft>`, `<chain-candidate>`, `<next-actions>` tags whenever they're not yet ready to commit to the KG**. The hook treats these as the canonical extraction points. This is documented in each agent's system prompt and reinforced by the `caveman` skill.

### 4.3 Tool result clearing (API-level context editing)

This is the Anthropic Developer Platform feature that automatically strips stale tool outputs from context as the window fills. When Lacuna calls Claude (whether through Claude Code or directly through the Foundry endpoint), the API request includes:

```json
{
  "model": "claude-opus-4-7",
  "context_management": {
    "edits": [
      {
        "type": "clear_tool_uses_20250919",
        "trigger": { "type": "input_tokens", "value": 120000 },
        "keep":    { "type": "tool_uses",   "value": 10 },
        "clear_at_least": { "type": "input_tokens", "value": 30000 },
        "exclude_tools": ["kg.read.application_model", "kg.status.exit_criteria"]
      }
    ]
  }
}
```

The trigger and keep/clear values are tuned for Lacuna's tool mix. Two pieces are non-obvious:

- **`exclude_tools`** preserves the small, durable references the agent needs to stay oriented. The application model summary and the exit-criteria status should never be cleared — clearing them would force a re-read every turn.
- **`clear_at_least`** ensures clearing actually creates meaningful headroom. Without it, the API might clear a single 200-token tool result and immediately re-trigger.

Inside Claude Code, this is configured via `.claude/settings.json`:

```json
{
  "api": {
    "context_management": {
      "tool_result_clearing": {
        "enabled": true,
        "trigger_tokens": 120000,
        "keep_recent": 10,
        "min_clear_tokens": 30000,
        "exclude_tools": [
          "kg.read.application_model",
          "kg.status.exit_criteria",
          "kg.read.findings"
        ]
      }
    }
  }
}
```

### 4.4 The memory tool — KG as agent memory

Anthropic's memory tool is a file-based interface. Lacuna exposes the KG *both* as MCP tools (for structured access) *and* as a memory-tool-shaped file interface (for the natural "write a note" pattern).

The memory tool sees a virtual directory layout:

```
/memory/
├── application_model.md              ← read-only, written by recon
├── current_phase.md                  ← read-only, written by orchestrator
├── pending_hypotheses/
│   ├── hyp-a1b2c3d4.md               ← one file per hypothesis
│   └── hyp-e5f6g7h8.md
├── confirmed_findings/
│   └── fnd-...md
├── primitives/
│   └── prim-...md
├── chains/
│   └── chain-...md
├── refuted_hypotheses/               ← critical: prevents re-exploration
│   └── ...
└── agent_notes/                      ← agent-private scratch
    ├── orchestrator/
    ├── chain-builder/
    └── hunter-injection/
```

These are not actual files — they're a projection over the KG. A `memory.read("/memory/primitives/prim-abc.md")` call hits the KG and returns a markdown rendering. A `memory.write("/memory/agent_notes/chain-builder/working.md", content)` call writes to a per-agent scratch table.

```sql
CREATE TABLE agent_notes (
  agent       TEXT NOT NULL,
  path        TEXT NOT NULL,
  content     TEXT NOT NULL,
  updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (agent, path)
);
```

**Why both interfaces?** Different access patterns. The orchestrator's planning logic benefits from structured queries (`kg.read.hypotheses(status='pending')`); the chain-builder's exploratory reasoning benefits from "open the file, scribble in it" semantics. Both routes hit the same SQLite DB.

### 4.5 Sub-agent architecture — explicit context contracts

Every subagent has a written input and output contract enforced by the harness. The contract is the boundary across which context isolation actually happens.

Example — `hunter-cross-service` contract:

```yaml
# .claude/agents/hunter-cross-service.contract.yaml
input:
  required:
    - kg.application_model           # Always pre-loaded into Tier 2
    - kg.service_map
    - kg.cross_repo_calls
  on_demand:                          # Subagent fetches as needed
    - lacuna-recon.code_excerpt
    - lacuna-recon.auth_surface
    - lacuna-recon.endpoints
    - kg.read.*
  max_input_tokens: 8000              # Hard cap on Tier 1+2 at spawn

output:
  format: structured_markdown
  required_sections:
    - summary                          # ≤ 300 words
    - hypotheses_added                 # ≤ 50 (each one in KG, just IDs here)
    - notes_for_orchestrator           # ≤ 200 words, actionable only
  max_output_tokens: 2000              # Hard cap on what returns to parent
  forbidden:
    - raw_code_excerpts                # No code returns to parent
    - tool_output_dumps
    - chain_of_thought                 # Stays in subagent's context
```

The harness enforces these caps by wrapping the subagent spawn. If a subagent tries to return 8K tokens of code, it gets truncated and the agent is asked to re-summarize — the parent's context window is sacred.

### 4.6 Just-in-time retrieval — tools return handles, not contents

The MCP tool design follows the just-in-time pattern Anthropic documents for Claude Code: return *references* and *summaries*, not full contents. The agent decides when (or if) to materialize.

Three-tier tool result pattern:

```python
# lacuna-recon.entrypoints — example tool result shape
{
  "summary": "47 HTTP endpoints across 3 frameworks; 5 admin routes; 12 unauthenticated; 30 require JWT.",
  "facets": {
    "by_auth": {"none": 12, "jwt": 30, "session": 5},
    "by_method": {"GET": 28, "POST": 14, "PUT": 3, "DELETE": 2},
    "by_repo": {"wallet-api": 35, "billing-svc": 12}
  },
  "handles": [
    {"id": "ep-001", "path": "POST /transfer",    "repo": "wallet-api", "auth": "jwt"},
    {"id": "ep-002", "path": "GET  /admin/users", "repo": "wallet-api", "auth": "none"},
    ...
  ],
  "fetch_hint": "Call lacuna-recon.endpoint_detail(id='ep-002') for full handler trace."
}
```

The agent reads the summary, picks one or two handles to drill into, and only then pays the context cost of the detail call. Compare to a naive design that returns 47 handler bodies — that's the ~50KB-of-tool-output anti-pattern.

The principle: **every tool answers two questions: "what is here?" and "what should I look at next?" — never "here's everything."**

---

## Part 5 — Semantic over syntactic: where this lives in the context

The Mythos "semantic over syntactic" claim has a clean architectural reading: **shape-of-bug knowledge belongs in the model's context (as skills/prompts), while pattern-of-code knowledge belongs outside it (as deterministic tools).**

Concretely:

- **In context (Tier 1, skill):** *"A trust-boundary smuggling bug exists when untrusted input reaches a sink that assumes a validated boundary was crossed. The semantic shape is: source → (unenforced boundary) → sink. The boundary may be syntactically present (e.g. a `validate()` call) but not actually enforcing the property the sink assumes."*

- **Out of context (deterministic tool):** A tree-sitter query that finds all call sites of `subprocess.run` with non-literal first arguments. This is the syntactic part. It runs outside the LLM and returns handles.

The agent's job is to ask the *semantic* question: *"Given the syntactic facts the tools just gave me, do any of them match the shape of a trust-boundary smuggling bug in this application?"* The shape lives in the skill; the facts come from tools; the matching happens in working memory.

This is why semgrep alone is not a Lacuna replacement. Semgrep is the syntactic substrate. The semantic reasoning — *does this pattern, in this application, with these data flows, actually constitute a bug?* — requires the LLM and a coherent context.

A representative semantic shape from the `semantic-pattern-matching` skill:

```markdown
## Shape: Cross-service authentication confusion

A request flows: client → service A → service B.
Service B accepts a header (e.g. `X-User-Id`, `X-Roles`) that service A sets
based on its own authentication of the client. The bug exists when:

1. The header is treated as authoritative by service B's authorization layer, AND
2. Service B is reachable from any network position that bypasses service A
   (direct VPC access, sidecar, internal service mesh, etc.), AND
3. Service A does not strip incoming copies of the header before adding its own.

The bug is *not* visible in either service in isolation. Hunting it requires
holding the cross-service call (from `cross_repo_calls`), the receiving
auth surface (from `auth_surface` on service B), and the network reachability
(from `iac_scan`) in mind simultaneously.

Refutation patterns:
- Service B requires mTLS and rejects non-mesh connections → refuted.
- Service A strips the header before forwarding → refuted.
- The header is signed/HMAC'd with a key only A knows → refuted.

Confirmation pattern:
- Find any path from "user-reachable code" to "issuing a request to B's
  internal address" — if it exists, the bug exists.
```

The skill never names a CWE. It describes a *shape*. The hunter agent reads the skill, queries the tools for the syntactic facts, and matches.

---

## Part 6 — Choreography of the validator's red/blue dialectic

The validator is the most context-intensive single agent in the system, because it must hold both attack and defense reasoning simultaneously. Its context discipline is therefore the most explicit.

**Validator context budget at spawn:**

| Tier | Content | Tokens |
|---|---|---|
| 1 | System prompt + `red-blue-dialectic` skill + `caveman` | ~4K |
| 2 | Hypothesis to validate (full text) + application_model summary | ~2K |
| 2 | Allowed tools list + KG status | ~1K |
| 3 | Working scratch (the dialectic itself) | ~remainder |

The dialectic is bounded by **rounds, not tokens**:

```
Round 1 — RED (attack)
  Tool calls: pull relevant code, trace data flow, draft PoC
  Output: <red-argument round="1"> ... </red-argument>

Round 1 — BLUE (defense)
  Tool calls: look for sanitizers, framework defenses, type coercions
  Output: <blue-argument round="1"> ... </blue-argument>

Round 1 — RECONCILE
  Output: <reconciliation round="1" verdict="continue|confirm|refute">
            <unresolved>...</unresolved>
          </reconciliation>

... repeat to round N (default 4) ...

Final
  If confirmed:
    <hypothesis-result status="confirmed">
      <evidence>...</evidence>
      <primitive-draft>...</primitive-draft>   ← PreCompact hook catches this
    </hypothesis-result>
  If refuted:
    <hypothesis-result status="refuted">
      <reasoning>...</reasoning>
    </hypothesis-result>
  If unresolved at max rounds:
    <hypothesis-result status="needs_human_review">
      <best_red_argument>...</best_red_argument>
      <best_blue_argument>...</best_blue_argument>
    </hypothesis-result>
```

**Critical detail:** after each round, the validator emits a `<round-summary>` block and is instructed by the skill to drop the round's detailed reasoning from active attention going into the next round. The summary survives; the reasoning is allowed to compact away. By round 4, the validator is reasoning over four ~200-token summaries plus the current round's working memory — not over 16K tokens of accumulated argument.

This is the in-skill version of context editing: the agent itself is taught to summarize-then-forget.

---

## Part 7 — The chain-builder's pure-primitive context

The chain-builder is the architectural showcase. It produces the highest-value output (composed exploit chains) while having the smallest, cleanest context window in the entire system.

**The chain-builder never sees code.** Its context contains:

- Tier 1: System prompt + `chain-construction` skill (~3K tokens)
- Tier 2: Application model summary (~1K) + service map (~1K)
- Tier 2: The primitive ledger — just IDs, names, prerequisites, effects (~2-5K depending on count)
- Tier 3: Working scratch — graph search reasoning

That's it. No code excerpts. No raw tool output. No HTTP traces. Just the abstracted *capabilities* (primitives) and the question: *can any sequence of these capabilities reach a high-impact goal?*

This is possible because the primitive abstraction is *the* abstraction layer. Once a finding is reduced to a primitive (via the `primitive-extraction` skill), the code reality is gone — what's left is "attacker can do X given Y, yielding Z." Chain composition is then a small graph search.

```python
# Pseudocode for the chain-builder's reasoning loop
def explore_chains(primitives, goals):
    for goal in goals:                                # e.g. 'rce', 'data-exfil'
        frontier = [p for p in primitives if satisfies(p.effects, goal)]
        for target in frontier:
            chain = [target]
            unmet = target.prerequisites - {"any_authenticated_user"}
            while unmet:
                supplier = find_primitive_satisfying(primitives, unmet)
                if not supplier:
                    break                              # dead end, try next
                chain.insert(0, supplier)
                unmet = (supplier.prerequisites | unmet) - supplier.effects
            if not unmet:
                yield Chain(primitives=chain, goal=goal, ...)
```

The agent's job is the soft-edge version of this: assess plausibility of prerequisite-to-effect matches, detect when two "different" primitives are really the same capability under different names, write the human-readable narrative. The skill provides the structure; the KG provides the data; the LLM provides the judgment about whether a chain is *plausible*, not just graph-reachable.

**Why this fits in a small context:** the entire primitive ledger for a large multi-repo application is unlikely to exceed 100 primitives, even at exhaustive scan depth. At ~50 tokens per primitive summary, that's a 5K-token problem. Chain composition is small data + hard reasoning — the right shape for an LLM.

---

## Part 8 — A walked example: 4-hour scan, three compactions

Concrete trace through what's in context at different points of a long scan.

**Hour 0 (scan starts).** Context: CLAUDE.md (4K) + manifest summary (1K) + KG status: "empty, recon not started" (200 tokens). ~5K used. Orchestrator spawns recon subagent. Recon runs for 8 minutes, burning ~40K tokens internally across many recon tool calls, returns a 1.5K-token application model summary. Orchestrator context: still ~5K used. **Recon's verbose work is gone from the orchestrator's context entirely — that's subagent isolation doing context editing for free.**

**Hour 1 (mid Phase 2).** Orchestrator has spawned five hunters in parallel. Each is operating in its own context. Three have returned, two are running. KG now has 23 hypotheses. Orchestrator context: CLAUDE.md (4K) + application_model (1K) + KG status: "23 hypotheses pending, 5 hunters: 3 returned, 2 running" (500 tokens) + working scratch as it considers which validators to spawn first (~10K). **~15K used.** Well under any compaction trigger.

**Hour 2 (mid Phase 3, first compaction).** Orchestrator has been validating findings; some hypotheses confirmed, some refuted. Working scratch has grown to ~80K tokens — lots of tool calls, lots of reasoning, lots of partially-explored tangents. The 70%-of-window trigger fires.

- PreCompact hook runs: scans transcript, extracts 4 in-flight `<hypothesis-draft>` blocks, 2 `<primitive-draft>` blocks (from the validator), 1 `<next-actions>` block. All persisted to KG.
- Compaction prompt (Lacuna-customized) summarizes the transcript: ~80K → ~6K. Preserves "currently validating hyp-c4d2, red argument established, awaiting blue."
- Tool result clearing strips the 12 tool results that contributed most to the bloat — file excerpts the validator already drew its conclusion from.
- Post-compaction context: CLAUDE.md (4K) + application_model (1K) + compacted transcript (6K) + KG status (1K) = ~12K used.
- Orchestrator continues. It re-reads `kg.read.hypotheses(status='validating')` to confirm hyp-c4d2 is still its focus. The KG says yes. It proceeds.

**Hour 3 (second compaction, chain explosion).** Chain-builder has been running concurrently, has produced 7 chains. One chain involves a primitive the orchestrator hadn't seen yet. The orchestrator pulls it from the KG (not from any old transcript — the KG is canonical) and works it into its next validator spawn (validate the chain end-to-end with DAST since this scan is sast+dast mode).

**Hour 4 (Phase 4, report generation).** Exit criteria met. Orchestrator invokes `report-exec` skill, which reads exclusively from the KG and writes the executive report. Then `report-tech`, same pattern. The reports do not depend on any single transcript surviving — they're a projection over Tier 5.

**The point of the walk:** at no point does the orchestrator's working window exceed ~80K tokens, even though the cumulative reasoning across the scan exceeds several million. The work scales horizontally (subagents) and durably (KG); the active attention budget stays bounded.

---

## Part 9 — Failure modes and recovery

A context strategy is only as good as its failure modes. Six to plan for.

### 9.1 Compaction loses something critical despite the hook
*Symptom:* orchestrator after compaction proceeds in a way that contradicts an earlier reasoned decision.
*Defense:* every decision the orchestrator makes is recorded in `event_log` with a `decision_rationale` event type. The `Stop` hook periodically samples decisions for self-consistency and re-injects rationale if drift is detected.
*Recovery:* the orchestrator's first action after compaction is always a `kg.read.application_model` + `kg.status.exit_criteria` + `event_log.recent_decisions(n=5)`. These three reads ground it.

### 9.2 Subagent stops prematurely
*Symptom:* `SubagentStop` fires but the agent didn't write its expected output (e.g. recon stopped without `application_model_ready`).
*Defense:* SubagentStop hook validates output presence in KG. If missing, returns `{"decision": "block", "reason": "must produce X before stopping"}`.
*Recovery:* up to 2 retries with progressively more directive prompting; after that, the parent agent is informed and decides how to proceed (often: spawn a different specialist, or escalate to human review).

### 9.3 KG inconsistency (concurrent subagents)
*Symptom:* two hunters write near-duplicate hypotheses; chain-builder counts both.
*Defense:* `kg.write.hypothesis` includes a fuzzy-match dedup pass on shape+repo+file±5 lines. Duplicates are merged with `seen_by` accumulated.
*Recovery:* the dedup runs continuously, not just at write time.

### 9.4 Agent oscillation
*Symptom:* an agent keeps re-hypothesizing the same shape on the same file, refuting itself, re-hypothesizing.
*Defense:* `event_log` pattern detector in the `Stop` hook. If an agent has produced ≥3 hypotheses with the same `(shape, repo, file)` triple, the next attempt is blocked and the agent is forced to read its own refuted-hypotheses list.
*Recovery:* the refuted-hypotheses file in the memory tool is the agent's "I already tried this" memory.

### 9.5 Tool result floods context
*Symptom:* an agent calls a tool that returns 50K tokens of output, blowing the budget.
*Defense:* MCP tool wrapper in the harness intercepts every tool result > 10K tokens, stores the full payload to `/state/tool_results/{hash}.json`, and returns a stub: `{"summary": "...", "payload_ref": "/state/tool_results/{hash}.json", "preview": "first 500 tokens..."}`. The agent must explicitly call `lacuna-recon.fetch_payload(hash, page)` to get more.
*Recovery:* this is preventive — the wrapper enforces the just-in-time pattern even on tools that violate it.

### 9.6 Chain search explosion
*Symptom:* chain-builder finds 200 chains, most low-value variants of a few core attack paths.
*Defense:* chain dedup based on `(set of primitive_ids, goal)`. Plus a similarity score: chains with ≥80% primitive overlap are merged with the highest-impact narrative kept.
*Recovery:* in the report, only top-K chains per goal are highlighted; the rest go to an appendix.

---

## Part 10 — Lifecycle of one hypothesis

Pulling everything together with one finding's complete journey. This is the canonical trace.

**Birth (Phase 2, in `hunter-cross-service`)**
The hunter reads `service_map` and notices `billing-svc` exposes a `/internal/refund` endpoint with no authentication. It reads `iac_scan` and sees billing-svc has a NodePort exposing it on the cluster network. It reads `endpoints` on `wallet-api` and finds a `POST /webhook` handler that takes a `callback_url` parameter and issues an HTTP request to it. It writes:

```
<hypothesis-draft>
{
  "shape": "cross-service-trust-via-network-position",
  "repo": "billing-svc",
  "file": "internal/refund/handler.go",
  "line": 23,
  "description": "billing-svc /internal/refund is unauthenticated and reachable from inside the cluster network. wallet-api /webhook accepts an arbitrary callback_url and issues a request from its pod, which is inside the cluster. Net: any authenticated wallet user can issue arbitrary refund requests by pointing the webhook at the billing internal endpoint.",
  "attacker_scenario": "1. Auth as any wallet user. 2. POST /webhook with callback_url=http://billing-svc.internal/internal/refund and a crafted body. 3. wallet-api issues the refund call from its pod.",
  "confidence": 0.6
}
</hypothesis-draft>
```

The hunter returns to the orchestrator with a 1.5K-token summary listing 8 hypothesis IDs (including this one). The orchestrator's context never holds the hunter's verbose investigation.

**Promotion to validation (Orchestrator → Validator spawn)**
Orchestrator sees the new hypothesis via `kg.read.hypotheses(status='pending', min_confidence=0.5)`. It spawns a `validator` subagent with input contract: validate hyp-7f2a1c. The validator's context is fresh: skill + hypothesis + tool access.

**Validation (Validator, 3 rounds)**

- *Round 1 RED:* "If wallet-api's HTTP client doesn't restrict URL schemes or destinations, this works. Pull the webhook handler code." Tool: `code_excerpt(wallet-api, src/webhook.py, 40, 80)`. Reads the handler. No SSRF protection. Writes `<red-argument round="1">`: attack viable, drafts PoC curl.
- *Round 1 BLUE:* "What about billing-svc rejecting requests not from the wallet service account? Pull billing's auth surface." Tool: `auth_surface(billing-svc)`. Confirms /internal/* paths have no auth middleware. "What about mTLS in the mesh?" Tool: `iac_scan(billing-svc)`. Confirms NodePort exposed without mTLS enforcement. Writes `<blue-argument round="1">`: no defense found. The hypothesis survives.
- *Round 1 RECONCILE:* "Both arguments converge — attack is viable. Proceeding to PoC validation."
- *Round 2 PoC:* In DAST mode, validator calls `dast.auth_login()` to get a session, then `dast.http_request(POST /webhook, {callback_url: 'http://billing-svc.internal:8080/internal/refund', body: ...})`, then checks billing-svc logs via a probe endpoint. The refund posts. Writes evidence to KG.

**Confirmation and primitive extraction (Validator)**

```
<hypothesis-result status="confirmed" id="hyp-7f2a1c">
  <evidence>
    <kind>http_trace</kind>
    <path>/state/evidence/hyp-7f2a1c/refund-poc.http</path>
  </evidence>
  <primitive-draft>
    {
      "name": "ssrf-to-internal-refund-via-wallet-webhook",
      "description": "Any authenticated wallet user can cause wallet-api's pod to issue arbitrary HTTP requests inside the cluster network via the /webhook endpoint, including to billing-svc's unauthenticated /internal/refund endpoint.",
      "prerequisites": ["any_authenticated_wallet_user"],
      "effects": ["arbitrary_internal_http_request_from_wallet_pod", "uncapped_refund_creation"],
      "repos_involved": ["wallet-api", "billing-svc"]
    }
  </primitive-draft>
</hypothesis-result>
```

Validator returns a 1.2K-token summary to the orchestrator. The orchestrator's context grows by 1.2K. The validator's 30K-token investigation does not propagate.

**Chain composition (Chain-builder, asynchronously)**
The chain-builder has been polling the primitive ledger. The new primitive arrives. It searches for chains. It already has a primitive: `refund_creation_uncapped_by_account_status` (from an earlier billing-svc bug — billing trusts incoming refund requests blindly). Composition:

```
1. ssrf-to-internal-refund-via-wallet-webhook
   prereqs: authenticated wallet user
   effects: uncapped_refund_creation
2. refund_creation_uncapped_by_account_status
   prereqs: ability_to_issue_refund
   effects: financial_loss_unbounded
→ Chain: any authenticated user can cause unbounded financial loss.
Goal: financial-loss. Combined severity: CRITICAL.
```

Chain written to KG.

**Death-by-promotion (Phase 4, report generation)**
The hypothesis is now: a confirmed finding (`fnd-...`), a primitive (`prim-...`), and a participant in a critical chain. All three are entities in the KG. The `report-exec` skill picks up the chain as one of its critical narratives:

> *"A logged-in customer can trigger refunds at will. Because the wallet service's webhook accepts arbitrary destinations and the billing service trusts requests from inside the cluster, a single API call from any authenticated user can force arbitrary refunds to be created..."*

The `report-tech` skill picks up the finding with its evidence path, the primitive with its prerequisites, and the chain with its step-by-step narrative.

**Total context cost to the orchestrator across this lifecycle:** roughly 3K tokens (hunter summary 1.5K + validator summary 1.2K + chain notification 300). Total tokens *generated* across the lifecycle by all agents: probably 80-120K. The ratio — generated to retained — is the entire point of the architecture.

---

## Part 11 — Putting it in the Lacuna repo (concrete file map)

Where each mechanism lives, in the repo layout from the main architecture doc:

```
.claude/
├── settings.json                     ← compaction prompt, tool-result-clearing config
├── CLAUDE.md                          ← Tier-1 system prompt
├── agents/
│   ├── recon.md
│   ├── hunter-*.md                    ← each with contract.yaml sibling
│   ├── validator.md                   ← red/blue dialectic skill loaded
│   └── chain-builder.md               ← chain-construction skill loaded
├── skills/
│   ├── caveman/SKILL.md     ← style + depth override
│   ├── semantic-pattern-matching/     ← shapes-of-bugs library
│   │   ├── SKILL.md
│   │   └── shapes/
│   │       ├── trust-boundary-smuggling.md
│   │       ├── cross-service-trust-confusion.md
│   │       ├── auth-drift.md
│   │       └── ...
│   ├── red-blue-dialectic/SKILL.md    ← round structure + summary-then-forget
│   ├── chain-construction/SKILL.md    ← primitive-graph search heuristics
│   ├── primitive-extraction/SKILL.md  ← finding → primitive distillation
│   └── ...
└── hooks/
    ├── session_start.py
    ├── user_prompt_submit_inject_status.py
    ├── pre_tool_use_gate.py
    ├── post_tool_use_record.py
    ├── pre_compact_flush.py           ← the KG flush hook (Part 4.2)
    ├── subagent_stop_validate.py
    └── stop_continuation.py

src/lacuna/
├── kg/
│   ├── schema.sql                    ← event_log, hypotheses, findings, primitives, chains, refuted, agent_notes
│   ├── client.py
│   └── memory_adapter.py             ← exposes KG as memory-tool file interface (Part 4.4)
├── tools/
│   ├── recon_server.py               ← summary+facets+handles tool result shape (Part 4.6)
│   ├── recon_payload_cache.py        ← /state/tool_results/ off-context payload store (Part 9.5)
│   ├── kg_server.py
│   └── dast_server.py
└── harness/
    ├── subagent_spawn.py             ← enforces input/output contracts (Part 4.5)
    └── api_client.py                 ← injects context_management on every API call (Part 4.3)
```

---

## Part 12 — Test plan for the context strategy

You'll want to verify the context strategy actually works before trusting it on real scans. Three deliberate stress tests:

### Test A — Compaction survival
Set up a scan with a synthetic application designed to produce ≥150 hypotheses. Run with compaction trigger at 50% (forcing many compactions). Verify: every confirmed finding has an unbroken trace in the event log; no orchestrator decision contradicts a prior KG state; final report matches what would be produced from KG alone.

### Test B — Subagent budget enforcement
Spawn a hunter against a deliberately massive repo (Linux kernel slice, say) and verify the hunter cannot return more than 2K tokens to the parent regardless of its internal exploration. Verify the truncation triggers a clean re-summarize, not a crash.

### Test C — Chain-builder context isolation
Run the chain-builder in standalone mode against a hand-seeded KG of 50 primitives. Verify it produces correct chains without ever calling a recon tool — its context should contain zero code.

If A, B, C pass, the context architecture is sound.

---

## Part 13 — Five reasons this is Mythos-shaped, not Snyk-shaped

Pulling out the distillation:

1. **Working memory is bounded; durable memory is not.** Every agent operates within a small attention budget at any moment. The KG holds everything. This is the inverse of "load the whole codebase into a huge window" — that approach hits context rot at scale.

2. **Subagent isolation is context editing on autopilot.** You don't need a clever forgetting heuristic when the verbose work happens in a sibling process that returns a summary.

3. **The KG is the agent's identity across compactions.** When the transcript is summarized, the orchestrator does not become a slightly-different orchestrator. It rereads the KG and is the same orchestrator with the same goals.

4. **Primitives are the abstraction layer that makes chaining tractable.** Once a finding is reduced to a primitive, code is gone. Chain reasoning happens over a small, dense representation — exactly the kind of small-data-hard-reasoning problem LLMs excel at.

5. **The Stop hook + exit criteria are the iterative loop.** Iteration is not a model property; it's a system property. Mythos's "recursive self-correction" is what happens when the system refuses to let the model declare victory until objective criteria are met.

These five together are what makes Lacuna an autonomous scanner rather than an LLM that happens to read code.
