# Lacuna Technical Report: {{ app_name }}

**Scan Date:** {{ scan_date }}  
**Mode:** {{ scan_mode }}  
**Duration:** {{ scan_duration }}  
**Manifest:** `{{ manifest_path }}`

---

## Application Model

{{ application_model_summary }}

## Scan Statistics

| Metric | Value |
|--------|-------|
| Repos scanned             | {{ repo_count }} |
| Hypotheses formed         | {{ hyp_total }} |
| Hypotheses confirmed      | {{ hyp_confirmed }} |
| Hypotheses refuted        | {{ hyp_refuted }} |
| Hypotheses needing review | {{ hyp_needs_human }} |
| Findings (Critical)       | {{ critical_count }} |
| Findings (High)           | {{ high_count }} |
| Findings (Medium)         | {{ medium_count }} |
| Findings (Low)            | {{ low_count }} |
| Primitives identified     | {{ primitive_count }} |
| Chains composed           | {{ chain_count }} |

---

## Findings

{% for finding in findings %}
### {{ finding.title }}

**ID:** `{{ finding.id }}`  
**Severity:** **{{ finding.severity|upper }}**  
**CVSS:** `{{ finding.cvss_vector or "-" }}`  
**CWEs:** {{ finding.cwes or "-" }}  
**Affected repos:** {{ finding.repos_involved }}  
**Source hypothesis:** `{{ finding.hypothesis_id }}`

#### Validator summary

{{ finding.validator_summary }}

#### Evidence

{% if finding.evidence %}
{% for e in finding.evidence %}
- **{{ e.kind }}** — `{{ e.payload_path }}`
{% endfor %}
{% else %}
*(no evidence files attached)*
{% endif %}

#### Remediation

{{ finding.remediation_md or "*Not provided by validator.*" }}

---
{% endfor %}

## Attacker Primitives

The following primitives were derived from confirmed findings. Each
represents a capability available to an attacker, with prerequisites and
effects:

{% for p in primitives %}
### {{ p.name }} (`{{ p.id }}`)

{{ p.description }}

- **Prerequisites:** {{ p.prerequisites|join(", ") or "none" }}
- **Effects:** {{ p.effects|join(", ") or "none" }}
- **Repos involved:** {{ p.repos_involved|join(", ") or "-" }}
- **Source finding:** `{{ p.finding_id }}`

---
{% endfor %}

## Attack Chains

{% if chains %}
{% for c in chains %}
### Chain `{{ c.id }}` → {{ c.goal }}

**Combined severity:** {{ c.combined_severity }}  
**Primitives (in order):** {{ c.primitive_ids|join(" → ") }}

{{ c.narrative_md }}

---
{% endfor %}
{% else %}
*No multi-step chains were composed.*
{% endif %}

## Refuted Hypotheses (audit trail)

The validator considered and refuted the following hypotheses. They are
included for traceability — if a future scan or a human reviewer believes
any of these were dismissed in error, the validator's reasoning is here.

{% for h in refuted %}
### `{{ h.id }}` ({{ h.shape }}) — by {{ h.hunter }}

**Location:** `{{ h.repo }}:{{ h.file }}:{{ h.line }}`  
**Hunter's confidence:** {{ h.confidence }}

> {{ h.description }}

**Refutation:** {{ h.refutation_reason }}

---
{% endfor %}

## Out-of-scope / Needs Human Review

{% if needs_human %}
The following hypotheses could not be conclusively confirmed or refuted by
the validator and need a human reviewer:

{% for h in needs_human %}
- `{{ h.id }}` ({{ h.shape }}) at `{{ h.repo }}:{{ h.file }}:{{ h.line }}` — {{ h.description }}
{% endfor %}
{% else %}
*No hypotheses were left needing human review.*
{% endif %}

---

## Coverage Gaps (We Did Not Examine)

Negative space is information. The following surfaces were NOT examined,
and why. If any of these are in your threat model, request a follow-up
scan that addresses them.

{% if coverage_gaps %}
| Surface | Reason | Suggested action |
|---|---|---|
{% for g in coverage_gaps %}
| {{ g.surface }} | {{ g.reason }} | {{ g.suggested_action or "-" }} |
{% endfor %}
{% else %}
*No coverage gaps recorded. (Either coverage was complete, or the agents
forgot to record gaps — review with skepticism.)*
{% endif %}

---

## Trust Shadow (Capability Graph)

The trust-shadow-analyzer enumerates assets (keys, secrets, tokens, IAM
roles), their holders, and the trust edges between repos.

{% if trust_shadow_summary %}
{{ trust_shadow_summary }}
{% endif %}

{% if cross_repo_trust_paths %}
### Cross-repo trust paths

| From | Relationship | To holder | Asset |
|---|---|---|---|
{% for p in cross_repo_trust_paths %}
| `{{ p.from_repo }}` | {{ p.relationship }} | `{{ p.to_holder }}` | `{{ p.asset }}` |
{% endfor %}
{% endif %}

{% if trust_holes %}
### Identified trust holes

{% for hole in trust_holes %}
- **{{ hole.summary }}** — affects shapes: {{ hole.affects_shapes }}
{% endfor %}
{% else %}
*No trust holes recorded by the analyzer.*
{% endif %}

---

## Weird Compositions

Compositions of primitives whose combined behavior enables unintended
computation. Drawn from the `weird-machine` skill.

{% if weird_compositions %}
{% for w in weird_compositions %}
- **{{ w.unintended_use }}** (enables: {{ w.enables_goal or "—" }}; confidence: {{ w.confidence }})
  - Primitives: {{ w.primitive_ids }}
  - Intended uses: {{ w.intended_use or "—" }}
{% endfor %}
{% else %}
*No weird compositions recorded.*
{% endif %}

---

## Skeptic Reviews

The skeptic agent re-reviewed every confirmed medium+ finding. Reviews
that did NOT confirm the validator's verdict are highlighted below.

{% if skeptic_reviews %}
| Finding | Verdict | Notes |
|---|---|---|
{% for r in skeptic_reviews %}
| `{{ r.finding_id }}` | {{ r.verdict }} | {{ r.notes or "—" }} |
{% endfor %}
{% else %}
*No skeptic reviews recorded for this scan.*
{% endif %}

---

## Cross-Hunter Observations

Non-hypothesis facts published to the shared board, useful for follow-up.

{% if observations %}
| Kind | Summary | Affects |
|---|---|---|
{% for o in observations %}
| {{ o.kind }} | {{ o.summary }} | {{ o.affects_shapes }} |
{% endfor %}
{% else %}
*No observations recorded.*
{% endif %}

---

## Variant Clusters (v3)

When a finding is confirmed, the variant-hunter searches the codebase for
sibling instances of the same bug pattern. Variants of the same parent
finding are grouped together; the parent is the originally-confirmed
finding, each child is a likely instance of the same bug at a different
site.

{% if variant_clusters %}
{% for cluster in variant_clusters %}
### Cluster: parent `{{ cluster.parent_finding_id }}` ({{ cluster.cwe }})

**Parent:** `{{ cluster.parent_title }}` at `{{ cluster.parent_location }}`

**Children ({{ cluster.children | length }}):**
{% for c in cluster.children %}
- `{{ c.hyp_id }}` at `{{ c.location }}` — verdict: {{ c.verdict or "pending" }}
{% endfor %}
{% endfor %}
{% else %}
*No variant clusters formed this scan.*
{% endif %}

---

## Crash Reproductions (v3)

For findings confirmed via libFuzzer, the crashing input and ASan report
are reproducible artifacts. The minimized input is the proof of concept.

{% if crash_reproductions %}
{% for c in crash_reproductions %}
### `{{ c.finding_id }}` — {{ c.asan_kind }}

- **Function:** `{{ c.function_qual }}`
- **Fuzz run:** {{ c.fuzz_run_id }} ({{ c.executions or "?" }} executions, {{ c.duration_s }}s)
- **Minimized input:** `{{ c.minimized_input_path or c.input_path }}`
- **ASan report:** `{{ c.asan_log_path }}`

Top crash frames:
```
{% for frame in c.crash_stack %}{{ frame }}
{% endfor %}
```
{% endfor %}
{% else %}
*No fuzz-confirmed findings this scan.*
{% endif %}

---

## Incomplete-Fix Findings (v3)

Findings filed by `patch-archaeologist`: sites where a historical fix
addressed one manifestation of a bug class but variants survive in the
codebase. The parent commit SHA is cited as evidence of the bug class.

{% if incomplete_fixes %}
| Hypothesis | File:line | Parent commit | Bug class | Verdict |
|---|---|---|---|---|
{% for f in incomplete_fixes %}
| `{{ f.hyp_id }}` | `{{ f.location }}` | `{{ f.parent_commit_short }}` | {{ f.bug_class }} | {{ f.verdict or "pending" }} |
{% endfor %}
{% else %}
*No incomplete-fix findings this scan.*
{% endif %}

---

## Precision Findings (v3, Layer 2)

High-quality static-analysis leads from `integer_range`, `lifetime`,
`format_string`, `type_confusion`, and `allocator_map`. Hunters convert
these into hypotheses; the listing here shows the underlying signal.

{% if precision_findings_summary %}
| Kind | CWE | Count | Consumed by hunters |
|---|---|---|---|
{% for row in precision_findings_summary %}
| {{ row.kind }} | {{ row.cwe }} | {{ row.count }} | {{ row.consumed }} / {{ row.count }} |
{% endfor %}
{% else %}
*No precision findings recorded.*
{% endif %}

---

*Generated by Lacuna v{{ version }}. Source: `{{ kg_path }}`.*
