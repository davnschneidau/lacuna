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

*Generated by Lacuna v{{ version }}. Source: `{{ kg_path }}`.*
