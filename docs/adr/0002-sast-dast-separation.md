# ADR-0002 — SAST and DAST must be physically separated

**Status.** Accepted.

**Date.** 2026-05-16.

**Deciders.** lacuna-maintainers.

## Context

Historically the harness unconditionally registered the
`lacuna-dast` MCP server regardless of `LACUNA_MODE`. The PreToolUse
hook refused DAST tool calls in `LACUNA_MODE=sast`, but only after
the agent had already wasted context tokens deciding to make the
call. Worse, the literal-string check in the hook missed
`LACUNA_MODE=diff`, leaving diff-mode scans silently DAST-enabled.

We split the single `LACUNA_MODE` string into two orthogonal axes
(kind and scope) so the gates can be enforced uniformly at every
layer.

## Decision

Lacuna will model the scan shape as the orthogonal pair
`(scan_kind, scan_scope)` where:

- `scan_kind ∈ {sast, sast_dast}` determines which MCP servers are
  registered and which agents are recruited.
- `scan_scope ∈ {full, diff}` determines which files are in-bounds.

Separation is enforced at four layers, each independently sufficient:

1. **MCP wiring.** `_write_mcp_config` omits `lacuna-dast` when
   `scan_kind=sast`.
2. **PreSessionValidate hook.** Refuses to start the scan if
   `.mcp.json` disagrees with `scan_kind`, or if a DAST scan lacks
   `scan.dast.target.allowed_hosts`.
3. **PreToolUse hook.** Refuses DAST tool calls when
   `scan_kind=sast` (covers `diff` mode too).
4. **DAST server kind-guard.** Refuses every tool call when the
   surrounding scan is SAST-only.

Backward compatibility: `lacuna.kind.parse_legacy_mode` translates
the legacy `LACUNA_MODE` strings to `(kind, scope)` pairs.

## Consequences

**We gain.** A canonical answer to "is this a DAST scan?" lives in
one place (`lacuna.kind`). Tests can pin separation invariants. The
PreSessionValidate hook turns misconfiguration into a startup-time
failure rather than a runtime token waste.

**We give up.** Single-knob simplicity: operators have to think
about kind and scope separately. The CLI keeps the legacy `--mode`
flag for back-compat; we document the new env vars
(`LACUNA_SCAN_KIND`, `LACUNA_SCAN_SCOPE`) as the preferred surface.

**Becomes harder.** Future kinds (e.g. `dast_only`, `iast`) need a
matching entry in `_LEGACY_MAP` and reasoning about the topology
file. The KGProtocol surface stays small.

## Enforcement

- `tests/test_kind_taxonomy.py`
- `tests/test_sast_dast_separation.py`
- `scripts/lint_topology.py`
- `lacuna.hooks.pre_session_validate`
- `lacuna.tools.dast_server._kind_guard`

## Reversibility

Medium. The kind enum lives in one module; collapsing back to a
single string would require touching the four enforcement layers
above plus the manifests. Not contemplated.
