---
name: kickoff
description: Begin a Lacuna scan from the orchestrator's perspective. Reads the manifest, starts recon, transitions through phases until reports are written.
---

# /kickoff

Initiate the scan. The orchestrator should:

1. Confirm the manifest path resolves (env: `LACUNA_MANIFEST_RESOLVED`).
2. `kg.write.set_phase(phase="phase-1-recon")`.
3. Spawn the `recon` subagent.
4. Once `application_model_ready` exit criterion is met, proceed to phase 2.
5. Spawn hunters in parallel (subject to `LACUNA_MAX_PARALLEL_SUBAGENTS`).
6. As each hypothesis crosses confidence ≥ 0.3, spawn validator instances.
7. Once `all_hypotheses_resolved`, spawn `chain-builder`.
8. Once `chain_search_exhausted`, run `python3 -m lacuna report` (or use the
   report-exec/report-tech skills to compose them directly).
9. Set `reports_generated`. Stop hook will then allow exit.

Don't deviate from this flow without a stated reason logged via `kg.write.event`.
