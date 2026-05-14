---
name: force-chain-search
description: Re-run the chain-builder against the current primitive set. For when new primitives have been added since the last chain search.
---

# /force-chain-search

Spawn a fresh `chain-builder` subagent. Useful when validators have
produced new primitives that the previous chain search didn't see.

Procedure:
1. `kg.read.primitives` — confirm the unexplored count.
2. Set `chain_search_exhausted` back to false:
   `kg.write.set_exit_criterion(name="chain_search_exhausted", met=False, reason="rerun")`.
3. Spawn `chain-builder` agent.
4. After it finishes, the criterion will be re-set to true by the agent.
