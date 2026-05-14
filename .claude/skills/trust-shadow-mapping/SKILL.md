---
name: trust-shadow-mapping
description: Procedure for building the application's capability graph — who holds which secrets/keys/roles, who trusts them, and which cross-boundary edges are holes. Use when running the trust-shadow-analyzer agent or whenever a finding touches authentication, signing, or service-to-service trust.
---

# Trust-shadow mapping

The capability graph answers a question hunter-authn-authz doesn't:
> **Given that every check IS present and every signature IS verified, does
> the resulting trust topology have holes?**

This is a different question from "is the auth code buggy." Many real-world
breaches happen with no auth bugs — just trust topologies that allowed a
low-privileged thing to act with high privilege.

## Definitions

- **Asset**: a credential, key, secret, token, role. Examples:
  `JWT_HS256_KEY`, `STRIPE_API_KEY`, `db_root_password`,
  `arn:aws:iam::...:role/admin`.
- **Holder**: the repo/service that has read access to the asset.
- **Grant**: what an asset enables. ("sign:user_token",
  "read:user_pii_table", "assume:admin_role").
- **Trust edge**: a `from_repo` `relationship` `to_capability` arc.
  - `reads`: the from_repo can read the asset directly.
  - `uses`: the from_repo invokes operations gated by the asset.
  - `trusts`: the from_repo validates signatures/tokens issued by holder.
  - `signs_for`: the from_repo issues credentials on behalf of holder.
  - `inherits`: the from_repo runs as a principal with the asset's grants.

## Procedure

### Step 1 — enumerate holders

For each repo:
- Run `secret_scan` to find hardcoded or env-var secrets.
- Read deployment configs (`.env`, `helm/values.yaml`, `terraform/`).
- Look for `os.environ`, `process.env`, `System.getenv` patterns.

For each finding:
- Classify the asset_kind (`token_signing_key`, `api_key`,
  `database_credential`, `iam_role`, etc.).
- Note the holder repo.
- Note what it grants — read the code where it's used. JWT signed with it?
  Database connected with it? S3 client instantiated with it?

Write `kg.write.capability` for each verified asset.

### Step 2 — enumerate trust edges

For each repo:
- Find signing operations (`jwt.encode`, `hmac.new`, etc.) — these are
  `from_repo signs_with <asset>` edges.
- Find verifying operations (`jwt.decode`, `hmac.compare_digest`,
  `public_key.verify`) — these are `from_repo trusts <asset>` edges.
- Find IAM role assumption — `from_repo assumes <role>` edges.
- Find inter-service calls (`cross_repo_calls` output). Note whether they
  authenticate at all. If not, it's an `implicit_trust` edge.

Write `kg.write.capability_edge` for each.

### Step 3 — find the holes

For each `trusts` edge, ask:
1. **Boundary check**: is `from_repo` in the same trust boundary as the
   `to_capability`'s holder, per the manifest's threat model? If not,
   you've found a cross-boundary trust path. That's an observation to
   write.

2. **Compromise propagation**: if `from_repo` is compromised, what
   capabilities can the attacker now use?
   - If from_repo holds keys it signs with, attacker can mint tokens.
   - If from_repo runs as an IAM principal, attacker has those grants.
   - If from_repo is trusted by anyone, attacker can forge "from" that
     identity.

   Map the blast radius. Findings often look like "compromise of
   image-resize service → admin token mint, because image-resize holds the
   shared HMAC key the admin API trusts."

3. **Algorithm/version drift**: same key used by multiple repos for
   different operations? An asset that's `HS256` here but accepted as
   `RS256` over there is an algorithm-confusion gadget.

4. **Test/dev/prod confusion**: assets with names containing `test`,
   `dev`, `staging` that are accepted in production paths. Real bugs.

5. **Stale keys**: `accepted_keys` lists with more entries than
   `signing_keys` lists. Old keys can still mint tokens others accept.

## Common patterns to watch

| Pattern | Indicator | Why bug |
|---|---|---|
| Asymmetric becomes symmetric | RS256 issuer + service that accepts `alg=HS256` | `kid` confusion → token forgery |
| Multi-tenant key reuse | Same signing key across tenant boundaries | Tenant A signs for tenant B |
| Service-mesh implicit trust | Service-to-service calls with no auth, behind a load balancer | Compromise the LB → forge any inter-service call |
| Audience field missing | JWT without `aud` claim used by 3+ services | One service's token replays at others |
| Shared session secret | Rails/Django/Express apps in same monorepo with identical SESSION_SECRET | Cross-app session forgery |

## Output

After analysis, write a final `<trust-shadow-summary>` block with:
- Capabilities discovered (count per repo).
- Cross-boundary edges (with the boundary names).
- Top 3 highest-risk trust holes, each with:
  - The asset and its holder.
  - The trusting party.
  - An attack narrative ≤4 sentences.
  - The hypothesis_id of any directly-related finding (if any).

If a trust hole has no corresponding finding yet, emit a new hypothesis via
the standard hypothesis emit-block — these are the most valuable trust-
shadow outputs.
