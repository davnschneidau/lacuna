---
shape: idor
title: IDOR / BOLA (Broken Object Level Authorization)
---

# IDOR / BOLA (Broken Object Level Authorization)

## Intent
Reach an object via a predictable identifier without proving authorization.

## Syntactic surface

What this usually looks like in code:

- `GET /api/v1/orders/{order_id}` returning the order regardless of who requested it.
- `Resource ID in path or query; no ownership check before returning.`
- Bulk endpoints (`POST /api/orders/bulk`) that don't filter by current user.
- `Sequential / guessable IDs (auto-increment integers, UUIDv1 with timestamp).`

## Semantic signals

- **HIGH** — Endpoint loads a resource by ID and returns it without checking `resource.owner_id == current_user.id` (or equivalent).
- **HIGH** — Authenticated user can access resources for any user just by changing the ID.
- **MEDIUM** — Authorization check exists but only checks role, not ownership.
- **MEDIUM** — Bulk operations accept lists of IDs without per-item ownership check.
- **REFUTING** — Endpoint uses `current_user.orders.find(id)` (scoped to user).
- **REFUTING** — Policy framework (CanCanCan, Pundit, Casbin) explicitly authorizes per request.

## Variants

- Classic IDOR — change the ID in the URL.
- Mass IDOR — bulk endpoint without filtering.
- Indirect IDOR — resource referenced via association without checking the parent.

## Calibration

IDOR is the single most common API vuln. Any endpoint loading a resource by ID without a `where(owner_id = current_user)` clause is a hypothesis. Validator must confirm by attempting cross-user access.
