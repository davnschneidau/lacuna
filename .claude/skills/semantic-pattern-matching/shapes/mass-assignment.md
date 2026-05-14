---
shape: mass-assignment
title: Mass assignment / overposting
---

# Mass assignment / overposting

## Intent
Set fields the client should not control by including them in the request.

## Syntactic surface

What this usually looks like in code:

- `Model.update(request.json)` / `Model.update(**request.form)`.
- `user.attributes = params[:user]` (Ruby).
- `DTO with all fields populated from request body.`
- `GraphQL inputs accepting any field of the target type.`

## Semantic signals

- **HIGH** — Update accepts arbitrary fields without an allow-list, AND the model has sensitive fields (role, is_admin, owner_id, password_hash).
- **HIGH** — Endpoint validates auth but not field-level authz on what is updateable.
- **MEDIUM** — Allow-list exists but is missing one or two sensitive fields.
- **REFUTING** — Explicit DTO / strong-parameters / `params.permit(:name, :email)` — sensitive fields excluded.

## Variants

- Role escalation by including `role: admin` in profile update.
- Ownership transfer by including `owner_id`.
- Bypass paywall by including `subscription_tier`.

## Calibration

Common in older Rails apps before Strong Parameters; Express apps; any place where `Model.update(req.body)` is written.
