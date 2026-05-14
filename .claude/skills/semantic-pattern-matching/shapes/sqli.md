---
shape: sqli
title: SQL Injection
---

# SQL Injection

## Intent
Build and execute a SQL query that uses untrusted input.

## Syntactic surface

What this usually looks like in code:

- `f-string / template-string / concatenation building a SQL string`
- `.execute(query)` with `query` not a parameterized prepared statement
- ORM `.raw()`, `.extra()`, or `.objects.raw()` calls with interpolation
- `db.query(...)` in Node where the string is built with template literals
- JDBC `Statement` (not `PreparedStatement`)
- `Custom query builders that concatenate identifiers`

## Semantic signals

- **HIGH** — Source is `request.args[...]` / `req.query.x` / etc. and reaches `.execute(...)` directly as part of the string.
- **HIGH** — Identifier (table/column name) is user-controlled — parameterization does NOT escape identifiers.
- **MEDIUM** — Source flows into the query through one intermediate function but no validation on that function.
- **MEDIUM** — ORM is in use but the call uses `.raw()` — even ORMs are not magic if you bypass them.
- **LOW** — Source is a number that the framework parses as int (sanitization-via-type-coercion).
- **REFUTING** — Call uses `?` or `$1` or `:name` placeholders with separate args list.
- **REFUTING** — ORM `.filter(name=value)` or `.where({name: value})` — parameterized by construction.
- **REFUTING** — Stored procedure with strictly-typed params.

## Variants

- Classic — error-based or union-based recovery of data.
- Blind boolean — response differs based on conditional injection.
- Blind time — server delays based on injected SLEEP / pg_sleep.
- Second-order — input stored verbatim and used in a later query.
- Out-of-band — DNS or HTTP exfiltration via xp_dirtree, LOAD_FILE.
- NoSQL injection — operator injection (`$ne`, `$where`) in Mongo.

## Calibration

Heavily framework-dependent. Django `.objects.filter()` is parameterized; `.objects.raw()` is not. SQLAlchemy `text()` without `:param` binding is not. Knex.js `.raw()` is not. Hibernate `createQuery()` is parameterized only if `setParameter()` is used; string concatenation defeats it.
