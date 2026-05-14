---
shape: path-traversal
title: Path traversal
---

# Path traversal

## Intent
Read or write files outside an intended directory by including `..` segments in a path.

## Syntactic surface

What this usually looks like in code:

- `open(os.path.join(BASE, request.args["file"]))`.
- `fs.readFile(req.params.path, ...)`.
- `Static file serving with user-provided filenames.`
- `Archive extraction without prefix validation (zip-slip).`

## Semantic signals

- **HIGH** — User input is part of the file path with no normalization or prefix check.
- **HIGH** — Archive extraction without checking that destination is within target dir.
- **MEDIUM** — Validation uses `.replace("..", "")` (defeated by `....//`).
- **REFUTING** — Path canonicalized with `realpath` / `os.path.realpath` then prefix-checked against base.
- **REFUTING** — User input maps to a fixed allow-list (key → filename).

## Variants

- Read traversal (config/secret exfil).
- Write traversal (overwrite app files).
- Zip-slip / tar-slip during archive extraction.

## Calibration

Any code path that takes a user-provided filename and joins it to a base directory deserves a hypothesis if there's no realpath check.
