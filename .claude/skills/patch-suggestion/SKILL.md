---
name: patch-suggestion
description: After a finding is confirmed, generate a minimal, correct, and reviewable code patch. Use only after validator writes a confirmed verdict. Never suggest patches for unconfirmed hypotheses.
when_to_use:
  - Validator just wrote a confirmed verdict and a minimal repro is recorded.
  - A reviewer asked for a remediation diff to accompany a finding in the tech report.
  - You are preparing a fix-PR artefact (Phase 8) and need the patch as a starting point.
---

# Patch suggestion

This skill generates minimal, correct patches for confirmed findings. The goal
is not to write the final production fix — it is to give the developer a
concrete starting point that:
1. Fixes the root cause (not the symptom)
2. Matches the codebase's existing style
3. Does not introduce new vulnerabilities
4. Passes the existing test suite

## When to use

Only after `kg.write.finding(status="confirmed")` has been written.
Never suggest patches for hypotheses or `needs_human` verdicts.

## Procedure

### Step 1 — Read the finding

Extract from the confirmed finding:
```text
SHAPE:    What class of vulnerability (sqli, ssrf, path_traversal, etc.)
FILE:     The source file(s) containing the vulnerable code
LINE:     The specific line(s) of the sink / missing check
ROOT CAUSE: Which control is absent (parameterization, allowlist, etc.)
```

### Step 2 — Read context

Call `code_excerpt(repo, file, line, context=30)` to read:
- The vulnerable function body
- Its imports and dependencies
- The calling convention (what type is the input?)
- Any existing validation patterns nearby

### Step 3 — Identify the minimal fix

The fix should be the smallest change that closes the vulnerability:

| Shape | Minimal fix pattern |
|-------|---------------------|
| SQLi | Replace string-formatted query with parameterized query |
| Path traversal | Add `Path(input).resolve()` + prefix assertion |
| SSRF | Add URL allowlist check before HTTP client call |
| Command injection | Replace `shell=True` + string with `shell=False` + list |
| XSS | Add output encoding / context-specific escaping |
| Mass assignment | Add explicit field allowlist to model binding |
| JWT none alg | Add `algorithms=["HS256"]` or RS256 to `jwt.decode()` |
| Hardcoded secret | Move to environment variable + document in README |
| Open redirect | Restrict to same-origin or known-safe redirect targets |

### Step 4 — Write the patch

Format the patch as a diff:
```diff
--- a/path/to/file.py
+++ b/path/to/file.py
@@ -N,M +N,M @@
 context_line
-vulnerable_line
+fixed_line
 context_line
```

Requirements for the patch:
- Minimal: change as few lines as possible
- Style-preserving: match indentation, quoting, naming conventions
- No leftover debug code, no TODOs
- The fix addresses the root cause named in Step 1

### Step 5 — Validate the patch

Before writing the patch, self-review:

1. **Does it fix the root cause?** (not just make the PoC fail)
2. **Can it be bypassed?** (different encoding, null byte, edge case)
3. **Does it break the happy path?** (the normal use case still works)
4. **Does it introduce a new vulnerability?** (side-channel, logic error)

If the answer to 2, 3, or 4 is "yes" → revise the patch.

### Step 6 — Write the output

Write the patch as a `kg.write.patch(finding_id=..., patch_diff=...,
rationale=..., test_hint=...)` with:
- `patch_diff`: the unified diff
- `rationale`: one sentence explaining why this fix closes the root cause
- `test_hint`: one sentence on what a regression test should assert

## Anti-patterns to avoid

- **Don't sanitize inputs at the call site** if the sink accepts the type
  everywhere — fix the model, not each call site (exception: if there are
  only 1-2 call sites)
- **Don't use blocklists** for injection prevention — use parameterization
  or allowlists
- **Don't add `try/except` to silence errors** — that hides the vulnerability
  without fixing it
- **Don't encode at display without fixing the root cause** — encoding output
  is defense-in-depth, not a fix for SQLi

## Example output

```text
Patch for fnd-abc (path traversal in upload_file):

rationale: Path traversal occurs because user-supplied filename is joined
  to upload_dir without normalization. Fix: resolve the final path and
  assert it is still under upload_dir.
```

```diff
--- a/app/views/upload.py
+++ b/app/views/upload.py
@@ -23,7 +23,10 @@ def upload_file():
     filename = request.form.get("filename", "")
-    dest = os.path.join(UPLOAD_DIR, filename)
-    with open(dest, "wb") as f:
+    dest = Path(UPLOAD_DIR, filename).resolve()
+    if not str(dest).startswith(str(Path(UPLOAD_DIR).resolve())):
+        return "Invalid filename", 400
+    with open(dest, "wb") as f:
         f.write(request.data)
```

```text
test_hint: Assert that a filename of "../../etc/passwd" returns 400
  and does not create a file outside UPLOAD_DIR.
```
