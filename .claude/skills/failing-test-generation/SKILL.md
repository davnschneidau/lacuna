---
name: failing-test-generation
description: After a finding is confirmed, generate a failing unit/integration test that demonstrates the vulnerability and will pass once the patch is applied. Use after patch-suggestion to produce a complete fix package.
when_to_use:
  - A finding has been confirmed and patch-suggestion produced a candidate diff.
  - The remediation package needs a regression test before being handed to developers.
  - You are preparing fix-PR artefacts (Phase 8) and need executable proof of the bug.
---

# Failing test generation

A confirmed finding without a failing test will be re-introduced. The test is
the regression guard. This skill generates the minimal test that:
1. **Fails** on the vulnerable code (the bug is demonstrable)
2. **Passes** after the patch is applied (the fix is correct)
3. **Lives in the existing test suite** (not a standalone script)

## When to use

After `patch-suggestion` has produced a patch diff. Read both the confirmed
finding and the patch before writing the test.

## Procedure

### Step 1 — Read the test suite

Call `test_coverage_for_endpoint(repo, route)` or
`test_assertions_for_function(repo, function)` to understand:
- What test framework is in use (pytest, unittest, jest, JUnit, etc.)
- How tests are structured (fixtures, factories, client setup)
- What the existing happy-path tests look like for the same function

### Step 2 — Identify the test oracle

The test oracle is the observable difference between vulnerable and fixed code:

| Shape | Oracle |
|-------|--------|
| SQLi | `' OR '1'='1` input returns 400 / empty result (not all rows) |
| Path traversal | `../../etc/passwd` returns 400, no file created outside upload dir |
| SSRF | `http://169.254.169.254/` returns 403 / connection refused |
| Auth bypass | Unauthenticated request returns 401/403, not 200 |
| Mass assignment | Posting `{"is_admin": true}` does not escalate the user |
| JWT alg=none | Token with `alg=none` is rejected with 401 |
| Open redirect | Redirect to `https://evil.example.com` is rejected |

The test asserts the **secure behavior** (what should happen after the fix).
On the vulnerable code, this assertion fails. After the patch, it passes.

### Step 3 — Write the test

Use the codebase's existing test style. Match:
- Import conventions
- Fixture/factory usage
- Assertion style
- File location (same directory as existing tests for this module)

Template:

```python
# pytest example
def test_<vulnerability_name>_is_rejected(client, ...):
    """
    Regression test for <CVE/finding ID>: <one-line description>.
    This test fails on the vulnerable code and passes after the patch.
    """
    response = client.<method>(<endpoint>, data=<malicious_payload>)
    assert response.status_code in (400, 403, 422), (
        "Vulnerable: expected rejection of malicious input"
    )
    # Optional: assert the side-effect did NOT happen
    # assert not Path(UPLOAD_DIR, "../../etc/passwd").exists()
```

```javascript
// jest example
test('<vulnerability_name> input is rejected', async () => {
  const res = await request(app)
    .<method>('<endpoint>')
    .send(<malicious_payload>);
  expect(res.status).toBe(400); // or 403
});
```

### Step 4 — Write edge-case variants

For injection vulnerabilities, add two to three variants covering encoding
bypasses that are commonly missed:

```python
@pytest.mark.parametrize("payload", [
    "../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",     # URL-encoded
    "....//....//etc/passwd",     # double-dot bypass
    "\x00/etc/passwd",            # null-byte
])
def test_path_traversal_variants_rejected(client, payload):
    response = client.post("/upload", data={"filename": payload})
    assert response.status_code in (400, 422, 403)
```

### Step 5 — Output format

Write the test to `kg.write.regression_test(finding_id=..., test_code=...,
test_file_path=..., framework=..., oracle_description=...)` with:
- `test_code`: the complete test function(s), including imports
- `test_file_path`: where to place it (relative to repo root)
- `framework`: pytest | unittest | jest | mocha | junit | rspec
- `oracle_description`: one sentence explaining what the test asserts

## Rules

- **Never write a test that mutates production state** (no real DB writes,
  no real file creates outside tmp, no outbound requests)
- Use mocking for external services
- The test must be deterministic — no random inputs without a fixed seed
- Mark the test with a comment referencing the finding ID

## Example output

```python
# tests/test_upload.py — regression for fnd-abc (path traversal in upload_file)
import pytest
from pathlib import Path


@pytest.mark.parametrize("filename", [
    "../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "\x00/etc/passwd",
])
def test_path_traversal_rejected(client, tmp_upload_dir, filename):  # noqa: fnd-abc
    """Regression for fnd-abc: path traversal via upload filename."""
    resp = client.post("/upload", data={"filename": filename}, content_type="multipart/form-data")
    assert resp.status_code in (400, 403, 422), (
        f"Expected rejection of traversal payload {filename!r}, got {resp.status_code}"
    )
    # No file should have been created outside tmp_upload_dir
    etc_passwd = Path("/etc/passwd")
    assert not (tmp_upload_dir.parent / "etc" / "passwd").exists()
```
