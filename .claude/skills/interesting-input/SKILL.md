---
name: interesting-input
description: |
  Per-type boundary sets for generating "what would make this function
  behave surprisingly?" inputs. Use whenever staring at a function and
  wondering what to try. The boundary set is the bug surface.
when_to_use:
  - You are reading a function and need a candidate input to test a hypothesis.
  - Validator is drafting a PoC and the obvious payload did not trigger the bug.
  - Fuzzing-coordinator is choosing seeds for a coverage-guided run.
---

# Interesting Input

Per type, the boundary set worth testing in your head (or with the fuzzer).

## Integers

- `0`, `1`, `-1`
- `INT_MAX`, `INT_MAX+1`, `INT_MIN`, `INT_MIN-1`
- `2^32`, `2^32-1`, `2^31`, `2^63-1`
- Negative when expected positive (signedness confusion)
- Very large (cause allocation overflow when multiplied)
- Very small (cause loop never enters, or buffer too small)
- Boundary of a length field that's read from the wire

## Strings

- Empty string `""`
- Single character
- Very long (1MB, 1GB)
- All whitespace, only newlines, only nulls
- Null bytes embedded mid-string (`"safe\0../etc/passwd"`)
- Unicode forms: NFC, NFD, NFKC, NFKD — same visible string, different bytes
- Homoglyphs (Cyrillic A vs Latin A)
- Right-to-left override characters
- Format-string control characters (`%n`, `%s`, `%x`)
- Path traversal sequences (`../`, `..\\`, `%2e%2e/`)
- URL-encoded versions of dangerous chars
- Double-encoded (`%252e%252e`)
- HTML entities (`&lt;script&gt;`)

## Floats

- `0.0`, `-0.0`
- `NaN`, `+Inf`, `-Inf`
- Subnormal
- Float that converts oddly to int (`1.7976931348623157e+308` → `INT_MAX`?)
- Float that loses precision when cast to int and back

## Arrays / Lists

- Empty
- Single element
- Very long
- Self-referential (if language allows)
- Nested very deep (parser stack overflow)
- Duplicate keys (last-wins vs first-wins)
- Heterogeneous types (`[1, "two", 3.0]`)

## Network input

- Multi-byte fields with length-from-wire that disagrees with payload
- Length fields that overflow when added to header offset
- Truncated payloads
- Concatenated requests/responses
- Pipelined requests with conflicting headers (smuggling)
- Header values containing `\r\n` (CRLF injection)
- Non-canonical method (`gEt`, `GET\t`, `GET `)

## File input

- Empty file
- File whose magic-bytes disagree with extension
- Polyglot (parses as multiple formats)
- Bombs: gzip-bomb, xml-bomb (billion laughs), regex-bomb
- TOCTOU: file changes between stat() and read()
- Symlinks to /etc/passwd
- Filenames with embedded null bytes (`foo\0.png`)

## URLs

- IPv4 in unusual notation (`http://0x7f000001`, `http://017700000001`)
- IPv6 with zone identifier (`http://[fe80::1%eth0]`)
- Userinfo separator (`http://example.com@evil.com`)
- Empty host with path-only (`http:///etc/passwd`)
- Scheme confusion (`javascript:alert(1)`, `file:///etc/passwd`)
- Punycode/IDN homoglyph (`http://xn--example-...`)
- `\` instead of `/` (some parsers normalize, some don't)

## JSON

- Duplicate keys
- Very deeply nested
- Number larger than `Number.MAX_SAFE_INTEGER`
- Number with too many decimal places
- Unicode escapes (`\u0000`, `\uD800` surrogate)
- Trailing comma (some parsers allow, some don't)

## Per-protocol weird machines

- HTTP: `Transfer-Encoding: chunked` + `Content-Length: N`
- HTTP/2: pseudo-header injection
- TLS: ALPN list with attacker-chosen protocol
- DNS: NXDOMAIN cached forever vs negative TTL respect
- SMTP: `RCPT TO:<attacker@example.com>\r\nRCPT TO:<victim@target.com>`

## Applying the discipline

For every parameter of every function under review, sweep the relevant
boundary set mentally. Where the function would crash, hang, or behave
unexpectedly — that's the bug candidate.

When a precision finding flags `integer_range_analysis` on a `malloc(n)`,
the question is no longer "could n overflow?" The question is "WHICH
value of n makes it overflow on THIS platform, and is that value reachable?"
The boundary set is the search space.
