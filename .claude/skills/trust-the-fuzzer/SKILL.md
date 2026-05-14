---
name: trust-the-fuzzer
description: |
  When static analysis says safe and fuzzing crashes, fuzzing wins.
  Encode the discipline of letting Layer-3 oracles override Layer-2
  analysis. Counterweights the validator failure mode where a confident
  static argument rationalizes away a real crash.
---

# Trust the Fuzzer

A crash is ground truth. A static argument is not. When they disagree,
the crash wins.

## The rule

If `fuzz_function` returned a crash on a candidate hypothesis:

- The verdict CANNOT be `refuted`.
- The verdict CAN be `confirmed`, `confirmed_with_caveats`, or
  `downgraded_severity`.
- If the static analysis seems to prove safety, you're missing something.
  Look harder.

## Why static gets it wrong

Static analysis abstracts. The abstraction loses information. Some
common failure modes that produce false "safe" claims:

- **Path conditions assumed unreachable.** The analyzer says
  `if (n > 100) panic()` so `n <= 100` is invariant downstream — but
  inlined optimizations or compiler reordering broke that invariant.
- **Aliasing collapsed.** Two pointer variables look distinct in source
  but point to the same allocation at runtime; analyzer didn't track the
  alias.
- **Integer widths confused.** Source has `int n`, analyzer reasoned in
  32-bit, but on 64-bit Linux `int` is still 32-bit and arithmetic with
  `size_t` produces a value the analyzer didn't model.
- **Macros that hide allocations.** `kmalloc(SIZE)` where `SIZE` is a
  macro the analyzer didn't expand correctly.
- **Library boundaries.** Source code stops at a library call;
  analyzer assumed the library is well-behaved on all inputs.
- **Compiler dead-code elimination removing safety checks.** UBSan
  catches some; not all.

The fuzzer doesn't abstract. It executes. Execution beats reasoning when
they fight.

## What the validator should do with a crash

1. **Confirm the bug class matches the hypothesis.**
   - If hypothesis says CWE-190 and crash shows ASan heap-buffer-overflow,
     these align (overflow → bad allocation → overflow at use).
   - If hypothesis says CWE-89 SQLi and crash shows null-deref, they
     DON'T align — the crash is a different bug. File a separate finding.
2. **Confirm the input the fuzzer found is plausibly attacker-reachable.**
   - If the input is `\xff\xff\xff\xff` and the function takes wire-format
     packets, attacker can reach.
   - If the input requires a precondition that only happens after
     authenticated admin upload, lower severity.
3. **Confirm at high confidence.** The crash is the evidence. The
   minimized input IS the proof of concept.

## When the fuzzer is wrong (rarely)

The fuzzer is wrong about exploitability, not about crashing. Things that
crash but aren't security bugs:

- Assertions that crash on invariant violation (might be defense-in-depth)
- Memory allocator failures from OOM in the fuzz harness itself
- Crashes triggered by inputs the harness shouldn't have allowed
  (harness bug, not target bug)
- Crashes in functions only called by the test harness

For these, downgrade. Don't refute. Memory-safety crashes are almost
always exploitable in practice; the burden of proof shifts.

## Anti-pattern

DO NOT, when faced with a crash report you don't understand, write
"the static analysis still says this is safe, the fuzzer must be wrong."
This is the cardinal sin. The fuzzer is showing you reality. Your job
is to update your model, not to defend it.
