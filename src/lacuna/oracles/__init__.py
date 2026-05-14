"""
Bug-class deep oracles.

When the validator is uncertain after 4 rounds of red/blue, hand off to
specialized mature tooling:

  sqlmap_wrapper:    SQLi (DBMS-agnostic, payload synthesis, dump support)
  ysoserial_wrapper: Java/Net deserialization gadget chains
  gopherus_wrapper:  Gopher-protocol SSRF payloads for Redis/Memcached/etc

Each wrapper exposes a single high-level function that runs the underlying
binary with safe defaults, parses output, and returns the "summary + handles"
shape. Errors (binary missing, timeout, permission) are caught and surfaced.
"""
from .gopherus_wrapper import run_gopherus
from .sqlmap_wrapper import run_sqlmap
from .ysoserial_wrapper import generate_ysoserial_payload

__all__ = ["generate_ysoserial_payload", "run_gopherus", "run_sqlmap"]
