---
shape: deserialize
title: Unsafe Deserialization
---

# Unsafe Deserialization

## Intent
Deserialize attacker-controlled bytes with a library that supports arbitrary type construction.

## Syntactic surface

What this usually looks like in code:

- Python `pickle.loads(data)` where `data` is from network/file upload/queue.
- Java `ObjectInputStream.readObject()` on untrusted bytes.
- Ruby `Marshal.load(data)`.
- PHP `unserialize($data)`.
- Node.js `node-serialize.unserialize(data)`.
- PyYAML `yaml.load(data)` without `Loader=SafeLoader`.
- .NET `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`.
- `MessagePack with type-erased custom deserializers.`

## Semantic signals

- **HIGH** — Deserializer is unsafe-by-default (pickle, Marshal, unserialize, BinaryFormatter, yaml.load) and reads HTTP/queue bytes.
- **HIGH** — Java with commons-collections / commons-beanutils / spring on classpath AND ObjectInputStream — gadget chains exist.
- **MEDIUM** — Untrusted bytes from queue / cron — trust boundary is whoever can write to the queue.
- **REFUTING** — Deserializer is safe-by-default (json.loads, yaml.safe_load, msgpack with explicit types, Jackson with no polymorphic types).
- **REFUTING** — HMAC verifies the bytes before deserialization — gadget chain unreachable without key.

## Variants

- Direct RCE via gadget chain.
- DoS via deeply nested or self-referential structures.
- Memory exhaustion via decompression-bomb payloads.

## Calibration

Anything `pickle.loads` from network is automatic. Java ObjectInputStream on HTTP data is automatic. The deserializer's safety is everything; if it's safe-by-default, refutation is straightforward.
