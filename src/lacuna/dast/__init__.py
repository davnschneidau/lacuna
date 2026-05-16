"""Lacuna DAST helpers: payloads, OOB client, auth flows.

OobClient pulls httpx in lazily; that keeps the payloads module testable in
environments without httpx (e.g. unit-test CI runners that haven't installed
the full requirements set).
"""
from .payloads import payloads_for_class


def __getattr__(name):
    if name == "OobClient":
        from .oob_client import OobClient
        return OobClient
    raise AttributeError(name)


__all__ = ["OobClient", "payloads_for_class"]
