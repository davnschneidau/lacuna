"""
Memory-tool adapter for Lacuna's KG.

Anthropic's memory tool is a file-based interface. Agents can read/write
"files" like `/memory/primitives/prim-abc.md`. This module projects the
KG into that file-tree shape:

  /memory/
    application_model.md
    current_phase.md
    pending_hypotheses/{id}.md
    confirmed_findings/{id}.md
    primitives/{id}.md
    chains/{id}.md
    refuted_hypotheses/{id}.md
    agent_notes/{agent}/{path}

Reads project from the KG. Writes go to agent_notes/{agent}/{path}; the
read-only projection paths reject writes.
"""
from __future__ import annotations

from .client import KG


class MemoryAdapter:
    """Projects the KG as a memory-tool-shaped file tree."""

    PROJECTED_PREFIXES = (
        "/memory/application_model.md",
        "/memory/current_phase.md",
        "/memory/pending_hypotheses/",
        "/memory/confirmed_findings/",
        "/memory/primitives/",
        "/memory/chains/",
        "/memory/refuted_hypotheses/",
    )
    WRITABLE_PREFIX = "/memory/agent_notes/"

    def __init__(self, kg: KG):
        self.kg = kg

    # ── read ────────────────────────────────────────────────────────────────

    def read(self, path: str) -> str | None:
        if path == "/memory/application_model.md":
            am = self.kg.read_application_model()
            return am["summary_md"] if am else None

        if path == "/memory/current_phase.md":
            return self.kg.get_meta("current_phase") or "unknown"

        if path.startswith("/memory/pending_hypotheses/"):
            hid = self._extract_id(path, "/memory/pending_hypotheses/", ".md")
            return self._render_hypothesis(hid)

        if path.startswith("/memory/refuted_hypotheses/"):
            hid = self._extract_id(path, "/memory/refuted_hypotheses/", ".md")
            return self._render_hypothesis(hid, only_status="refuted")

        if path.startswith("/memory/confirmed_findings/"):
            fid = self._extract_id(path, "/memory/confirmed_findings/", ".md")
            return self._render_finding(fid)

        if path.startswith("/memory/primitives/"):
            pid = self._extract_id(path, "/memory/primitives/", ".md")
            return self._render_primitive(pid)

        if path.startswith("/memory/chains/"):
            cid = self._extract_id(path, "/memory/chains/", ".md")
            return self._render_chain(cid)

        if path.startswith(self.WRITABLE_PREFIX):
            agent, sub = self._split_agent_path(path)
            return self.kg.note_read(agent, sub)

        return None

    def list(self, path: str) -> list[str]:
        """List entries under a directory-like path."""
        if path == "/memory/" or path == "/memory":
            entries = [
                "application_model.md", "current_phase.md",
                "pending_hypotheses/", "confirmed_findings/",
                "primitives/", "chains/", "refuted_hypotheses/",
                "agent_notes/",
            ]
            return [f"/memory/{e}" for e in entries]

        if path == "/memory/pending_hypotheses/":
            return [
                f"/memory/pending_hypotheses/{h['id']}.md"
                for h in self.kg.list_hypotheses(status="pending")
            ]
        if path == "/memory/refuted_hypotheses/":
            return [
                f"/memory/refuted_hypotheses/{h['id']}.md"
                for h in self.kg.list_hypotheses(status="refuted")
            ]
        if path == "/memory/confirmed_findings/":
            return [f"/memory/confirmed_findings/{f['id']}.md"
                    for f in self.kg.list_findings()]
        if path == "/memory/primitives/":
            return [f"/memory/primitives/{p.id}.md" for p in self.kg.list_primitives()]
        if path == "/memory/chains/":
            return [f"/memory/chains/{c.id}.md" for c in self.kg.list_chains()]

        if path.startswith(self.WRITABLE_PREFIX):
            parts = path[len(self.WRITABLE_PREFIX):].rstrip("/").split("/", 1)
            agent = parts[0]
            paths = self.kg.note_list(agent)
            return [f"/memory/agent_notes/{agent}/{p}" for p in paths]

        return []

    # ── write ───────────────────────────────────────────────────────────────

    def write(self, path: str, content: str) -> bool:
        """Only agent_notes paths are writable. Returns True on success."""
        if not path.startswith(self.WRITABLE_PREFIX):
            return False
        agent, sub = self._split_agent_path(path)
        if not agent or not sub:
            return False
        self.kg.note_write(agent, sub, content)
        return True

    def delete(self, path: str) -> bool:
        """Only agent_notes paths are deletable."""
        return bool(path.startswith(self.WRITABLE_PREFIX))

    # ── rendering helpers ───────────────────────────────────────────────────

    def _render_hypothesis(self, hid: str, only_status: str | None = None) -> str | None:
        h = self.kg.get_hypothesis(hid)
        if h is None:
            return None
        if only_status and h["status"] != only_status:
            return None
        return (
            f"# Hypothesis {hid}\n\n"
            f"- **Shape:** {h['shape']}\n"
            f"- **Hunter:** {h['hunter']}\n"
            f"- **Status:** {h['status']}\n"
            f"- **Confidence:** {h['confidence']}\n"
            f"- **Location:** {h['repo'] or '-'}:{h['file'] or '-'}:"
            f"{h['line'] or '-'}\n\n"
            f"## Description\n{h['description']}\n\n"
            f"## Attacker scenario\n{h['attacker_scenario'] or '-'}\n\n"
            f"## Refutation reason\n{h['refutation_reason'] or '-'}\n"
        )

    def _render_finding(self, fid: str) -> str | None:
        f = self.kg.get_finding(fid)
        if f is None:
            return None
        evidence = self.kg.get_evidence(fid)
        ev_md = "\n".join(
            f"- {e['kind']}: `{e['payload_path']}`" for e in evidence
        )
        cwes = ", ".join(f.get("cwes") or []) or "-"
        repos = ", ".join(f.get("repos_involved") or []) or "-"
        return (
            f"# Finding {fid}: {f['title']}\n\n"
            f"- **Severity:** {f['severity']}\n"
            f"- **CVSS:** {f['cvss_vector'] or '-'}\n"
            f"- **CWEs:** {cwes}\n"
            f"- **Repos:** {repos}\n"
            f"- **Hypothesis:** {f['hypothesis_id']}\n\n"
            f"## Validator summary\n{f['validator_summary']}\n\n"
            f"## Remediation\n{f['remediation_md'] or '-'}\n\n"
            f"## Evidence\n{ev_md or '- none -'}\n"
        )

    def _render_primitive(self, pid: str) -> str | None:
        p = self.kg.get_primitive(pid)
        if p is None:
            return None
        return (
            f"# Primitive {pid}: {p.name}\n\n"
            f"{p.description}\n\n"
            f"**Prerequisites:** {', '.join(p.prerequisites) or 'none'}\n"
            f"**Effects:** {', '.join(p.effects) or 'none'}\n"
            f"**Repos involved:** {', '.join(p.repos_involved) or '-'}\n"
            f"**Finding:** {p.finding_id or '-'}\n"
        )

    def _render_chain(self, cid: str) -> str | None:
        c = self.kg.get_chain(cid)
        if c is None:
            return None
        return (
            f"# Chain {cid} → goal: {c.goal}\n\n"
            f"**Combined severity:** {c.combined_severity}\n"
            f"**Primitives:** {', '.join(c.primitive_ids)}\n\n"
            f"## Narrative\n{c.narrative_md}\n"
        )

    # ── path utils ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_id(path: str, prefix: str, suffix: str) -> str:
        return path[len(prefix):].removesuffix(suffix)

    @staticmethod
    def _split_agent_path(path: str) -> tuple[str, str]:
        rest = path[len("/memory/agent_notes/"):]
        if "/" not in rest:
            return rest, ""
        agent, sub = rest.split("/", 1)
        return agent, sub
