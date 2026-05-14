"""
Playwright DAST runner.

Headless browser fuzzing for vulnerabilities invisible to HTTP-only DAST:

  - DOM-based XSS         (sources: location.hash, location.search, document.referrer)
  - postMessage abuse     (cross-origin messages reaching sensitive handlers)
  - DOM clobbering        (named-element overrides of globals)
  - Prototype pollution   (window.* polluted via __proto__)
  - Open-window / form behavior (window.open with javascript: scheme)

Each scenario:
  1. Navigate to the target URL
  2. Inject a payload-in-context (URL fragment, postMessage, etc.)
  3. Observe console errors, alert dialogs, executed-marker globals
  4. Report what fired

Findings are written in the same shape as http_dast results so the
hunter-injection / hunter-xss agents can consume them uniformly.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Any

from .. import __version__


@dataclass
class PlaywrightFinding:
    url: str
    scenario: str
    confirmed: bool
    evidence_markers: list[str] = field(default_factory=list)
    payload: str = ""
    console_errors: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    network_outbound: list[str] = field(default_factory=list)


# ─── Scenarios ──────────────────────────────────────────────────────────────

DOM_XSS_PAYLOADS = [
    "javascript:void(0)#<img src=x onerror=window.__lac_xss=1>",
    "#'><svg/onload=window.__lac_xss=1>",
    "#\"><img src=x onerror=window.__lac_xss=1>",
    "?q=<script>window.__lac_xss=1</script>",
    "?q=javascript:window.__lac_xss=1",
]

POSTMESSAGE_PAYLOADS = [
    {"type": "auth", "token": "../../etc/passwd"},
    {"action": "exec", "cmd": "alert(1)"},
    {"href": "javascript:window.__lac_pm=1"},
    "__proto__[isAdmin]=true",
]


async def _dom_xss_scenario(page, target_url: str) -> list[PlaywrightFinding]:
    """Run DOM-XSS payloads against ``target_url``.

    Listeners are registered ONCE per page (rather than per payload):
    Playwright keeps every handler attached across navigations, so the
    previous loop-and-register style accumulated N handlers per page,
    fired the same console line N times, and leaked memory between
    payloads. We use shared mutable buffers cleared at each iteration.
    """
    findings: list[PlaywrightFinding] = []
    console_msgs: list[str] = []
    alert_msgs: list[str] = []
    # Keep strong refs to dialog-dismiss tasks so they aren't GC'd before
    # the dialog actually closes; ``asyncio.create_task`` returns a weakly
    # referenced handle otherwise.
    dismiss_tasks: set[asyncio.Task[Any]] = set()

    def _on_console(m: Any) -> None:
        console_msgs.append(m.text)

    def _on_dialog(d: Any) -> None:
        alert_msgs.append(d.message)
        task = asyncio.create_task(d.dismiss())
        dismiss_tasks.add(task)
        task.add_done_callback(dismiss_tasks.discard)

    page.on("console", _on_console)
    page.on("dialog", _on_dialog)
    try:
        for payload in DOM_XSS_PAYLOADS:
            console_msgs.clear()
            alert_msgs.clear()
            finding = PlaywrightFinding(
                url=target_url, scenario="dom_xss",
                confirmed=False, payload=payload,
            )
            with contextlib.suppress(Exception):
                await page.evaluate("window.__lac_xss = undefined")
            try:
                full_url = target_url + payload
                await page.goto(full_url, wait_until="networkidle",
                                 timeout=15000)
                marker = await page.evaluate(
                    "() => typeof window.__lac_xss !== 'undefined'"
                )
                if marker or alert_msgs:
                    finding.confirmed = True
                    finding.evidence_markers = (
                        ["window.__lac_xss set"] if marker else []
                    ) + (
                        [f"alert: {a}" for a in alert_msgs] if alert_msgs else []
                    )
            except Exception as e:
                finding.console_errors.append(str(e)[:120])
            finding.console_errors.extend(console_msgs[-5:])
            finding.alerts.extend(alert_msgs)
            findings.append(finding)
    finally:
        try:
            page.remove_listener("console", _on_console)
            page.remove_listener("dialog", _on_dialog)
        except Exception:
            pass
    return findings


async def _postmessage_scenario(
    page, target_url: str,
) -> list[PlaywrightFinding]:
    findings: list[PlaywrightFinding] = []
    try:
        await page.goto(target_url, wait_until="networkidle", timeout=15000)
    except Exception as e:
        return [PlaywrightFinding(
            url=target_url, scenario="postmessage",
            confirmed=False, console_errors=[str(e)[:120]],
        )]
    for payload in POSTMESSAGE_PAYLOADS:
        finding = PlaywrightFinding(
            url=target_url, scenario="postmessage",
            confirmed=False, payload=str(payload)[:200],
        )
        try:
            await page.evaluate("window.__lac_pm = undefined")
            await page.evaluate(
                "(p) => window.postMessage(p, '*')", payload,
            )
            await page.wait_for_timeout(500)
            marker = await page.evaluate(
                "() => typeof window.__lac_pm !== 'undefined'"
            )
            if marker:
                finding.confirmed = True
                finding.evidence_markers = ["postMessage triggered handler with attacker-controlled data"]
        except Exception as e:
            finding.console_errors.append(str(e)[:120])
        findings.append(finding)
    return findings


async def _dom_clobbering_scenario(
    page, target_url: str,
) -> list[PlaywrightFinding]:
    findings: list[PlaywrightFinding] = []
    try:
        await page.goto(target_url, wait_until="networkidle", timeout=15000)
    except Exception:
        return findings
    # Look for risky globals that could be clobbered by named-element
    risky_globals = ["config", "settings", "api", "endpoint", "auth",
                     "token", "Object", "Array", "JSON"]
    for g in risky_globals:
        try:
            kind = await page.evaluate(
                f"() => {{ const v = window['{g}']; "
                f"return v && v.tagName ? v.tagName : null; }}"
            )
            if kind:
                findings.append(PlaywrightFinding(
                    url=target_url, scenario="dom_clobbering",
                    confirmed=True,
                    payload=f"window.{g} is clobbered by element <{kind}>",
                    evidence_markers=[f"global '{g}' overridden by named element"],
                ))
        except Exception:
            pass
    return findings


# ─── Driver ─────────────────────────────────────────────────────────────────

async def _run_async(
    target_urls: list[str], scenarios: list[str], headless: bool = True,
) -> list[dict]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return [{"error": "playwright not installed (pip install playwright "
                          "&& playwright install chromium)"}]
    all_findings: list[PlaywrightFinding] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent=f"lacuna/{__version__} (DAST; Playwright)",
        )
        page = await context.new_page()
        for url in target_urls:
            if "dom_xss" in scenarios:
                all_findings.extend(await _dom_xss_scenario(page, url))
            if "postmessage" in scenarios:
                all_findings.extend(await _postmessage_scenario(page, url))
            if "dom_clobbering" in scenarios:
                all_findings.extend(await _dom_clobbering_scenario(page, url))
        await browser.close()
    return [
        {
            "url": f.url, "scenario": f.scenario,
            "confirmed": f.confirmed,
            "evidence_markers": f.evidence_markers,
            "payload": f.payload,
            "console_errors_tail": f.console_errors[-3:],
            "alerts": f.alerts,
        }
        for f in all_findings
    ]


def playwright_dom_scan(
    target_urls: list[str],
    scenarios: list[str] | None = None,
    headless: bool = True,
    timeout: int = 600,
) -> dict:
    """Synchronous entrypoint.

    scenarios: subset of {"dom_xss", "postmessage", "dom_clobbering"}.
    Default: all three.
    """
    if scenarios is None:
        scenarios = ["dom_xss", "postmessage", "dom_clobbering"]
    try:
        findings = asyncio.run(_run_async(
            target_urls, scenarios, headless=headless,
        ))
    except Exception as e:
        return {"error": f"playwright runner crashed: {e}"}
    confirmed = [f for f in findings if f.get("confirmed")]
    return {
        "summary": (
            f"Playwright: scanned {len(target_urls)} URLs across "
            f"{len(scenarios)} scenarios; {len(confirmed)} confirmed"
        ),
        "confirmed_count": len(confirmed),
        "handles": confirmed[:50],
        "all_findings_count": len(findings),
    }
