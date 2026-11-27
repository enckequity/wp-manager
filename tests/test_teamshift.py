"""TeamShift carry fixes, one section per fix:

1. approval pinned on, every write gated;
2. dashboard/ and desktop/ stripped (the dashboard update route skipped the approval hook);
3. no op:// 1Password path; credentials only from workspace secrets, fail closed;
4. WordPress connector rebranded, no engine names in user-facing text;
5. no local/private/link-local/metadata targets, including after redirects;
plus the stripped runtime copy loading in the engine (skipped when the engine is not importable).

Run from tests/ like the rest of the suite: ``python -m unittest``.
"""

import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from helpers import BASE, SECRET, USER, Env, ReplayTransport, add_default_site, call, submodule

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_PY = sorted([ROOT / "__init__.py", ROOT / "approval.py", ROOT / "schemas.py", ROOT / "tools.py",
                     *(ROOT / "core").glob("*.py")])
CONNECTOR = ROOT / "connector" / "teamshift-connector"
NOT_RUNTIME = ("tests", "docs", "e2e", "scripts", "connector", "README.md", "CHANGELOG.md", ".gitignore")
WRITES = {
    "wp_update_apply": {"site": "wp-example", "type": "plugin"},
    "wp_content_save": {"site": "wp-example", "type": "post", "title": "Draft only"},
    "wp_site_add": {"url": "https://new.example.test", "username": "a", "id": "new"},
    "wp_site_remove": {"site": "wp-example"},
}
READS = {
    "wp_sites": {},
    "wp_updates_scan": {"sites": ["wp-example"]},
    "wp_health_check": {"site": "wp-example"},
    "wp_content_list": {"site": "wp-example", "type": "post"},
    "wp_content_get": {"site": "wp-example", "type": "post", "id": 12},
}


def _engine_available() -> bool:
    return importlib.util.find_spec("hermes_cli") is not None and importlib.util.find_spec("agent") is not None


# -- 1. approval pinned on ---------------------------------------------------------------------
class ApprovalPinned(unittest.TestCase):
    def setUp(self):
        self.env = Env(settings={"require_approval": False, "require-approval": False}).start()
        add_default_site(self.env)
        self.approval = submodule("approval")

    def tearDown(self):
        self.env.stop()

    def hook(self, tool, args):
        return self.approval.pre_tool_call(tool_name=tool, args=dict(args))

    def test_setting_is_gone_from_the_manifest(self):
        import yaml
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
        self.assertNotIn("require_approval", manifest.get("config_schema") or {})

    def test_config_cannot_turn_it_off(self):
        for value in (False, "false", 0, "no", "off"):
            self.env.settings["require_approval"] = value
            self.assertTrue(submodule("core.settings").current().require_approval, value)

    def test_every_write_asks_even_with_the_setting_off(self):
        self.assertEqual(set(WRITES), set(self.approval.GATED_TOOLS))
        for tool, args in WRITES.items():
            d = self.hook(tool, args)
            self.assertIsNotNone(d, tool)
            self.assertEqual(d["action"], "approve", tool)
            self.assertTrue(d["rule_key"].startswith("wp-manager:"), d)

    def test_every_write_is_blocked_unattended(self):
        self.approval.set_cron_probe(lambda: object())
        try:
            for tool, args in WRITES.items():
                self.assertEqual(self.hook(tool, args)["action"], "block", tool)
        finally:
            self.approval.set_cron_probe(None)

    def test_reads_are_not_gated(self):
        for tool, args in READS.items():
            self.assertIsNone(self.hook(tool, args), tool)

    def test_every_registered_tool_is_classified(self):
        schemas = submodule("schemas")
        self.assertEqual({s["name"] for s in schemas.ALL}, set(WRITES) | set(READS))


# -- 2. dashboard stripped ---------------------------------------------------------------------
class DashboardStripped(unittest.TestCase):
    def test_no_dashboard_or_desktop_page(self):
        for name in ("dashboard", "desktop"):
            left = [f for f in (ROOT / name).rglob("*") if f.is_file() and "__pycache__" not in f.parts]
            self.assertEqual(left, [], name)

    def test_runtime_has_no_web_routes(self):
        for path in RUNTIME_PY:
            text = path.read_text(encoding="utf-8")
            for name in ("fastapi", "starlette", "plugin_api", "APIRouter", "dashboard"):
                self.assertNotRegex(text, rf"^\s*(from|import)\s+[.\w]*{name}", (path.name, name))
            self.assertNotIn("/sites/{", text, path.name)


# -- 3. no op:// path --------------------------------------------------------------------------
class NoOnePassword(unittest.TestCase):
    def setUp(self):
        self.env = Env().start()
        self.creds = submodule("core.credentials")
        self.registry = submodule("core.registry")

    def tearDown(self):
        self.env.stop()

    def test_no_cli_or_subprocess_in_runtime(self):
        self.assertFalse((ROOT / "core" / "onepassword.py").exists())
        for path in RUNTIME_PY:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"^\s*(import|from)\s+subprocess", path.name)
            self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", text, path.name)
            self.assertNotIn("op_binary", text, path.name)
        import yaml
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
        self.assertNotIn("op_binary", manifest.get("config_schema") or {})

    def test_op_reference_refused(self):
        with self.assertRaises(self.registry.RegistryError):
            self.registry.check_credential_ref({"op": "op://Private/WP/password"})
        with self.assertRaises(self.creds.CredentialError):
            self.creds.resolve({"id": "a", "username": "u", "credential": {"op": "op://Private/WP/password"}})

    def test_unresolved_op_value_refused(self):
        self.env.secrets["WPM_A_APP_PASSWORD"] = "op://Private/WP/password"
        with self.assertRaises(self.creds.CredentialError):
            self.creds.resolve({"id": "a", "username": "u"})

    def test_onepassword_storage_and_chat_passwords_refused_without_io(self):
        t = self.env.transport
        for args in ({"url": BASE, "username": USER, "id": "wp-example", "storage": "onepassword",
                      "vault_id": "a" * 26, "app_password": SECRET},
                     {"url": BASE, "username": USER, "id": "wp-example", "app_password": SECRET},
                     {"url": BASE, "username": USER, "id": "wp-example", "vault_id": "a" * 26}):
            r = call(submodule("tools").wp_site_add, args)
            self.assertFalse(r["success"], r)
            self.assertNotIn(SECRET, json.dumps(r))
        self.assertEqual(t.network_calls, 0)

    def test_schema_offers_no_op_path(self):
        site_add = next(s for s in submodule("schemas").ALL if s["name"] == "wp_site_add")
        props = site_add["parameters"]["properties"]
        self.assertNotIn("vault_id", props)
        self.assertEqual(props["storage"]["enum"], ["existing"])
        self.assertEqual(set(props["credential"]["properties"]), {"env"})
        self.assertNotIn("op://", json.dumps(site_add))

    def test_default_reader_is_the_workspace_secret_route(self):
        self.creds.set_secret_getter(None)
        fake = mock.MagicMock()
        fake.get_secret = mock.MagicMock(return_value=SECRET)
        with mock.patch.dict(sys.modules, {"agent.secret_scope": fake}), \
             mock.patch.dict(os.environ, {"WPM_A_APP_PASSWORD": "from-process-env"}):
            self.assertEqual(self.creds.resolve({"id": "a", "username": "u"}), SECRET)
        fake.get_secret.assert_called_once_with("WPM_A_APP_PASSWORD")

    def test_fails_closed_without_the_secret_route(self):
        self.creds.set_secret_getter(None)
        with mock.patch.dict(sys.modules, {"agent.secret_scope": None}), \
             mock.patch.dict(os.environ, {"WPM_A_APP_PASSWORD": SECRET}):
            with self.assertRaises(self.creds.CredentialError) as cm:
                self.creds.resolve({"id": "a", "username": "u"})
        self.assertNotIn(SECRET, str(cm.exception))
        src = (ROOT / "core" / "credentials.py").read_text()
        self.assertNotIn("os.environ", src)
        self.assertNotIn("getenv", src)

    @unittest.skipUnless(_engine_available(), "needs the engine")
    def test_engine_secret_route_is_used(self):
        import agent.secret_scope as scope
        self.creds.set_secret_getter(None)
        asked = []
        with mock.patch.object(scope, "get_secret", lambda name, default=None: asked.append(name) or SECRET):
            self.assertEqual(self.creds.resolve({"id": "a", "username": "u"}), SECRET)
        self.assertEqual(asked, ["WPM_A_APP_PASSWORD"])

    def test_connection_string_secret_must_match_the_site(self):
        from helpers import connection_string
        self.env.secrets["WPM_A_APP_PASSWORD"] = connection_string(url="https://a.example.test", user="u")
        self.assertEqual(self.creds.resolve({"id": "a", "username": "u", "url": "https://a.example.test"}), SECRET)
        with self.assertRaises(self.creds.CredentialError):
            self.creds.resolve({"id": "a", "username": "u", "url": "https://other.example.test"})
        with self.assertRaises(self.creds.CredentialError):
            self.creds.resolve({"id": "a", "username": "someone-else", "url": "https://a.example.test"})


# -- 4. rebrand --------------------------------------------------------------------------------
ENGINE_WORD = re.compile(r"hermes|nous\s*research|nousresearch", re.I)


def _user_strings(path: Path) -> list:
    """String literals minus docstrings (developer text nobody sees)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


# Engine identifiers the code must use to talk to the engine; none of them reaches a person.
ENGINE_IDENTIFIERS = {"HERMES_CRON_SESSION", "HERMES_SESSION_PLATFORM", "HERMES_HOME"}


class Rebrand(unittest.TestCase):
    def test_connector_names_no_third_party(self):
        self.assertTrue(CONNECTOR.is_dir())
        self.assertFalse((ROOT / "connector" / "website-manager-hermes-connector").exists())
        for path in CONNECTOR.rglob("*"):
            if not path.is_file():
                continue
            self.assertNotRegex(path.name, ENGINE_WORD)
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.startswith("Copyright (C) 2026 danieljwonder"):
                    continue  # GPL requires the original copyright notice to stay (source only)
                self.assertNotRegex(line, ENGINE_WORD, f"{path.relative_to(ROOT)}:{n}")
                self.assertNotIn("danieljwonder", line, f"{path.relative_to(ROOT)}:{n}")

    def test_connector_header_and_rest_namespace(self):
        main = (CONNECTOR / "teamshift-connector.php").read_text()
        self.assertRegex(main, r"\* Plugin Name:\s+TeamShift Connector\n")
        self.assertRegex(main, r"\* Author:\s+TeamShift\n")
        self.assertIn("define( 'WMHC_REST_NAMESPACE', 'teamshift-connector/v1' );", main)
        core = submodule("core")
        self.assertEqual(core.CONNECTOR_NAMESPACE, "teamshift-connector/v1")
        self.assertEqual(core.CONNECTOR_SLUG, "teamshift-connector")
        service = (CONNECTOR / "includes" / "class-service.php").read_text()
        self.assertIn("const APP_PASSWORD_NAME     = 'TeamShift Connector';", service)

    def test_runtime_text_names_no_engine(self):
        for path in RUNTIME_PY:
            bad = [s for s in _user_strings(path) if ENGINE_WORD.search(s) and s not in ENGINE_IDENTIFIERS
                   and not s.startswith(("hermes_constants", "agent.secret_scope"))]
            self.assertEqual(bad, [], path.name)

    def test_manifest_and_skill_text_name_no_engine(self):
        import yaml
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
        visible = [manifest["description"]]
        for spec in (manifest.get("config_schema") or {}).values():
            visible += [str(spec.get("label", "")), str(spec.get("description", ""))]
        skill = (ROOT / "skills" / "wp-manager" / "SKILL.md").read_text()
        body = skill.split("---", 2)[2]  # the frontmatter's metadata key is engine schema, not text
        visible.append(body)
        for schema in submodule("schemas").ALL:
            visible.append(json.dumps(schema))
        self.assertEqual([v for v in visible if ENGINE_WORD.search(v)], [])

    def test_user_agent_is_neutral(self):
        self.assertNotRegex(submodule("core.client").USER_AGENT, ENGINE_WORD)


# -- 5. no local/private/metadata targets ------------------------------------------------------
class Redirector:
    """Answers the first request with a redirect to ``target``; records every request."""

    def __init__(self, target, status=302):
        self.target, self.status, self.calls = target, status, []

    def __call__(self, req):
        client = submodule("core.client")
        self.calls.append(req)
        if len(self.calls) == 1:
            return client.Response(self.status, {"location": self.target}, b"")
        return client.Response(200, {}, b"<html>internal</html>")


class PrivateTargets(unittest.TestCase):
    def setUp(self):
        self.env = Env().start()
        self.client = submodule("core.client")
        self.dns = {"public.example.test": ["93.184.215.14"], "internal.example.test": ["10.1.2.3"],
                    "rebind.example.test": ["93.184.215.14", "127.0.0.1"],
                    "v6meta.example.test": ["fd00:ec2::254"], "mapped.example.test": ["::ffff:169.254.169.254"]}
        self.client.set_resolver(lambda host, port: self.dns.get(host, ["93.184.215.14"]))

    def tearDown(self):
        self.env.stop()

    def test_address_classes(self):
        blocked = ["127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "169.254.1.1",
                   "100.64.0.1", "100.100.100.200", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
                   "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "2002:7f00:1::1", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "not-an-ip"]
        for a in blocked:
            self.assertTrue(self.client.address_blocked(a), a)
        for a in ("93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertFalse(self.client.address_blocked(a), a)

    def test_vet_target(self):
        for url in ("http://localhost/", "https://wp.localhost/", "http://127.0.0.1:8080/", "http://[::1]/",
                    "http://169.254.169.254/latest/meta-data/", "https://internal.example.test/",
                    "https://rebind.example.test/", "https://v6meta.example.test/", "https://mapped.example.test/"):
            with self.assertRaises(self.client.WPError) as cm:
                self.client.vet_target(url)
            self.assertEqual(cm.exception.kind, "blocked", url)
        self.assertEqual(self.client.vet_target("https://public.example.test/"), "93.184.215.14")

    def _client_for(self, transport):
        self.client.set_transport(transport)
        # allow_insecure, so the private-address guard (not the plain-http rule) is what refuses http:// hops
        return self.client.WPClient({"id": "s", "url": "https://public.example.test", "username": "u",
                                     "allow_insecure": True}, None)

    def test_health_fetch_does_not_follow_a_redirect_to_metadata(self):
        for target in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:6379/",
                       "https://internal.example.test/", "http://[fe80::1]/", "http://localhost/"):
            t = Redirector(target)
            with self.assertRaises(self.client.WPError) as cm:
                self._client_for(t).fetch_page()
            self.assertEqual(cm.exception.kind, "blocked", target)
            self.assertEqual(len(t.calls), 1, target)  # the redirect target was never requested

    def test_health_fetch_follows_a_public_redirect(self):
        t = Redirector("https://www.public.example.test/")
        page = self._client_for(t).fetch_page()
        self.assertEqual(page["status"], 200)
        self.assertEqual([c.connect_ip for c in t.calls], ["93.184.215.14", "93.184.215.14"])

    def test_health_check_reports_the_blocked_redirect(self):
        add_default_site(self.env, allow_insecure=True)
        t = ReplayTransport(overrides={"GET /": [{"status": 302, "headers": {"location": "http://10.0.0.5/"},
                                                  "body": ""}]})
        self.client.set_transport(t)
        r = call(submodule("tools").wp_health_check, {"site": "wp-example"})
        home = r["signals"]["home"]
        self.assertFalse(home["ok"])
        self.assertIn("refusing to connect", home["error"])
        self.assertFalse([c for c in t.calls if "10.0.0.5" in c.url])

    def test_real_transport_connects_only_to_the_vetted_address(self):
        import http.client
        seen = []
        with mock.patch.object(self.client.socket, "create_connection",
                               side_effect=lambda addr, *a, **k: seen.append(addr) or (_ for _ in ()).throw(OSError("stop"))):
            conn = self.client._pinned(http.client.HTTPConnection, "93.184.215.14")("public.example.test", timeout=1)
            with self.assertRaises(OSError):
                conn.connect()
        self.assertEqual(seen, [("93.184.215.14", 80)])
        for bad in (None, "", "127.0.0.1", "169.254.169.254"):
            with self.assertRaises(self.client.WPError):
                self.client._pinned(http.client.HTTPConnection, bad)

    def test_real_transport_ignores_proxy_settings(self):
        handlers = [type(h).__name__ for h in self.client._opener.handlers]
        self.assertIn("_PinnedHTTPHandler", handlers)
        self.assertIn("_PinnedHTTPSHandler", handlers)
        proxy = [h for h in self.client._opener.handlers if type(h).__name__ == "ProxyHandler"]
        self.assertTrue(all(not h.proxies for h in proxy))

    def test_real_transport_refuses_a_request_without_a_vetted_address(self):
        req = self.client.Request("GET", "https://public.example.test/", {}, None, 5, None)
        with self.assertRaises(self.client.WPError) as cm:
            self.client._urllib_transport(req)
        self.assertEqual(cm.exception.kind, "blocked")


# -- runtime copy in the engine ----------------------------------------------------------------
@unittest.skipUnless(_engine_available(), "needs the engine")
class StrippedCopyInEngine(unittest.TestCase):
    def test_loads_registers_and_gates(self):
        tmp = Path(tempfile.mkdtemp(prefix="wpm-engine-"))
        try:
            home = tmp / "home"
            plugin = home / "plugins" / "wp-manager"
            shutil.copytree(ROOT, plugin, ignore=shutil.ignore_patterns(".git", "__pycache__", *NOT_RUNTIME))
            (tmp / "managed").mkdir()
            (home / "config.yaml").write_text("plugins:\n  enabled: [wp-manager]\n  isolation: in_process\n"
                                              "  entries:\n    wp-manager:\n      settings:\n"
                                              "        require_approval: false\n")
            (home / "wp-manager").mkdir()
            (home / "wp-manager" / "sites.json").write_text(json.dumps({"version": 1, "sites": [
                {"id": "shop", "label": "Shop", "url": "https://shop.example.test", "username": "a",
                 "credential": {"env": "WPM_SHOP_APP_PASSWORD"}, "tags": []}]}))
            script = textwrap.dedent("""
                import json, sys
                from hermes_cli.plugins import discover_plugins, get_plugin_manager, invoke_hook
                discover_plugins(force=True)
                from tools.registry import registry
                pm = get_plugin_manager()
                names = sorted(n for n in registry.get_all_tool_names() if n.startswith("wp_"))
                toolsets = sorted({registry.get_toolset_for_tool(n) for n in names})
                info = next(p for p in pm.list_plugins() if p["name"] == "wp-manager")
                skills = sorted(str(s) for s in pm.list_plugin_skills("wp-manager")) if hasattr(pm, "list_plugin_skills") else []
                hook = [r for r in invoke_hook("pre_tool_call", tool_name="wp_update_apply",
                                               args={"site": "shop", "type": "plugin"}, task_id="t") if r]
                leaked = [m for m in sys.modules if m.startswith("hermes_plugins.wp_manager")
                          and m.split(".")[-1] in ("plugin_api", "onepassword", "dashboard")]
                print(json.dumps({"tools": names, "toolsets": toolsets, "hooks": info["hooks"], "error": info["error"],
                                  "skills": skills, "hook": hook, "leaked": leaked}))
            """)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "WPM_", "OP_"))}
            env.update(HERMES_HOME=str(home), HOME=str(tmp), HERMES_MANAGED_DIR=str(tmp / "managed"))
            out = subprocess.run([sys.executable, "-I", "-c", script], env=env, cwd=tmp, capture_output=True,
                                 text=True, timeout=180)
            self.assertEqual(out.returncode, 0, out.stderr[-3000:])
            got = json.loads(out.stdout.strip().splitlines()[-1])
            self.assertIsNone(got["error"])
            self.assertEqual(len(got["tools"]), 9, got["tools"])
            self.assertEqual(got["toolsets"], ["wp_manager"])
            self.assertEqual(got["hooks"], 1)
            self.assertEqual(got["skills"], ["wp-manager"])  # registered as wp-manager:wp-manager
            self.assertEqual(got["leaked"], [])
            self.assertEqual(len(got["hook"]), 1, got)
            self.assertEqual(got["hook"][0]["action"], "approve")  # require_approval: false is ignored
            self.assertEqual(got["hook"][0]["rule_key"], "wp-manager:update:shop")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
