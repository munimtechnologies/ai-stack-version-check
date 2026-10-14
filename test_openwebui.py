"""Tests for the Open WebUI function, openwebui/ai_stack_version_check.py. Standard library only:
pydantic and Open WebUI's own modules are stubbed when they aren't installed, and a fake Ollama
answers on 127.0.0.1. test_live_feed needs the network (set SKIP_FEED=1 to skip it).

Run: python -m pytest test_openwebui.py
"""

import asyncio
import http.server
import importlib.util
import json
import os
import socket
import sys
import threading
import time
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
if any(k.lower() in ("http_proxy", "all_proxy") for k in os.environ):
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"  # the fake Ollama is local

if importlib.util.find_spec("pydantic") is None:
    pydantic = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **values):
            for name in getattr(type(self), "__annotations__", {}):
                setattr(self, name, values.get(name, getattr(type(self), name)))

    pydantic.BaseModel = BaseModel
    pydantic.Field = lambda default=None, **kwargs: default
    sys.modules["pydantic"] = pydantic


class Config:
    """Stand-in for open_webui.models.config.Config (Open WebUI 0.11 and later)."""

    values = {}

    @classmethod
    async def get(cls, key, default=None):
        return cls.values.get(key, default)


def install_open_webui(new_config=True):
    for name in ("open_webui", "open_webui.env", "open_webui.models", "open_webui.models.config"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["open_webui.env"].VERSION = "0.6.5"
    sys.modules["open_webui.models.config"].Config = Config
    if not new_config:
        del sys.modules["open_webui.models.config"]


install_open_webui()
spec = importlib.util.spec_from_file_location("ai_stack_version_check", HERE / "openwebui" / "ai_stack_version_check.py")
fn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fn)

import match_reference as ref  # noqa: E402

FEED = {
    "checked": "2026-10-14",
    "products": {
        "openwebui": {"name": "Open WebUI", "items": [
            {"introduced": None, "fixed": "0.6.35", "kind": "server", "ids": ["CVE-2025-0001"], "severity": "HIGH",
             "summary": "Pipe | test.", "url": "https://example.com/a", "inPublicDatabases": False},
            {"introduced": "0.6.0", "fixed": "0.6.6", "kind": "feature", "ids": ["GHSA-test"],
             "severity": "MODERATE", "summary": "Feature bug.", "url": "https://example.com/b"},
        ]},
        "ollama": {"name": "Ollama", "items": [
            {"introduced": None, "fixed": "0.1.34", "kind": "server", "ids": ["CVE-2024-37032"],
             "severity": "HIGH", "summary": "Path traversal.", "url": "https://example.com/c"},
        ]},
        "litellm": {"name": "LiteLLM", "items": [
            {"introduced": None, "fixed": None, "only": ["1.82.7", "1.82.8"], "kind": "server", "ids": [],
             "severity": "CRITICAL", "summary": "Malicious release.", "url": "https://example.com/d"},
        ]},
        "n8n": {"name": "n8n", "items": [
            {"introduced": "1.0.0", "fixed": None, "lastAffected": "1.90.0", "kind": "server", "ids": ["GHSA-n8n"],
             "severity": "HIGH", "summary": "No fix.", "url": "https://example.com/e"},
        ]},
        "vllm": {"name": "vLLM", "items": []},
        "dify": {"name": "Dify", "items": []},
        "langflow": {"name": "Langflow", "items": []},
        "mcpinspector": {"name": "MCP Inspector", "items": []},
    },
}


class FakeOllama(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = json.dumps({"version": "0.1.33"}).encode()
        self.send_response(200 if self.path == "/api/version" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def closed_port_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{s.getsockname()[1]}"


def ask(pipe, text, role="admin", request=None, **kwargs):
    body = {"messages": [{"role": "user", "content": text}], "stream": True}
    return asyncio.run(pipe.pipe(body, __user__={"role": role}, __request__=request, **kwargs))


class FunctionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeOllama)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.good = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.bad = closed_port_url()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        install_open_webui()
        Config.values = {}
        fn._CACHE.update(feed=FEED, at=time.time(), url=fn.FEED_URL)
        self.pipe = fn.Pipe()
        self.pipe.valves.TIMEOUT_SECONDS = 5.0

    def test_frontmatter(self):
        src = (HERE / "openwebui" / "ai_stack_version_check.py").read_text(encoding="utf-8")
        head = src.split('"""')[1]
        problems = [line for line in ("title: AI Stack Version Check", "author: MV2 of Munim, Inc.",
                                      "version: 0.1.0", "license: Apache-2.0") if line not in head]
        self.assertTrue(src.startswith('"""\ntitle:'), "the frontmatter docstring must open the file")
        self.assertEqual(problems, [])
        self.assertNotIn(" an AI", src)

    def test_same_rules_as_the_extension(self):
        self.assertEqual((fn.VERSION.pattern, fn.VERSION.flags), (ref.VERSION.pattern, ref.VERSION.flags))
        self.assertEqual((fn.PRE.pattern, fn.PRE.flags), (ref.PRE.pattern, ref.PRE.flags))
        vectors = json.loads((HERE / "tests" / "vectors.json").read_text(encoding="utf-8"))
        wrong = [("compare", a, b) for a, b, want in vectors["compare"] if fn.compare(a, b) != want]
        wrong += [("isVersion", v) for v, want in vectors["isVersion"] if fn.is_version(v) != want]
        wrong += [("affects", item, v) for item, v, want in vectors["affects"] if fn.affects(item, v) != want]
        for case in vectors["check"]:
            matched, unchecked = fn.check(case["feed"], case["product"], case["version"])
            got = ([i["ids"][0] for i in matched], unchecked, *fn.upgrade_target(matched))
            if got != (case["matched"], case["unchecked"], case["upgradeTo"], case["noFix"]):
                wrong.append(("check", case["version"], got))
        self.assertEqual(wrong, [])

    def test_find_targets(self):
        cases = {
            "Is n8n 1.88.0 affected? And litellm==1.82.7": [("n8n", "1.88.0"), ("litellm", "1.82.7")],
            "ghcr.io/open-webui/open-webui:v0.6.5-cuda": [("openwebui", "0.6.5")],
            "vllm/vllm-openai:v0.9.1": [("vllm", "0.9.1")],
            "my Open WebUI uses Ollama 0.1.33": [("ollama", "0.1.33")],
            "langgenius/dify-api:1.4.0, MCP Inspector 0.14.1": [("dify", "1.4.0"), ("mcpinspector", "0.14.1")],
            "ollama version is 0.12.3.": [("ollama", "0.12.3")],
            "n8n 2.0.0-rc.1": [("n8n", "2.0.0-rc.1")],
            "langflowai/langflow:1.5.0": [("langflow", "1.5.0")],
            "n8n 1.88.0, n8n 1.88.0": [("n8n", "1.88.0")],
            "check": [],
        }
        wrong = {}
        for text, want in cases.items():
            got = fn.find_targets(text, FEED["products"])[0]
            if got != want:
                wrong[text] = got
        self.assertEqual(wrong, {})
        self.assertEqual(fn.find_targets("Ubuntu 22.04", FEED["products"]), ([], ["22.04"]))

    def test_typed_check(self):
        out = ask(self.pipe, "open webui 0.6.5")
        for part in ("### Open WebUI 0.6.5", "**2 known advisories affect this version.**",
                     "The newest fix among them is in 0.6.35", "[CVE-2025-0001](https://example.com/a)",
                     "Pipe \\| test.", "Not in OSV.dev", "Only if the affected feature is in use.",
                     "checked 2026-10-14", "MV2 of Munim, Inc."):
            self.assertIn(part, out)
        self.assertIn("None of the 2 advisories listed for Open WebUI affects 0.7.0.", ask(self.pipe, "Open WebUI 0.7.0"))

    def test_bad_release_and_no_fix(self):
        out = ask(self.pipe, "litellm 1.82.7, n8n 1.88.0")
        for part in ("Bad releases: 1.82.7, 1.82.8.", "Malicious release.", "1 has no fixed version yet.",
                     "Affected: from 1.0.0 up to 1.90.0, no fix yet."):
            self.assertIn(part, out)
        self.assertNotIn("Malicious release.", ask(self.pipe, "litellm 1.82.6"))

    def test_server_check(self):
        disabled = closed_port_url() + "/off"
        Config.values = {"ollama.enable": True, "ollama.base_urls": [self.good + "/", self.bad, disabled],
                         "ollama.api_configs": {"2": {"enable": False}}}
        events = []

        async def emit(event):
            events.append(event)

        out = ask(self.pipe, "", __event_emitter__=emit)
        for part in ("### Open WebUI 0.6.5 (this server)", f"### Ollama 0.1.33 (at {self.good})",
                     "CVE-2024-37032", f"Couldn't read the Ollama version at {self.bad}"):
            self.assertIn(part, out)
        self.assertNotIn(disabled, out)
        self.assertTrue(events and events[-1]["data"].get("done"), events)

    def test_server_check_older_open_webui(self):
        install_open_webui(new_config=False)
        config = types.SimpleNamespace(ENABLE_OLLAMA_API=True, OLLAMA_BASE_URLS=[self.good], OLLAMA_API_CONFIGS={})
        request = types.SimpleNamespace(app=types.SimpleNamespace(state=types.SimpleNamespace(config=config)))
        self.assertIn("### Ollama 0.1.33", ask(self.pipe, "check", request=request))
        config.ENABLE_OLLAMA_API = False
        self.assertNotIn("Ollama", ask(self.pipe, "check", request=request).split("Apps covered")[0])

    def test_non_admin(self):
        out = ask(self.pipe, "", role="user")
        self.assertIn("Only an admin", out)
        self.assertNotIn("0.6.5 (this server)", out)
        self.assertIn("CVE-2024-37032", ask(self.pipe, "ollama 0.1.33", role="user"))

    def test_message_parts_and_skipped(self):
        body = {"messages": [{"role": "user", "content": [
            {"type": "text", "text": "Ubuntu 22.04 runs ollama 0.1.33"},
            {"type": "image_url", "image_url": {"url": "data:,"}}]}]}
        out = asyncio.run(self.pipe.pipe(body, __user__={"role": "user"}))
        self.assertIn("CVE-2024-37032", out)
        self.assertIn("`22.04`", out)

    def test_tasks(self):
        out = ask(self.pipe, "anything", __task__="title_generation")
        self.assertEqual(json.loads(out)["title"], "AI stack version check")

    def test_feed_download_failure(self):
        self.pipe.valves.FEED_URL = closed_port_url() + "/advisories.json"
        self.assertIn("Couldn't download the advisories", ask(self.pipe, "ollama 0.1.33"))


class LiveFeedTests(unittest.TestCase):
    def test_live_feed(self):
        if os.environ.get("SKIP_FEED") == "1":
            self.skipTest("SKIP_FEED=1")
        fn._CACHE.update(feed=None, at=0.0, url=None)
        pipe = fn.Pipe()
        feed = asyncio.run(pipe.load_feed())
        bad = [f"{slug}: {v!r}" for slug, product in feed["products"].items() for item in product["items"]
               for v in [item.get("introduced"), item.get("fixed"), item.get("lastAffected")] + list(item.get("only") or [])
               if v is not None and not fn.is_version(v)]
        self.assertEqual(bad, [])
        self.assertTrue({"openwebui", "ollama"} <= set(feed["products"]))
        out = asyncio.run(pipe.pipe({"messages": [{"role": "user", "content": "ollama 0.1.33"}]}, __user__={"role": "user"}))
        self.assertIn("CVE-2024-37032", out)


if __name__ == "__main__":
    unittest.main()
