"""Checks the live advisory feed the extension downloads: its shape, that every version in it
can be compared, and a few known answers. Standard library only; needs the network.

Run: python -m pytest test_feed.py  (set SKIP_FEED=1 to skip when offline)
"""

import json
import os
import re
import sys
import unittest
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import match_reference as ref  # noqa: E402

SOURCES = [
    "https://raw.githubusercontent.com/munimv2/ai-stack-advisories/main/advisories.json",
    "https://cdn.jsdelivr.net/gh/munimv2/ai-stack-advisories@main/advisories.json",
]
REQUIRED = ("introduced", "fixed", "kind", "ids", "summary", "url")


def load_feed():
    errors = []
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "munimv2-ai-stack-version-check-test"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # try the next mirror
            errors.append(f"{url}: {e}")
    raise RuntimeError("could not download the advisory feed: " + "; ".join(errors))


class FeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("SKIP_FEED") == "1":
            raise unittest.SkipTest("SKIP_FEED=1")
        cls.feed = load_feed()

    def ids(self, product, version):
        matched = ref.check(self.feed, product, version)["matched"]
        return {i for item in matched for i in item.get("ids") or []}

    def test_shape(self):
        products = self.feed.get("products")
        self.assertIsInstance(products, dict)
        problems = []
        for slug, product in products.items():
            if not isinstance(product.get("name"), str):
                problems.append(f"{slug}: no name")
            if not isinstance(product.get("items"), list):
                problems.append(f"{slug}: no items list")
                continue
            for n, item in enumerate(product["items"]):
                where = f"{slug}[{n}]"
                problems += [f"{where}: no {key}" for key in REQUIRED if key not in item]
                if not isinstance(item.get("ids", []), list):
                    problems.append(f"{where}: ids is not a list")
                versions = [item.get(k) for k in ("introduced", "fixed", "lastAffected")] + list(item.get("only") or [])
                problems += [f"{where}: {v!r} is not a version the extension can compare"
                             for v in versions if v is not None and not ref.is_version(v)]
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_tab_readers_name_feed_products(self):
        src = (HERE / "popup.js").read_text(encoding="utf-8")
        readers = re.findall(r"^  (\w+): \{ path: ", src, re.M)
        self.assertEqual(sorted(readers), ["comfyui", "flowise", "langflow", "ollama", "openwebui"])
        self.assertEqual([r for r in readers if r not in self.feed["products"]], [])

    def test_known_answers(self):
        self.assertIn("CVE-2024-37032", self.ids("ollama", "0.1.33"))
        self.assertNotIn("CVE-2024-37032", self.ids("ollama", "0.1.34"))
        self.assertIn("CVE-2026-7482", self.ids("ollama", "0.17.0"))
        self.assertNotIn("CVE-2026-7482", self.ids("ollama", "0.17.1"))
        bad = [item for item in self.feed["products"]["litellm"]["items"] if "1.82.7" in (item.get("only") or [])]
        self.assertTrue(bad, "the LiteLLM 1.82.7 bad-release entry is missing")
        self.assertTrue(any(m is bad[0] for m in ref.check(self.feed, "litellm", "1.82.7")["matched"]))
        self.assertFalse(any(m is bad[0] for m in ref.check(self.feed, "litellm", "1.82.6")["matched"]))


if __name__ == "__main__":
    unittest.main()
