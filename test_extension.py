"""Checks the extension's files and its version matching. Standard library only, no network.

Run: python -m pytest test_extension.py  (or python test_extension.py)
test_feed.py checks the live advisory feed; test_js.py runs lib/match.js itself under Node.
"""

import json
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import match_reference as ref  # noqa: E402

FEED_URL = "https://raw.githubusercontent.com/munimtechnologies/ai-stack-advisories/main/advisories.json"
PERMISSIONS = {"activeTab", "scripting", "storage"}
HOSTS = ["https://raw.githubusercontent.com/*"]
SCRIPTS = ["lib/match.js", "popup.js"]
UNSAFE_JS = ["eval(", "new Function", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]


def read(path):
    return (HERE / path).read_text(encoding="utf-8")


class PageRefs(HTMLParser):
    """Script and stylesheet references in an extension page, and any inline script."""

    def __init__(self):
        super().__init__()
        self.refs, self.inline, self._in_script = [], [], False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self._in_script = True
            if attrs.get("src"):
                self.refs.append(attrs["src"])
        elif tag == "link" and attrs.get("href"):
            self.refs.append(attrs["href"])
        for name in attrs:
            if name.startswith("on"):
                self.inline.append(f"<{tag} {name}>")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline.append(data.strip()[:60])


class ManifestTests(unittest.TestCase):
    def test_manifest(self):
        m = json.loads(read("manifest.json"))
        problems = []
        if m.get("manifest_version") != 3:
            problems.append("manifest_version must be 3")
        if not re.fullmatch(r"\d+(\.\d+){0,3}", m.get("version", "")):
            problems.append(f"version {m.get('version')!r} is not 1-4 dot-separated numbers")
        if not 0 < len(m.get("name", "")) <= 45:
            problems.append("name must be 1-45 characters")
        if not 0 < len(m.get("description", "")) <= 132:
            problems.append(f"description is {len(m.get('description', ''))} characters, the stores allow 132")
        if set(m.get("permissions", [])) != PERMISSIONS:
            problems.append(f"permissions {m.get('permissions')} should be exactly {sorted(PERMISSIONS)}")
        if m.get("host_permissions") != HOSTS:
            problems.append(f"host_permissions {m.get('host_permissions')} should be {HOSTS}")
        popup = (m.get("action") or {}).get("default_popup")
        if not popup or not (HERE / popup).is_file():
            problems.append(f"action.default_popup {popup!r} is missing")
        for size, icon in (m.get("icons") or {}).items():
            if not (HERE / icon).is_file():
                problems.append(f"icon {size} {icon!r} is missing")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_popup_page(self):
        page = PageRefs()
        page.feed(read("popup.html"))
        problems = [f"inline script or handler (blocked by the extension CSP): {s}" for s in page.inline]
        for ref_ in page.refs:
            if re.match(r"^[a-z]+:", ref_) or ref_.startswith("//"):
                problems.append(f"remote file {ref_!r}: extensions must ship their own code")
            elif not (HERE / ref_).is_file():
                problems.append(f"{ref_!r} is missing")
        scripts = [r for r in page.refs if r.endswith(".js")]
        if scripts != SCRIPTS:
            problems.append(f"scripts {scripts} should be {SCRIPTS}, in that order")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_scripts_are_safe(self):
        problems = []
        for path in SCRIPTS:
            src = read(path)
            problems += [f"{path}: uses {word}" for word in UNSAFE_JS if word in src]
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_feed_url(self):
        self.assertIn(f'const FEED_URL = "{FEED_URL}";', read("popup.js"))
        self.assertTrue(any(FEED_URL.startswith(h.rstrip("*")) for h in HOSTS))

    def test_same_patterns_as_python(self):
        src = read("lib/match.js")
        for name, pattern in (("VERSION", ref.VERSION), ("PRE", ref.PRE)):
            found = re.search(rf"const {name} = /(.*)/i;", src)
            self.assertIsNotNone(found, f"const {name} not found in lib/match.js")
            self.assertEqual(found.group(1), pattern.pattern, name)


class MatchTests(unittest.TestCase):
    """tests/vectors.json against the Python twin; test_js.py runs the same vectors in Node."""

    vectors = json.loads(read("tests/vectors.json"))

    def test_vectors(self):
        v, problems = self.vectors, []

        def expect(label, run, want):
            try:
                got = run()
            except ValueError as e:
                got = f"error: {e}"
            if got != want:
                problems.append(f"{label}: got {got!r}, want {want!r}")

        for a, b, want in v["compare"]:
            expect(f"compare({a}, {b})", lambda: ref.compare(a, b), want)
        for s, want in v["isVersion"]:
            expect(f"isVersion({s!r})", lambda: ref.is_version(s), want)
        for item, s, want in v["affects"]:
            expect(f"affects({item}, {s})", lambda: ref.affects(item, s), want)
        for c in v["check"]:
            def run():
                r = ref.check(c["feed"], c["product"], c["version"])
                u = ref.upgrade_target(r["matched"])
                return [[i["ids"][0] for i in r["matched"]], r["unchecked"], u["upgradeTo"], u["noFix"]]
            expect(f"check({c['product']}, {c['version']})", run,
                   [c["matched"], c["unchecked"], c["upgradeTo"], c["noFix"]])
        self.assertEqual(problems, [], "\n" + "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
