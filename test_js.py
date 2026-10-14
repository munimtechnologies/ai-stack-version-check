"""Runs the extension's JavaScript under Node: tests/vectors.json against lib/match.js, and a
syntax check of popup.js. Needs `node` on the PATH.

Run: python -m pytest test_js.py
"""

import shutil
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class JsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def run_node(self, *args):
        self.assertIsNotNone(self.node, "node is not installed where these tests run")
        run = subprocess.run([self.node, *args], cwd=HERE, capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, (run.stdout + run.stderr)[-3000:])

    def test_vectors(self):
        self.run_node(str(HERE / "tests" / "match_test.js"))

    def test_popup_syntax(self):
        self.run_node("--check", str(HERE / "popup.js"))


if __name__ == "__main__":
    unittest.main()
